//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

type boundedPoolOutput struct{ bytes.Buffer }

func (b *boundedPoolOutput) Write(value []byte) (int, error) {
	if len(value) > 64<<10-b.Len() {
		return 0, errors.New("windows pool: native worker output exceeds bound")
	}
	return b.Buffer.Write(value)
}
func nativePoolWorkerPIDs(ctx context.Context, name string) ([]uint32, error) {
	if !validPoolName(name) {
		return nil, errors.New("windows pool: invalid native worker selection")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, errors.New("windows pool: native system directory unavailable")
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, filepath.Join(system, "inetsrv", "appcmd.exe"), "list", "wp", "/apppool.name:"+name, "/xml") // #nosec G204 -- fixed inbox IIS executable in native System32, read-only operation and validated pool name; no shell/credentials (CWE-78)
	command.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + system}
	command.WaitDelay = time.Second
	var output boundedPoolOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("windows pool: independent native worker readback failed")
	}
	return parsePoolWorkerMetadata(output.Bytes(), name)
}
func openPoolWorkerIdentity(pid uint32) (string, func(), error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", nil, errors.New("windows pool: worker process unavailable for identity proof")
	}
	closeProcess := func() { _ = windows.CloseHandle(process) }
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		closeProcess()
		return "", nil, errors.New("windows pool: worker process token unavailable")
	}
	user, err := token.GetTokenUser()
	_ = token.Close()
	if err != nil {
		closeProcess()
		return "", nil, errors.New("windows pool: worker process account unavailable")
	}
	return user.User.Sid.String(), closeProcess, nil
}
func (nativePoolDriver) workers(ctx context.Context, name string) ([]PoolWorker, error) {
	pids, err := nativePoolWorkerPIDs(ctx, name)
	if err != nil {
		return nil, err
	}
	var workers []PoolWorker
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, pid := range pids {
		sid, release, err := openPoolWorkerIdentity(pid)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
		workers = append(workers, PoolWorker{ProcessID: pid, AccountSID: sid})
	}
	// Process handles remain open until the second inbox readback, preventing PID
	// reuse from turning a different process into this pool's identity witness.
	after, err := nativePoolWorkerPIDs(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(after) != len(pids) {
		return nil, errors.New("windows pool: worker set changed during identity proof")
	}
	seen := map[uint32]bool{}
	for _, pid := range after {
		seen[pid] = true
	}
	for _, pid := range pids {
		if !seen[pid] {
			return nil, errors.New("windows pool: worker changed during identity proof")
		}
	}
	return workers, nil
}
func nativePoolState(ctx context.Context, name string) (int64, error) {
	var state int64
	err := withIISPools(ctx, func(_ *automationObject, collection *automationObject) error {
		pool, err := findNativePool(collection, name)
		if err != nil {
			return err
		}
		defer pool.destroy()
		state, err = iisIntegerProperty(pool, "state")
		return err
	})
	return state, err
}
func waitNativePoolState(ctx context.Context, name string, want int64) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := nativePoolState(bounded, name)
		if err != nil {
			return err
		}
		if state == want {
			return nil
		}
		select {
		case <-bounded.Done():
			return errors.New("windows pool: native state transition deadline exceeded")
		case <-ticker.C:
		}
	}
}
func (driver nativePoolDriver) restart(ctx context.Context, expected Pool) (PoolRestartProof, error) {
	previous, err := nativePoolWorkerPIDs(ctx, expected.Name)
	if err != nil {
		return PoolRestartProof{}, err
	}
	proof := PoolRestartProof{Name: expected.Name, AccountSID: expected.AccountSID, ConfigSHA256: expected.ConfigSHA256, WasStarted: expected.WasStarted, PreviousPIDs: previous}
	err = withNativePool(ctx, expected.Name, func(_ *automationObject, snapshot *nativePoolSnapshot) error {
		if !samePoolBinding(expected, snapshot.Pool) {
			return errors.New("windows pool: native authority changed before restart")
		}
		if !expected.WasStarted {
			if snapshot.WasStarted || len(previous) != 0 {
				return errors.New("windows pool: stopped pool state changed")
			}
			proof.StoppedObserved = true
			return nil
		}
		if snapshot.WasStarted {
			return executePoolMethod(snapshot.object, "Stop")
		}
		return nil
	})
	if err != nil {
		return PoolRestartProof{}, err
	}
	if !expected.WasStarted {
		return proof, nil
	}
	if err := waitNativePoolState(ctx, expected.Name, 3); err != nil {
		return PoolRestartProof{}, err
	}
	// The stopped state must also have released every predecessor worker.
	deadline, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		current, err := nativePoolWorkerPIDs(deadline, expected.Name)
		if err != nil {
			return PoolRestartProof{}, err
		}
		if len(current) == 0 {
			break
		}
		select {
		case <-deadline.Done():
			return PoolRestartProof{}, errors.New("windows pool: predecessor workers did not exit")
		case <-time.After(100 * time.Millisecond):
		}
	}
	proof.StoppedObserved = true
	err = withNativePool(ctx, expected.Name, func(_ *automationObject, snapshot *nativePoolSnapshot) error {
		if !samePoolBinding(expected, snapshot.Pool) || snapshot.WasStarted {
			return errors.New("windows pool: frozen stopped pool changed before start")
		}
		return executePoolMethod(snapshot.object, "Start")
	})
	if err != nil {
		return PoolRestartProof{}, err
	}
	if err := waitNativePoolState(ctx, expected.Name, 1); err != nil {
		return PoolRestartProof{}, err
	}
	proof.StartedObserved = true
	return proof, nil
}
