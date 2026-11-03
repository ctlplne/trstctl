// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package winservice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestHandlerReportsLoopErrorAsServiceFailure(t *testing.T) {
	statuses := make(chan svc.Status, 4)
	requests := make(chan svc.ChangeRequest)
	result := make(chan uint32, 1)
	h := &handler{loop: func(context.Context) error { return errors.New("control plane unavailable") }}

	go func() {
		_, code := h.Execute(nil, requests, statuses)
		result <- code
	}()

	if got := <-statuses; got.State != svc.StartPending {
		t.Fatalf("first status = %v, want StartPending", got.State)
	}
	if got := <-statuses; got.State != svc.Running {
		t.Fatalf("second status = %v, want Running", got.State)
	}
	if got := <-statuses; got.State != svc.StopPending {
		t.Fatalf("third status = %v, want StopPending", got.State)
	}
	if code := <-result; code == 0 {
		t.Fatal("loop error reported a successful service exit; SCM recovery would not run")
	}
}

func TestHandlerReportsOperatorStopAsCleanExit(t *testing.T) {
	statuses := make(chan svc.Status, 4)
	requests := make(chan svc.ChangeRequest, 1)
	result := make(chan uint32, 1)
	h := &handler{loop: func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}}

	go func() {
		_, code := h.Execute(nil, requests, statuses)
		result <- code
	}()

	<-statuses // StartPending
	if got := <-statuses; got.State != svc.Running {
		t.Fatalf("second status = %v, want Running", got.State)
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if got := <-statuses; got.State != svc.StopPending {
		t.Fatalf("stop status = %v, want StopPending", got.State)
	}
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("operator stop exit code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish after operator stop")
	}
}

// TestInstallAndServiceStartSetTheRecoveryPolicy registers a throwaway service
// with the real SCM (an administrator token is needed; hosted Windows CI
// runners have one) and reads back the policy Install sets. It then clears the
// policy and calls setRecovery, which Run calls at every service start with
// only the rights it asks for, and reads the policy back again.
func TestInstallAndServiceStartSetTheRecoveryPolicy(t *testing.T) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("registering a service needs an administrator token")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Disconnect() }()

	name := fmt.Sprintf("trstctl-agent-recovery-test-%d", os.Getpid())
	spec, err := BuildSpec(Config{Name: name, ExePath: `C:\Windows\System32\cmd.exe`, ManualStart: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(spec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Uninstall(name) })

	check := func(stage string) {
		t.Helper()
		s, err := m.OpenService(name)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		actions, err := s.RecoveryActions()
		if err != nil {
			t.Fatal(err)
		}
		want := []time.Duration{30 * time.Second, 60 * time.Second, 5 * time.Minute}
		if len(actions) != len(want) {
			t.Fatalf("%s: %d recovery actions, want %d", stage, len(actions), len(want))
		}
		for i, action := range actions {
			if action.Type != mgr.ServiceRestart || action.Delay != want[i] {
				t.Errorf("%s: action %d = type %d after %s, want a restart after %s", stage, i+1, action.Type, action.Delay, want[i])
			}
		}
		if reset, err := s.ResetPeriod(); err != nil || reset != 86400 {
			t.Errorf("%s: reset period = %d (%v), want 86400 seconds", stage, reset, err)
		}
		if flag, err := s.RecoveryActionsOnNonCrashFailures(); err != nil || !flag {
			t.Errorf("%s: error exits count as failures = %v (%v), want true", stage, flag, err)
		}
	}
	check("install")

	s, err := m.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetRecoveryActions(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(false); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if actions, err := func() ([]mgr.RecoveryAction, error) {
		s, err := m.OpenService(name)
		if err != nil {
			return nil, err
		}
		defer func() { _ = s.Close() }()
		return s.RecoveryActions()
	}(); err != nil || len(actions) != 0 {
		t.Fatalf("clearing the policy left %d actions (%v)", len(actions), err)
	}
	if err := setRecovery(name); err != nil {
		t.Fatal(err)
	}
	check("service start")
}
