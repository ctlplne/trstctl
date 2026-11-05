// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func startNative(ctx context.Context, helper string, target Target, password []byte) (*Stream, error) {
	if !filepath.IsAbs(helper) {
		return nil, errors.New("rdp: helper must be an absolute installed path")
	}
	// Execute the already-open regular file, so a path replacement cannot swap
	// the executable between validation and exec. Only the helper descriptor is inherited.
	binary, err := os.Open(helper) // #nosec G304 G703 -- operator-installed helper; absolute regular protected executable, executed by this open FD (CWE-22)
	if err != nil {
		return nil, errors.New("rdp: helper unavailable")
	}
	defer func() { _ = binary.Close() }()
	st, err := binary.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("rdp: helper must be a protected regular executable")
	}
	wire, err := request(target, password)
	if err != nil {
		return nil, err
	}
	defer wire.Destroy()
	cmd := nativeCommand(ctx, binary)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, errors.New("rdp: helper failed to start")
	}
	stop := func() error { _ = cmd.Process.Kill(); _ = cmd.Wait(); return nil }
	stream := &Stream{input: input, output: output, stop: stop, pid: cmd.Process.Pid}
	if _, err = input.Write(wire.Bytes()); err != nil {
		_ = stream.Close()
		return nil, errors.New("rdp: helper request failed")
	}
	return stream, nil
}

func nativeCommand(ctx context.Context, binary *os.File) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{binary}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "WLOG_LEVEL=OFF"}
	cmd.Stderr = io.Discard
	return cmd
}
