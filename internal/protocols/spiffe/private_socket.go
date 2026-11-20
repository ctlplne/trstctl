// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/privatesocket"
)

// PrepareWorkloadSocket verifies the path before any listener is advertised.
// It removes only a socket owned by this uid whose listener has gone away.
func PrepareWorkloadSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("spiffe: workload API socket path must be absolute and clean")
	}
	if err := privatesocket.EnsureDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("spiffe: workload API socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("spiffe: inspect workload API socket: %w", err)
	}
	owned, err := privatesocket.OwnedByProcess(info)
	if err != nil {
		return err
	}
	if !owned || info.Mode()&os.ModeSocket == 0 {
		return errors.New("spiffe: existing workload API path is not an owned socket")
	}
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("spiffe: workload API socket already has a live listener")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("spiffe: cannot prove workload API socket is stale: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("spiffe: remove owned stale workload API socket: %w", err)
	}
	return nil
}

// ListenWorkloadAPI binds only after its directory and existing entry pass
// ownership checks. The 0700 directory denies other users during the short
// interval before the socket itself is verified at 0600.
func ListenWorkloadAPI(path string) (net.Listener, error) {
	if err := PrepareWorkloadSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("spiffe: listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("spiffe: restrict workload API socket: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("spiffe: inspect bound workload API socket: %w", err)
	}
	owned, err := privatesocket.OwnedByProcess(info)
	if err != nil || !owned || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		_ = ln.Close()
		return nil, errors.New("spiffe: bound workload API socket lacks owner-only permissions")
	}
	return ln, nil
}
