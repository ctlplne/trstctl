// SPDX-License-Identifier: MPL-2.0

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package signing

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateUnixSocketCreatedWithExactModeBeforeChmod(t *testing.T) {
	// Start from the permissive mask used by the shipped runner. The listener
	// must atomically override it for bind and then restore it.
	socketUmaskMu.Lock()
	originalMask := unix.Umask(0o022)
	socketUmaskMu.Unlock()
	t.Cleanup(func() {
		socketUmaskMu.Lock()
		unix.Umask(originalMask)
		socketUmaskMu.Unlock()
	})

	socketPath := filepath.Join(shortSocketTestDir(t), "signer.sock")
	ln, err := listenPrivateUnixSocket(socketPath)
	if err != nil {
		t.Fatalf("listen private Unix socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("inspect socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("created socket mode = %s, want exact 0600 Unix socket", info.Mode())
	}

	chmodCalled := false
	err = enforceExactSocketMode(socketPath, 0o600, func(string, os.FileMode) error {
		chmodCalled = true
		return unix.EINVAL
	})
	if err != nil {
		t.Fatalf("exact socket mode should not require fakeowner-incompatible chmod: %v", err)
	}
	if chmodCalled {
		t.Fatal("exact atomically-created socket mode issued a redundant chmod")
	}

	socketUmaskMu.Lock()
	gotMask := unix.Umask(0o022)
	unix.Umask(gotMask)
	socketUmaskMu.Unlock()
	if gotMask != 0o022 {
		t.Fatalf("process umask after socket bind = %04o, want restored 0022", gotMask)
	}
}

func TestExactSocketModeFailsClosedWhenCorrectionIsUnsupported(t *testing.T) {
	socketUmaskMu.Lock()
	originalMask := unix.Umask(0o022)
	socketPath := filepath.Join(shortSocketTestDir(t), "loose.sock")
	ln, err := net.Listen("unix", socketPath)
	unix.Umask(originalMask)
	socketUmaskMu.Unlock()
	if err != nil {
		t.Fatalf("listen loose Unix socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	chmodErr := errors.New("filesystem rejects socket chmod")
	err = enforceExactSocketMode(socketPath, 0o600, func(string, os.FileMode) error { return chmodErr })
	if !errors.Is(err, chmodErr) {
		t.Fatalf("enforce loose socket mode error = %v, want chmod failure", err)
	}
}

func shortSocketTestDir(t *testing.T) string {
	t.Helper()
	// Darwin limits Unix-socket pathnames to roughly 104 bytes. testing.TempDir
	// includes the full test name beneath a long per-user temporary root, so use
	// the standard short POSIX alias while retaining an exclusive 0700 directory.
	dir, err := os.MkdirTemp("/tmp", "trstctl-uds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
