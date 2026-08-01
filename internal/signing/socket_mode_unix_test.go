// SPDX-License-Identifier: MPL-2.0

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package signing

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestPrivateUnixSocketRestoresUmaskAfterListenFailure(t *testing.T) {
	socketUmaskMu.Lock()
	originalMask := unix.Umask(0o022)
	socketUmaskMu.Unlock()
	t.Cleanup(func() {
		socketUmaskMu.Lock()
		unix.Umask(originalMask)
		socketUmaskMu.Unlock()
	})

	missingParent := filepath.Join(shortSocketTestDir(t), "missing")
	ln, err := listenPrivateUnixSocket(filepath.Join(missingParent, "signer.sock"))
	if err == nil {
		_ = ln.Close()
		t.Fatal("listen private Unix socket unexpectedly succeeded beneath a missing directory")
	}

	socketUmaskMu.Lock()
	gotMask := unix.Umask(0o022)
	unix.Umask(gotMask)
	socketUmaskMu.Unlock()
	if gotMask != 0o022 {
		t.Fatalf("process umask after failed socket bind = %04o, want restored 0022", gotMask)
	}
}

func TestExactSocketModeRejectsNonSocketsWithoutChmod(t *testing.T) {
	dir := shortSocketTestDir(t)
	regularPath := filepath.Join(dir, "regular")
	if err := os.WriteFile(regularPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(dir, "real.sock")
	ln, err := listenPrivateUnixSocket(socketPath)
	if err != nil {
		t.Fatalf("listen private Unix socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	symlinkPath := filepath.Join(dir, "alias.sock")
	if err := os.Symlink(socketPath, symlinkPath); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{regularPath, symlinkPath} {
		chmodCalled := false
		err := enforceExactSocketMode(path, 0o600, func(string, os.FileMode) error {
			chmodCalled = true
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "is not a Unix socket") {
			t.Errorf("enforce non-socket %q error = %v, want Unix-socket type rejection", path, err)
		}
		if chmodCalled {
			t.Errorf("enforce non-socket %q attempted chmod before rejecting its type", path)
		}
	}
}

func TestExactSocketModeCorrectsLooseSocketAndRechecks(t *testing.T) {
	socketPath, ln := listenLooseUnixSocket(t)
	t.Cleanup(func() { _ = ln.Close() })

	chmodCalls := 0
	err := enforceExactSocketMode(socketPath, 0o600, func(path string, mode os.FileMode) error {
		chmodCalls++
		return os.Chmod(path, mode)
	})
	if err != nil {
		t.Fatalf("correct loose socket mode: %v", err)
	}
	if chmodCalls != 1 {
		t.Fatalf("socket mode correction calls = %d, want exactly one", chmodCalls)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("corrected socket mode = %s, want exact 0600 Unix socket", info.Mode())
	}
}

func TestExactSocketModeFailsWhenCorrectionDoesNotTakeEffect(t *testing.T) {
	socketPath, ln := listenLooseUnixSocket(t)
	t.Cleanup(func() { _ = ln.Close() })

	if err := enforceExactSocketMode(socketPath, 0o600, func(string, os.FileMode) error { return nil }); err == nil {
		t.Fatal("mode correction that reported success without changing the socket passed exact recheck")
	}
}

func TestExactSocketModeRejectsTypeSwapDuringCorrection(t *testing.T) {
	socketPath, ln := listenLooseUnixSocket(t)
	t.Cleanup(func() { _ = ln.Close() })

	err := enforceExactSocketMode(socketPath, 0o600, func(path string, mode os.FileMode) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return os.WriteFile(path, nil, mode)
	})
	if err == nil {
		t.Fatal("socket replaced by a regular file during correction passed the type recheck")
	}
	info, statErr := os.Lstat(socketPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode()&os.ModeSocket != 0 || !info.Mode().IsRegular() {
		t.Fatalf("correction race fixture mode = %s, want a regular-file replacement", info.Mode())
	}
}

func listenLooseUnixSocket(t *testing.T) (string, net.Listener) {
	t.Helper()
	socketPath := filepath.Join(shortSocketTestDir(t), "loose.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen loose Unix socket: %v", err)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		_ = ln.Close()
		t.Fatalf("make socket deliberately loose: %v", err)
	}
	return socketPath, ln
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
