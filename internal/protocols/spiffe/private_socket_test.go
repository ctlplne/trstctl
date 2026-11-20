// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func serveSocketForBoundaryTest(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	return ServeWorkloadAPI(ctx, path, &WorkloadAPIServer{})
}

func privateSocketTestDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		// Keep Unix socket paths short and avoid macOS's /tmp symlink. The
		// production boundary correctly refuses a symlinked ancestor.
		var err error
		base, err = filepath.EvalSymlinks("/tmp")
		if err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.MkdirTemp(base, "ws-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- directory execute bit is needed to reach the test socket
		t.Fatal(err)
	}
	return dir
}

func TestWorkloadSocketRefusesWritableDirectory(t *testing.T) {
	dir := privateSocketTestDir(t)
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- deliberately unsafe directory is the rejected test input
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore owner-only test directory for cleanup
	path := filepath.Join(dir, "workload.sock")
	if err := serveSocketForBoundaryTest(path); err == nil {
		t.Fatal("Workload API bound inside a directory another local user can write")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected path gained a socket: %v", err)
	}
}

func TestWorkloadSocketRefusesWritableAncestor(t *testing.T) {
	parent := privateSocketTestDir(t)
	shared := filepath.Join(parent, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe ancestor is the rejected test input
		t.Fatal(err)
	}
	private := filepath.Join(shared, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := serveSocketForBoundaryTest(filepath.Join(private, "workload.sock")); err == nil {
		t.Fatal("Workload API bound below an ancestor that another user can replace")
	}
}

func TestWorkloadSocketRefusesSymlinkedDirectory(t *testing.T) {
	parent := privateSocketTestDir(t)
	target := privateSocketTestDir(t)
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := serveSocketForBoundaryTest(filepath.Join(link, "workload.sock")); err == nil {
		t.Fatal("Workload API bound through a directory symlink")
	}
	if _, err := os.Lstat(filepath.Join(target, "workload.sock")); !os.IsNotExist(err) {
		t.Fatalf("symlink target gained a socket: %v", err)
	}
}

func TestWorkloadSocketPreservesExistingRegularFile(t *testing.T) {
	path := filepath.Join(privateSocketTestDir(t), "workload.sock")
	if err := os.WriteFile(path, []byte("existing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serveSocketForBoundaryTest(path); err == nil {
		t.Fatal("Workload API replaced an existing regular file")
	}
	got, err := os.ReadFile(path) // #nosec G304 -- exact test-created file, checked after refusal
	if err != nil || string(got) != "existing data" {
		t.Fatalf("existing file changed: %q, %v", got, err)
	}
}

func TestWorkloadSocketPreservesLiveListener(t *testing.T) {
	path := filepath.Join(privateSocketTestDir(t), "workload.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := serveSocketForBoundaryTest(path); err == nil {
		t.Fatal("Workload API replaced a live listener")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("live listener path changed: %v", err)
	}
}

func TestWorkloadSocketReusesOnlyOwnStaleSocket(t *testing.T) {
	path := filepath.Join(privateSocketTestDir(t), "workload.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	err = serveSocketForBoundaryTest(path)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("platform without Unix owner checks accepted a stale socket")
		}
		return
	}
	if err != nil {
		t.Fatalf("own stale socket was not replaced: %v", err)
	}
}

func TestWorkloadSocketModeIsOwnerOnlyAtBind(t *testing.T) {
	path := filepath.Join(privateSocketTestDir(t), "workload.sock")
	listener, err := ListenWorkloadAPI(path)
	if runtime.GOOS == "windows" {
		if err == nil {
			_ = listener.Close()
			t.Fatal("platform without Unix owner checks bound a Workload API socket")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("bound socket mode = %v, error = %v", info, err)
	}
}
