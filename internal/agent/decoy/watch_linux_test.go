// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package decoy

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Q6-O1: another process opening a decoy is reported; with fanotify (the
// agent holding CAP_SYS_ADMIN) the report names the process, with inotify it
// reports the open alone. Run in a Linux container by runners/q6o1-lab.sh,
// with and without CAP_SYS_ADMIN.
func TestAnotherProcessOpeningADecoyIsReportedQ6O1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519_backup")
	decoys, err := Plant([]string{path}, filepath.Join(dir, "decoys.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	accesses := make(chan Access, 8)
	mechanism := make(chan string, 1)
	go func() {
		m, err := Watch(ctx, decoys, func(a Access) { accesses <- a })
		if err != nil {
			t.Errorf("Watch: %v", err)
		}
		mechanism <- m
	}()
	time.Sleep(500 * time.Millisecond)                                                                                               // the watcher arms its marks
	if out, err := exec.Command("cat", path).CombinedOutput(); err != nil || !strings.Contains(string(out), "OPENSSH PRIVATE KEY") { // #nosec G204 -- the test's own decoy path (CWE-78)
		t.Fatalf("cat the decoy: %v", err)
	}
	var got Access
	select {
	case got = <-accesses:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatalf("no access reported (mechanism %s)", <-mechanism)
	}
	cancel()
	m := <-mechanism
	t.Logf("mechanism %s: %+v", m, got)
	if got.Path != path || got.At.IsZero() || got.Mechanism != m {
		t.Fatalf("access = %+v (mechanism %s)", got, m)
	}
	if m == "fanotify" && (got.PID <= 0 || !strings.Contains(got.Process, "cat")) {
		t.Fatalf("fanotify access = %+v; want the cat process named", got)
	}
}
