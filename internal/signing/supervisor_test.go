//go:build unix

package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/signing"
)

// TestSupervisorRestartsKilledChild is the AN-4 supervision acceptance: the
// control plane runs the signer as a child process, and if the child dies the
// supervisor relaunches it with backoff and the connection recovers. (Keys are
// held in the signer's memory and do not survive a restart by design — recovery
// here means the process is back and serving.)
func TestSupervisorRestartsKilledChild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the signer child; skipped in -short")
	}
	bin := buildSigner(t)
	dir, err := os.MkdirTemp("", "ts-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sup, err := signing.Supervise(ctx, bin, socket)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	defer sup.Close()

	if c := sup.Client(); c == nil || !c.Healthy(ctx) {
		t.Fatal("signer not healthy after initial start")
	}
	oldPid := sup.Pid()
	if oldPid == 0 {
		t.Fatal("supervisor reports no child pid")
	}

	// Kill the child out of band; the supervisor must relaunch it.
	if err := syscall.Kill(oldPid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill child: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		newPid := sup.Pid()
		if newPid != 0 && newPid != oldPid {
			if c := sup.Client(); c != nil && c.Healthy(ctx) {
				// Recovered: a new, healthy child is running. The relaunch must
				// also show in the restart counter the control plane samples for
				// trstctl_signer_restarts_total (SF.3).
				if sup.Restarts() == 0 {
					t.Errorf("supervisor relaunched the child but Restarts() is still 0")
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("supervisor did not restart the killed signer (pid still %d)", sup.Pid())
}

// TestSupervisorFailsFastOnBadBinary: a binary that never becomes ready surfaces
// an error at Supervise time rather than silently retrying forever.
func TestSupervisorFailsFastOnBadBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := signing.Supervise(ctx, "/nonexistent/trstctl-signer", filepath.Join(t.TempDir(), "s.sock"))
	if err == nil {
		t.Fatal("Supervise with a nonexistent binary should return an error")
	}
}
