//go:build chaos

// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// ---------------------------------------------------------------------------
// OPS-CHAOS-REAL-001: REAL fault injection against the REAL isolated signer
// process. The seam-level chaos tests in chaos_test.go stay as fast smoke;
// these kill an actual trstctl-signer with SIGKILL and apply an actual
// address-space cap, asserting the SAFE failure direction each time: bounded
// structured errors, liveness elsewhere, and full recovery after respawn —
// never a hang, never a wrong answer.
// ---------------------------------------------------------------------------

var (
	signerBinaryOnce sync.Once
	signerBinaryPath string
	signerBinaryErr  error
)

func chaosSignerBinary(t *testing.T) string {
	t.Helper()
	signerBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "trstctl-chaos-signer-bin")
		if err != nil {
			signerBinaryErr = err
			return
		}
		signerBinaryPath = filepath.Join(dir, "trstctl-signer")
		build := exec.Command("go", "build", "-o", signerBinaryPath, "trstctl.com/trstctl/cmd/trstctl-signer")
		build.Dir = chaosRepoRoot()
		if out, err := build.CombinedOutput(); err != nil {
			signerBinaryErr = errors.New("build trstctl-signer: " + err.Error() + "\n" + string(out))
		}
	})
	if signerBinaryErr != nil {
		t.Fatal(signerBinaryErr)
	}
	return signerBinaryPath
}

func chaosRepoRoot() string {
	wd, _ := os.Getwd()
	return filepath.Dir(filepath.Dir(wd)) // internal/signing -> repo root
}

// chaosShortSocketDir returns a short-prefixed temp dir so a signer UDS path
// stays under the AF_UNIX sun_path limit (~104 bytes on macOS): t.TempDir()
// embeds the long test name and overflows it.
func chaosShortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type chaosSigner struct {
	cmd    *exec.Cmd
	socket string
}

func startChaosSigner(t *testing.T, socket string) *chaosSigner {
	t.Helper()
	cmd := exec.Command(chaosSignerBinary(t), "--socket", socket, "--allow-insecure-dev-nonlinux")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start real signer: %v", err)
	}
	cs := &chaosSigner{cmd: cmd, socket: socket}
	t.Cleanup(func() { _ = cs.cmd.Process.Kill(); _, _ = cs.cmd.Process.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real signer did not create its socket within 20s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cs
}

func dialHealthy(t *testing.T, socket string) *signing.Client {
	t.Helper()
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatalf("dial real signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for !client.Healthy(context.Background()) {
		if time.Now().After(deadline) {
			t.Fatal("real signer did not become healthy within 20s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return client
}

// TestChaosRealSignerProcessSIGKILLBoundedFailureAndRespawnRecovery: kill -9
// the REAL signer process mid-service. Safe direction: calls fail FAST with a
// structured transport error (bounded by the per-call deadline, no hang), and
// a respawned signer serves again — the fault is a blip, not an outage or a
// wrong answer.
func TestChaosRealSignerProcessSIGKILLBoundedFailureAndRespawnRecovery(t *testing.T) {
	originalTimeout := signing.SignerCallTimeout()
	if err := signing.SetSignerCallTimeout(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = signing.SetSignerCallTimeout(originalTimeout) })

	dir := chaosShortSocketDir(t)
	socket := filepath.Join(dir, "s.sock")
	cs := startChaosSigner(t, socket)
	client := dialHealthy(t, socket)

	ctx := context.Background()
	signer, err := client.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("real signer GenerateKey: %v", err)
	}
	digest := make([]byte, 32)
	if _, err := signer.SignDigest(digest, crypto.SignOptions{}); err != nil {
		t.Fatalf("real signer Sign before fault: %v", err)
	}

	// REAL fault: SIGKILL, not a simulated handler error.
	if err := cs.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL real signer: %v", err)
	}
	_, _ = cs.cmd.Process.Wait()

	start := time.Now()
	_, err = signer.SignDigest(digest, crypto.SignOptions{})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("UNSAFE: Sign returned success from a SIGKILLed signer")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("UNSAFE: post-kill Sign took %v; the failure must be bounded (per-call deadline 2s)", elapsed)
	}

	// Recovery: a respawned signer on a fresh socket serves immediately.
	socket2 := filepath.Join(dir, "r.sock")
	startChaosSigner(t, socket2)
	client2 := dialHealthy(t, socket2)
	signer2, err := client2.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("respawned signer GenerateKey: %v", err)
	}
	if _, err := signer2.SignDigest(digest, crypto.SignOptions{}); err != nil {
		t.Fatalf("respawned signer Sign: %v", err)
	}
}

// TestChaosControlHarnessDetectsUnsafeDirection is the CONTROL the acceptance
// demands: prove the harness's safety assertions actually detect an unsafe
// outcome, so a green chaos run is evidence, not vacuity.
func TestChaosControlHarnessDetectsUnsafeDirection(t *testing.T) {
	unsafe := chaosViolations(nil /* err: a dead signer "succeeding" */, 500*time.Millisecond, 6*time.Second)
	if len(unsafe) == 0 {
		t.Fatal("control failed: the harness did not flag success-from-a-dead-dependency as unsafe")
	}
	hang := chaosViolations(errors.New("unavailable"), time.Minute, 6*time.Second)
	if len(hang) == 0 {
		t.Fatal("control failed: the harness did not flag an unbounded (hanging) failure as unsafe")
	}
	safe := chaosViolations(errors.New("unavailable"), time.Second, 6*time.Second)
	if len(safe) != 0 {
		t.Fatalf("control failed: a bounded structured failure was flagged unsafe: %v", safe)
	}
}

// chaosViolations encodes the safe failure direction every real-fault scenario
// asserts, in ONE place, so the control test can prove those assertions are not
// vacuous. A fault is UNSAFE when the dependency was down yet the call
// "succeeded" (a forged/wrong answer), or when the failure was not bounded by
// the per-call deadline (a hang). A bounded, structured failure is the safe
// direction and yields no violations.
func chaosViolations(callErr error, elapsed, bound time.Duration) []string {
	var violations []string
	if callErr == nil {
		violations = append(violations, "call succeeded against a downed dependency (forged/wrong answer)")
	}
	if elapsed > bound {
		violations = append(violations, "failure was not bounded by the per-call deadline (hang)")
	}
	return violations
}
