//go:build chaos && linux

// SPDX-License-Identifier: MPL-2.0

package signing_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestChaosRealSignerAddressSpaceCapShedsWithoutWrongAnswers applies a REAL
// OS memory cap (RLIMIT_AS via prlimit, the unprivileged form of a cgroup
// memory limit) to the running signer and floods it. Safe directions: requests
// may fail or the process may die — but every SUCCESSFUL response must verify,
// and the flood must never hang past its deadline.
func TestChaosRealSignerAddressSpaceCapShedsWithoutWrongAnswers(t *testing.T) {
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
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	pub := signer.Public()

	// REAL memory pressure: cap the signer's address space to a fraction of a
	// normal Go process's appetite while it keeps serving.
	limit := unix.Rlimit{Cur: 384 << 20, Max: 384 << 20}
	if err := unix.Prlimit(cs.cmd.Process.Pid, unix.RLIMIT_AS, &limit, nil); err != nil {
		t.Fatalf("prlimit RLIMIT_AS on real signer: %v", err)
	}

	const flood = 64
	type outcome struct {
		sig []byte
		err error
	}
	results := make(chan outcome, flood)
	for i := 0; i < flood; i++ {
		go func() {
			sig, err := signer.SignDigest(digest, crypto.SignOptions{})
			results <- outcome{sig: sig, err: err}
		}()
	}
	succeeded, failed := 0, 0
	deadline := time.After(90 * time.Second)
	for i := 0; i < flood; i++ {
		select {
		case result := <-results:
			if result.err != nil {
				failed++
				continue
			}
			succeeded++
			if err := crypto.VerifyDigest(pub, digest, result.sig, crypto.SignOptions{}); err != nil {
				t.Fatal("UNSAFE: signer under memory pressure returned an INVALID signature — wrong answers are never a safe direction")
			}
		case <-deadline:
			t.Fatalf("UNSAFE: flood hung under memory pressure (%d/%d responses)", succeeded+failed, flood)
		}
	}
	t.Logf("memory-capped real signer: %d signed (all verified), %d shed/failed — both safe directions", succeeded, failed)
}
