// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// destroyBorrowGrace bounds how long a parked in-flight private-key operation waits to
// hear that a concurrent Destroy finished. The wait is one-sided by construction, and
// that is what makes these deterministic tripwires instead of a race-detector lottery:
//
//   - Broken (Destroy wipes and releases the locked region while the operation holds a
//     slice into it): Destroy returns in microseconds, destroyed closes at once, the
//     parked operation resumes and parses released memory. On Linux the region is
//     munmapped and the process faults; elsewhere it parses zeros and the operation
//     fails. Either way this fails on the FIRST run, not one run in fifty.
//   - Fixed (Destroy waits for the borrow to drain): Destroy cannot return while we are
//     parked, so the wait always runs the full grace and the operation then completes
//     normally. No interleaving exists in which a correct implementation trips it.
const destroyBorrowGrace = 250 * time.Millisecond

// parkBorrowUntilDestroyed installs the package borrow hook so the FIRST locked-buffer
// borrow parks inside the private-key operation, lets a second goroutine call destroy
// while it is parked, and then waits (bounded by destroyBorrowGrace) to see whether
// destroy returned. The returned channel is closed once destroy has returned.
func parkBorrowUntilDestroyed(t *testing.T, destroy func()) <-chan struct{} {
	t.Helper()

	borrowed := make(chan struct{})   // closed once the operation holds the locked region
	destroying := make(chan struct{}) // closed immediately before Destroy is called
	destroyed := make(chan struct{})  // closed once Destroy has returned

	var once sync.Once
	prev := borrowObserver
	borrowObserver = func() {
		once.Do(func() {
			close(borrowed)
			<-destroying
			select {
			case <-destroyed:
			case <-time.After(destroyBorrowGrace):
			}
		})
	}
	t.Cleanup(func() { borrowObserver = prev })

	go func() {
		<-borrowed
		close(destroying)
		destroy()
		close(destroyed)
	}()
	return destroyed
}

// TestPQCSignInFlightSurvivesConcurrentDestroy is the AN-4/AN-8 lifetime tripwire for the
// ENTERPRISE signer's most dangerous interleaving: a DestroyKey landing while a Sign is
// already inside the private-key operation.
//
// cmd/trstctl-signer/ee_attach.go wires signing.WithKeyFactory(NewSignerKeyFactory()) into
// the production signer, so every ML-DSA and hybrid key the Enterprise binary custodies is
// one of these. The signer serves Sign and DestroyKey concurrently and holds no per-key
// lock across the private-key operation, so this ordering is reachable from two ordinary
// RPCs. Before the fix this method took a raw slice out of the locked secret.Buffer with
// Bytes() and used it unsynchronized, while Buffer.Destroy wiped and (on Linux) munmapped
// the region under it -- a use-after-free on the crown-jewel key.
//
// The contract this pins: an in-flight signature either completes correctly, or is refused
// with the destroyed-key error. It never reads released memory, and Destroy never returns
// while a reader still holds the region.
func TestPQCSignInFlightSurvivesConcurrentDestroy(t *testing.T) {
	signer, err := GenerateKey(MLDSA44)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", MLDSA44, err)
	}
	public := signer.Public()
	destroyed := parkBorrowUntilDestroyed(t, signer.Destroy)

	message := []byte("destroy during pqc sign")
	sig, err := signer.Sign(message, SignOptions{})
	if err != nil {
		t.Fatalf("in-flight Sign was broken by a concurrent Destroy: %v "+
			"(the locked key region was wiped/released while this signature held a slice into it)", err)
	}
	if err := Verify(public, message, sig); err != nil {
		t.Fatalf("signature produced under a concurrent Destroy does not verify: %v", err)
	}

	select {
	case <-destroyed:
	case <-time.After(30 * time.Second):
		t.Fatal("Destroy never returned after the in-flight signature finished: the borrow is not being released")
	}

	// Destroy really happened: the key is gone and later signatures fail closed.
	if _, err := signer.Sign(message, SignOptions{}); err == nil {
		t.Fatal("Sign succeeded after Destroy returned; the key material must be gone")
	} else if !strings.Contains(err.Error(), destroyedSigningKeyMsg) {
		t.Fatalf("Sign after Destroy = %v, want %q", err, destroyedSigningKeyMsg)
	}
}

// TestPQCKEMDecapsulateInFlightSurvivesConcurrentDestroy pins the same lifetime contract
// for ML-KEM custody: PCAS KEM custody lives inside the signer too (ee_attach.go's
// signing.WithKEMCustody), so a decapsulation can race the destruction of its own key.
func TestPQCKEMDecapsulateInFlightSurvivesConcurrentDestroy(t *testing.T) {
	kemKey, err := GenerateKEMKey(MLKEM768)
	if err != nil {
		t.Fatalf("GenerateKEMKey(%s): %v", MLKEM768, err)
	}
	ciphertext, want, err := Encapsulate(kemKey.Public())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	destroyed := parkBorrowUntilDestroyed(t, kemKey.Destroy)

	got, err := kemKey.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("in-flight Decapsulate was broken by a concurrent Destroy: %v "+
			"(the locked key region was wiped/released while this decapsulation held a slice into it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the shared secret decapsulated under a concurrent Destroy does not match the encapsulated one")
	}

	select {
	case <-destroyed:
	case <-time.After(30 * time.Second):
		t.Fatal("Destroy never returned after the in-flight decapsulation finished: the borrow is not being released")
	}

	if _, err := kemKey.Decapsulate(ciphertext); err == nil {
		t.Fatal("Decapsulate succeeded after Destroy returned; the key material must be gone")
	} else if !strings.Contains(err.Error(), destroyedKEMKeyMsg) {
		t.Fatalf("Decapsulate after Destroy = %v, want %q", err, destroyedKEMKeyMsg)
	}
}

// TestPQCDestroyBeforeUseFailsClosed pins the other half of the contract: when Destroy
// wins the race outright, every borrow is refused and nothing is produced from released
// material. It covers all three key types this package custodies for the signer.
func TestPQCDestroyBeforeUseFailsClosed(t *testing.T) {
	signer, err := GenerateKey(MLDSA44)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", MLDSA44, err)
	}
	signer.Destroy()
	signer.Destroy() // idempotent
	if _, err := signer.Sign([]byte("after destroy"), SignOptions{}); err == nil {
		t.Fatal("Sign on a destroyed ML-DSA key must fail")
	} else if !strings.Contains(err.Error(), destroyedSigningKeyMsg) {
		t.Fatalf("Sign on a destroyed ML-DSA key = %v, want %q", err, destroyedSigningKeyMsg)
	}
	if _, err := signer.PrivateKeyBytes(); err == nil {
		t.Fatal("PrivateKeyBytes on a destroyed ML-DSA key must fail")
	} else if !strings.Contains(err.Error(), destroyedSigningKeyMsg) {
		t.Fatalf("PrivateKeyBytes on a destroyed ML-DSA key = %v, want %q", err, destroyedSigningKeyMsg)
	}

	kemKey, err := GenerateKEMKey(MLKEM768)
	if err != nil {
		t.Fatalf("GenerateKEMKey(%s): %v", MLKEM768, err)
	}
	kemKey.Destroy()
	kemKey.Destroy() // idempotent
	if _, err := kemKey.Decapsulate([]byte("not a ciphertext")); err == nil {
		t.Fatal("Decapsulate on a destroyed ML-KEM key must fail")
	} else if !strings.Contains(err.Error(), destroyedKEMKeyMsg) {
		t.Fatalf("Decapsulate on a destroyed ML-KEM key = %v, want %q", err, destroyedKEMKeyMsg)
	}
	if _, err := kemKey.PrivateKeyBytes(); err == nil {
		t.Fatal("PrivateKeyBytes on a destroyed ML-KEM key must fail")
	} else if !strings.Contains(err.Error(), destroyedKEMKeyMsg) {
		t.Fatalf("PrivateKeyBytes on a destroyed ML-KEM key = %v, want %q", err, destroyedKEMKeyMsg)
	}

	slh, err := GenerateSLHDSAKey(SLHDSA128f)
	if err != nil {
		t.Fatalf("GenerateSLHDSAKey(%s): %v", SLHDSA128f, err)
	}
	slh.Destroy()
	slh.Destroy() // idempotent
	if _, err := slh.Sign([]byte("after destroy"), SignOptions{}); err == nil {
		t.Fatal("Sign on a destroyed SLH-DSA key must fail")
	} else if !strings.Contains(err.Error(), destroyedSLHDSAKeyMsg) {
		t.Fatalf("Sign on a destroyed SLH-DSA key = %v, want %q", err, destroyedSLHDSAKeyMsg)
	}
	if _, err := slh.PrivateKeyBytes(); err == nil {
		t.Fatal("PrivateKeyBytes on a destroyed SLH-DSA key must fail")
	} else if !strings.Contains(err.Error(), destroyedSLHDSAKeyMsg) {
		t.Fatalf("PrivateKeyBytes on a destroyed SLH-DSA key = %v, want %q", err, destroyedSLHDSAKeyMsg)
	}
}
