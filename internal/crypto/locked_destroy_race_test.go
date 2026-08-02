// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// destroyBorrowGrace bounds how long the parked in-flight signature waits to hear
// that a concurrent Destroy finished. The wait is one-sided by construction, and
// that is what makes this a deterministic tripwire instead of a race-detector
// lottery:
//
//   - Broken (Destroy wipes and releases the locked region while a Sign holds a
//     slice into it): Destroy returns in microseconds, destroyed closes at once,
//     the parked signature resumes and parses released memory. On Linux the region
//     is munmapped and the process faults; elsewhere it parses zeros and SignDigest
//     fails. Either way this test fails on the FIRST run, not one run in fifty.
//   - Fixed (Destroy waits for the borrow to drain): Destroy cannot return while we
//     are parked, so the wait always runs the full grace and the signature then
//     completes normally. No interleaving exists in which a correct implementation
//     trips it.
const destroyBorrowGrace = 250 * time.Millisecond

// TestSignDigestInFlightSurvivesConcurrentDestroy is the AN-4/AN-8 lifetime
// tripwire for the signer's most dangerous interleaving: a DestroyKey landing
// while a Sign is already inside the private-key operation.
//
// The signer serves Sign and DestroyKey concurrently and holds neither its own
// mutex nor any per-key lock across the private-key operation, so this ordering is
// reachable from two ordinary RPCs. Before the fix, LockedSigner.SignDigest took a
// raw slice out of the locked secret.Buffer and used it unsynchronized, while
// Buffer.Destroy wiped and (on Linux) munmapped the region under it — a
// use-after-free on the crown-jewel key.
//
// The contract this pins: an in-flight signature either completes correctly, or is
// refused with the destroyed-key error. It never reads released memory, and Destroy
// never returns while a reader still holds the region.
func TestSignDigestInFlightSurvivesConcurrentDestroy(t *testing.T) {
	ls, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}

	borrowed := make(chan struct{})   // closed once the signature holds the locked region
	destroying := make(chan struct{}) // closed immediately before Destroy is called
	destroyed := make(chan struct{})  // closed once Destroy has returned

	var once sync.Once
	prev := signDigestBorrowObserver
	signDigestBorrowObserver = func() {
		once.Do(func() {
			close(borrowed)
			<-destroying
			select {
			case <-destroyed:
			case <-time.After(destroyBorrowGrace):
			}
		})
	}
	t.Cleanup(func() { signDigestBorrowObserver = prev })

	go func() {
		<-borrowed
		close(destroying)
		ls.Destroy()
		close(destroyed)
	}()

	digest, err := Digest(SHA256, []byte("destroy during sign"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	opts := SignOptions{Hash: SHA256}

	sig, err := ls.SignDigest(digest, opts)
	if err != nil {
		t.Fatalf("in-flight SignDigest was broken by a concurrent Destroy: %v "+
			"(the locked key region was wiped/released while this signature held a slice into it)", err)
	}
	if err := VerifyDigest(ls.Public(), digest, sig, opts); err != nil {
		t.Fatalf("signature produced under a concurrent Destroy does not verify: %v", err)
	}

	select {
	case <-destroyed:
	case <-time.After(30 * time.Second):
		t.Fatal("Destroy never returned after the in-flight signature finished: the borrow is not being released")
	}

	// Destroy really happened: the key is gone and later signatures fail closed.
	if _, err := ls.SignDigest(digest, opts); err == nil {
		t.Fatal("SignDigest succeeded after Destroy returned; the key material must be gone")
	} else if !strings.Contains(err.Error(), "locked key has been destroyed") {
		t.Fatalf("SignDigest after Destroy = %v, want the destroyed-key error", err)
	}
}

// TestDestroyBeforeSignFailsClosed pins the other half of the contract: when
// Destroy wins the race outright, the borrow is refused and no signature is
// produced from released material.
func TestDestroyBeforeSignFailsClosed(t *testing.T) {
	ls, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	ls.Destroy()
	ls.Destroy() // idempotent

	digest, err := Digest(SHA256, []byte("after destroy"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if _, err := ls.SignDigest(digest, SignOptions{Hash: SHA256}); err == nil {
		t.Fatal("SignDigest on a destroyed key must fail")
	} else if !strings.Contains(err.Error(), "locked key has been destroyed") {
		t.Fatalf("SignDigest on a destroyed key = %v, want the destroyed-key error", err)
	}
	if _, err := ls.PKCS8(); err == nil {
		t.Fatal("PKCS8 on a destroyed key must fail")
	}
	if _, err := ls.PrivateKeyPEM(); err == nil {
		t.Fatal("PrivateKeyPEM on a destroyed key must fail")
	}
}
