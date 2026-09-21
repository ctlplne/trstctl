// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package crypto

import (
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// TestSignDigestInFlightDoesNotFaultWhenDestroyMunmaps is the LINUX half of the
// AN-4/AN-8 destroy-during-sign contract, and it is linux-only for a concrete
// reason: internal/crypto/secret/mem_other.go (//go:build !linux) makes free() a
// bare `return nil`, so on darwin a Destroy racing a Sign only ZEROES the region.
// On Linux, mem_linux.go's free() ends in unix.Munmap, so the same race
// DEREFERENCES UNMAPPED MEMORY — the signer process takes an unexpected fault and
// dies. That is the AN-4 availability failure, and no darwin run can observe it.
//
// The assertion is explicit rather than "the binary survived": the signing
// goroutine sets runtime/debug.SetPanicOnFault(true) (per-goroutine), which turns
// a fault on unmapped memory into a recoverable runtime panic instead of a fatal
// crash. So this test reports "SignDigest faulted" as an ordinary test failure,
// with the fault address, and does not take the rest of the package's tests down
// with it.
//
// It also keeps the behavioral assertion, because a fault is not guaranteed: the
// allocator may re-map the freed address before the parked reader touches it, in
// which case the read silently returns garbage instead of faulting. Correct code
// produces a valid signature; broken code either faults or fails to parse.
func TestSignDigestInFlightDoesNotFaultWhenDestroyMunmaps(t *testing.T) {
	ls, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}

	borrowed := make(chan struct{})
	destroying := make(chan struct{})
	destroyed := make(chan struct{})

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

	digest, err := Digest(SHA256, []byte("munmap during sign"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	opts := SignOptions{Hash: SHA256}

	type outcome struct {
		sig   []byte
		err   error
		fault any
	}
	res := make(chan outcome, 1)
	go func() {
		// Per-goroutine: convert a dereference of the munmapped locked region into a
		// recoverable panic so this test can NAME the fault instead of aborting the
		// whole test binary. Restoring it is unnecessary — the setting dies with the
		// goroutine.
		debug.SetPanicOnFault(true)
		var out outcome
		defer func() {
			out.fault = recover()
			res <- out
		}()
		out.sig, out.err = ls.SignDigest(digest, opts)
	}()

	got := <-res
	if got.fault != nil {
		t.Fatalf("in-flight SignDigest FAULTED while a concurrent Destroy munmapped the locked key region: %v "+
			"(AN-4: this is a signer-process crash, AN-8: a use-after-free on the key)", got.fault)
	}
	if got.err != nil {
		t.Fatalf("in-flight SignDigest was broken by a concurrent Destroy: %v", got.err)
	}
	if err := VerifyDigest(ls.Public(), digest, got.sig, opts); err != nil {
		t.Fatalf("signature produced under a concurrent Destroy does not verify: %v", err)
	}

	select {
	case <-destroyed:
	case <-time.After(30 * time.Second):
		t.Fatal("Destroy never returned after the in-flight signature finished: the borrow is not being released")
	}
}
