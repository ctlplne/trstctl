// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

var errCheckpointRefused = errors.New("checkpoint refused")

// TestFailedCheckpointRollsTheKeyOutOfTheRing is the regression guard for
// AUD-201 follow-up B3/V4. CreateKey mutated the ring first and checkpointed
// second with no rollback, so on a Save failure the caller got an error while
// the key stayed silently USABLE: Encrypt succeeded, a retry reported
// "transit: key exists", and the next restart dropped the key — leaving
// ciphertext nothing can ever decrypt. docs/limitations.md already claimed "a
// failed checkpoint fails the mutation"; only the response failed.
func TestFailedCheckpointRollsTheKeyOutOfTheRing(t *testing.T) {
	ctx := context.Background()
	svc := &Service{audit: auditsink.Nop{}}
	persistWorks := false
	svc.SetPersist(func() error {
		if persistWorks {
			return nil
		}
		return errCheckpointRefused
	})

	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err == nil {
		t.Fatal("CreateKey succeeded although the checkpoint failed")
	}
	// The phantom key must be GONE, not silently usable.
	if _, err := svc.Encrypt(ctx, "t1", "k", []byte("x"), nil); err == nil {
		t.Fatal("a key whose creation failed still encrypts; it would die on the next restart taking its ciphertext with it")
	}
	// And a retry must succeed rather than reporting "key exists".
	persistWorks = true
	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatalf("retry after a failed checkpoint: %v (the phantom key was left in the ring)", err)
	}
	if _, err := svc.Encrypt(ctx, "t1", "k", []byte("x"), nil); err != nil {
		t.Fatalf("encrypt after successful retry: %v", err)
	}
}

// TestFailedCheckpointRollsTheRotationBack is the Rotate half: the new version
// must be discarded, ciphertext under the previous version must stay
// decryptable, and a retried rotation must land on the version the failed one
// claimed.
func TestFailedCheckpointRollsTheRotationBack(t *testing.T) {
	ctx := context.Background()
	svc := &Service{audit: auditsink.Nop{}}
	persistWorks := true
	svc.SetPersist(func() error {
		if persistWorks {
			return nil
		}
		return errCheckpointRefused
	})

	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatal(err)
	}
	ct1, err := svc.Encrypt(ctx, "t1", "k", []byte("v1 payload"), nil)
	if err != nil {
		t.Fatal(err)
	}

	persistWorks = false
	if _, err := svc.Rotate(ctx, "t1", "k"); err == nil {
		t.Fatal("Rotate succeeded although the checkpoint failed")
	}
	// New encryptions must still use version 1 — version 2 was rolled back.
	ct, err := svc.Encrypt(ctx, "t1", "k", []byte("post-failure"), nil)
	if err != nil {
		t.Fatalf("encrypt after rolled-back rotate: %v", err)
	}
	if v, err := CiphertextVersion(ct); err != nil || v != 1 {
		t.Fatalf("post-failure ciphertext version = %d (%v), want 1: the unpersisted version is still live", v, err)
	}
	if _, err := svc.Decrypt(ctx, "t1", "k", ct1, nil); err != nil {
		t.Fatalf("v1 ciphertext no longer decrypts after the rollback: %v", err)
	}

	// A retried rotation succeeds and lands on version 2.
	persistWorks = true
	info, err := svc.Rotate(ctx, "t1", "k")
	if err != nil {
		t.Fatalf("retry rotate: %v", err)
	}
	if info.Version != 2 {
		t.Fatalf("retried rotation produced version %d, want 2", info.Version)
	}
	if _, err := svc.Decrypt(ctx, "t1", "k", ct1, nil); err != nil {
		t.Fatalf("v1 ciphertext must survive a later successful rotation: %v", err)
	}
}
