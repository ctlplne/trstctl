// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

// TestSealAndCommitWipesExportedSigningKeyDER is the AN-8 regression guard for
// AUD-201 follow-up B2/V6. export() copies each signing key out of locked
// memory via signer.PKCS8(), whose contract says the caller MUST wipe the copy
// promptly — but Save wiped only the marshalled JSON, abandoning every signing
// key's raw DER on the GC heap at every checkpoint, recoverable from a heap
// dump or core file. This holds references to the exported copies and proves
// they are all-zero once the commit path returns. Save routes through the same
// sealAndCommit, so the checkpoint path inherits the wipe.
func TestSealAndCommitWipesExportedSigningKeyDER(t *testing.T) {
	ctx := context.Background()
	svc := &Service{audit: auditsink.Nop{}}
	if _, err := svc.CreateKey(ctx, "t1", "attest", KindSign); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rotate(ctx, "t1", "attest"); err != nil {
		t.Fatal(err)
	}

	exported, err := svc.ring("t1").export()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var refs [][]byte
	for _, p := range exported {
		for _, der := range p.SignPKCS8 {
			if len(der) > 0 {
				refs = append(refs, der)
			}
		}
	}
	if len(refs) != 2 {
		t.Fatalf("fixture is broken: expected 2 exported signing versions, got %d", len(refs))
	}
	for i, der := range refs {
		if allZero(der) {
			t.Fatalf("fixture is broken: exported DER %d is already zero", i)
		}
	}

	store := NewStore(t.TempDir(), testWrapper(t))
	state := persistedState{Format: transitStateFormat, Rings: map[string]map[string]persistedKey{"t1": exported}}
	if err := store.sealAndCommit(state); err != nil {
		t.Fatalf("sealAndCommit: %v", err)
	}
	for i, der := range refs {
		if !allZero(der) {
			t.Fatalf("exported signing-key DER %d survived the checkpoint unwiped on the heap (AN-8)", i)
		}
	}

	// The wipe must hit the COPIES, not the keyring: the live signing key still
	// signs after a checkpoint.
	if _, _, err := svc.Sign(ctx, "t1", "attest", []byte("still works")); err != nil {
		t.Fatalf("live signing key was damaged by the checkpoint wipe: %v", err)
	}
}

// TestRestoreWipesDecodedSigningKeyDER is the load-path half: after
// LockedKeyFromPKCS8 copies the DER into locked memory, the decoded heap buffer
// must be zeroed — and the restored key must still work, proving the wipe
// happens after the lock, not instead of it.
func TestRestoreWipesDecodedSigningKeyDER(t *testing.T) {
	ctx := context.Background()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	signer.Destroy()
	if allZero(der) {
		t.Fatal("fixture is broken: PKCS8 DER is already zero")
	}

	svc := &Service{audit: auditsink.Nop{}}
	ring := svc.ring("t1")
	if err := ring.restore(map[string]persistedKey{
		"attest": {Kind: KindSign, Latest: 1, SignPKCS8: [][]byte{nil, der}},
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !allZero(der) {
		t.Fatal("decoded signing-key DER survived restore unwiped on the heap (AN-8)")
	}
	if _, _, err := svc.Sign(ctx, "t1", "attest", []byte("post-restore")); err != nil {
		t.Fatalf("restored signing key does not sign (wipe ran before the lock?): %v", err)
	}
}

// TestRestoreDoesNotWipeAEADBuffers pins the aliasing constraint the wipe must
// respect: restore's AEAD/HMAC buffers BECOME the live ring keys, so wiping
// them would destroy the keyring it just restored. A restored AEAD key must
// still decrypt.
func TestRestoreDoesNotWipeAEADBuffers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wrapper := testWrapper(t)

	before := &Service{audit: auditsink.Nop{}}
	if _, err := before.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := before.Encrypt(ctx, "t1", "k", []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewStore(dir, wrapper).Save(before); err != nil {
		t.Fatal(err)
	}

	after := &Service{audit: auditsink.Nop{}}
	if err := NewStore(dir, wrapper).Load(after); err != nil {
		t.Fatal(err)
	}
	got, err := after.Decrypt(ctx, "t1", "k", ciphertext, nil)
	if err != nil {
		t.Fatalf("restored AEAD key cannot decrypt (its buffer was wiped?): %v", err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("decrypt = %q, want %q", got, "payload")
	}
}
