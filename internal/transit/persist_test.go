// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/seal"
)

func testWrapper(t *testing.T) seal.KeyWrapper {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// TestTransitKeysSurviveARestart is the regression guard for the ephemeral
// keyring.
//
// The keyring lived only in memory, so every key vanished on restart and
// anything encrypted with it became permanently undecryptable — a data-loss bug
// wearing the costume of a cache. A fresh Service stands in for the restart.
func TestTransitKeysSurviveARestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wrapper := testWrapper(t)
	const tenant = "t-transit"

	before := &Service{audit: auditsink.Nop{}}
	if _, err := before.CreateKey(ctx, tenant, "app-data", KindAEAD); err != nil {
		t.Fatalf("create aead key: %v", err)
	}
	if _, err := before.Rotate(ctx, tenant, "app-data"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := before.CreateKey(ctx, tenant, "receipts", KindHMAC); err != nil {
		t.Fatalf("create hmac key: %v", err)
	}
	if _, err := before.CreateKey(ctx, tenant, "attest", KindSign); err != nil {
		t.Fatalf("create sign key: %v", err)
	}

	plaintext := []byte("the row that must still be readable tomorrow")
	aad := []byte("tenant=t-transit")
	ciphertext, err := before.Encrypt(ctx, tenant, "app-data", plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mac, err := before.HMAC(ctx, tenant, "receipts", plaintext)
	if err != nil {
		t.Fatalf("hmac: %v", err)
	}

	store := NewStore(dir, wrapper)
	if store == nil {
		t.Fatal("NewStore returned nil for a configured dir and wrapper")
	}
	if err := store.Save(before); err != nil {
		t.Fatalf("save keyring: %v", err)
	}

	// Restart.
	after := &Service{audit: auditsink.Nop{}}
	if err := NewStore(dir, wrapper).Load(after); err != nil {
		t.Fatalf("load keyring: %v", err)
	}

	got, err := after.Decrypt(ctx, tenant, "app-data", ciphertext, aad)
	if err != nil {
		t.Fatalf("ciphertext written before the restart is no longer decryptable: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted %q, want %q", got, plaintext)
	}

	mac2, err := after.HMAC(ctx, tenant, "receipts", plaintext)
	if err != nil {
		t.Fatalf("hmac after restart: %v", err)
	}
	if !bytes.Equal(mac, mac2) {
		t.Error("the HMAC key changed across the restart, so previously issued receipts no longer verify")
	}

	if _, _, err := after.Sign(ctx, tenant, "attest", plaintext); err != nil {
		t.Errorf("the signing key did not survive the restart: %v", err)
	}
}

// TestSealedKeyringNeverWritesKeyMaterialInTheClear is the AN-8 half: the file on
// disk must not contain the key bytes, and must not be openable without the KEK.
func TestSealedKeyringNeverWritesKeyMaterialInTheClear(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wrapper := testWrapper(t)

	svc := &Service{audit: auditsink.Nop{}}
	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(dir, wrapper).Save(svc); err != nil {
		t.Fatal(err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, transitStateFile))
	if err != nil {
		t.Fatal(err)
	}
	// The raw key bytes must not appear in the file.
	svc.mu.Lock()
	ring := svc.rings["t1"]
	svc.mu.Unlock()
	ring.mu.Lock()
	// Versions are 1-based, so index 0 is a placeholder. Take every real version
	// and refuse to search for an empty needle — bytes.Contains(x, nil) is true
	// for any x, which would make this assertion pass for the wrong reason.
	var versions [][]byte
	for _, v := range ring.keys["k"].aead {
		if len(v) > 0 {
			versions = append(versions, append([]byte(nil), v...))
		}
	}
	ring.mu.Unlock()
	if len(versions) == 0 {
		t.Fatal("fixture is broken: the key has no versions to look for")
	}
	for i, raw := range versions {
		if bytes.Contains(onDisk, raw) {
			t.Fatalf("the sealed keyring file contains raw key bytes for version %d", i+1)
		}
	}
	if bytes.Contains(onDisk, []byte("aead")) {
		t.Error("the sealed file leaks its plaintext structure; it should be opaque ciphertext")
	}

	// A different KEK must not open it.
	other := &Service{audit: auditsink.Nop{}}
	if err := NewStore(dir, testWrapper(t)).Load(other); err == nil {
		t.Fatal("the keyring opened under a DIFFERENT KEK; it is not actually sealed to this deployment")
	}
}

// TestPersistenceIsRefusedRatherThanWrittenInTheClear pins the fail-closed edge:
// with no KEK wrapper there is no safe way to persist key material, so the store
// must be absent rather than silently writing plaintext.
func TestPersistenceIsRefusedRatherThanWrittenInTheClear(t *testing.T) {
	if NewStore(t.TempDir(), nil) != nil {
		t.Error("a store was created with no KEK wrapper; key material would be written unsealed")
	}
	if NewStore("", testWrapper(t)) != nil {
		t.Error("a store was created with no directory")
	}
	// A nil store must be a no-op, not a panic, so callers need no special case.
	var s *Store
	if err := s.Save(&Service{audit: auditsink.Nop{}}); err != nil {
		t.Errorf("nil store Save: %v", err)
	}
	if err := s.Load(&Service{audit: auditsink.Nop{}}); err != nil {
		t.Errorf("nil store Load: %v", err)
	}
}

// TestCheckpointRunsOnEveryKeyMutation guards the half that makes persistence
// reliable rather than merely possible: a key that works until the next restart
// and then silently does not is exactly the failure this mechanism exists to
// prevent, so create and rotate must both checkpoint.
func TestCheckpointRunsOnEveryKeyMutation(t *testing.T) {
	ctx := context.Background()
	svc := &Service{audit: auditsink.Nop{}}
	saves := 0
	svc.SetPersist(func() error { saves++; return nil })

	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err != nil {
		t.Fatal(err)
	}
	if saves != 1 {
		t.Fatalf("create checkpointed %d times, want 1", saves)
	}
	if _, err := svc.Rotate(ctx, "t1", "k"); err != nil {
		t.Fatal(err)
	}
	if saves != 2 {
		t.Fatalf("rotate checkpointed %d times, want 2", saves)
	}

	// A read must NOT checkpoint — that would turn every decrypt into a disk write.
	if _, err := svc.Encrypt(ctx, "t1", "k", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if saves != 2 {
		t.Errorf("an encrypt checkpointed the keyring (%d saves); only mutations should", saves)
	}
}

// TestFailedCheckpointFailsTheMutation keeps the error from being swallowed: if
// the key cannot be persisted, the caller must not be told it was created.
func TestFailedCheckpointFailsTheMutation(t *testing.T) {
	ctx := context.Background()
	svc := &Service{audit: auditsink.Nop{}}
	svc.SetPersist(func() error { return errDiskFull })

	if _, err := svc.CreateKey(ctx, "t1", "k", KindAEAD); err == nil {
		t.Fatal("CreateKey reported success although the key could not be persisted; " +
			"the caller would use a key that disappears on the next restart")
	}
}

var errDiskFull = errors.New("disk full")
