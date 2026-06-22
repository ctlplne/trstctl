package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func newStore(t *testing.T, rec auditsink.Auditor) *Store {
	t.Helper()
	kek, _ := crypto.NewKEK()
	s, err := New(Config{TenantID: "t1", KEK: kek, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreVersionRollback(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	if _, err := s.Put(ctx, "app/db", []byte("v1"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "app/db", []byte("v2"), ""); err != nil {
		t.Fatal(err)
	}
	got, ver, err := s.Get(ctx, "app/db")
	if err != nil || string(got) != "v2" || ver != 2 {
		t.Fatalf("get latest = %q v%d (err %v), want v2 v2", got, ver, err)
	}
	if vs := s.Versions("app/db"); len(vs) != 2 {
		t.Errorf("versions = %v, want 2", vs)
	}
	// Rollback to v1 creates v3 with v1's content.
	nv, err := s.Rollback(ctx, "app/db", 1)
	if err != nil || nv != 3 {
		t.Fatalf("rollback -> v%d (err %v), want v3", nv, err)
	}
	got, _, _ = s.Get(ctx, "app/db")
	if string(got) != "v1" {
		t.Errorf("after rollback latest = %q, want v1", got)
	}
}

func TestStoreIdempotentWrite(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	v1, _ := s.Put(ctx, "p", []byte("x"), "key-1")
	v2, _ := s.Put(ctx, "p", []byte("x"), "key-1") // replay
	if v1 != v2 {
		t.Errorf("idempotent replay made a new version: %d vs %d", v1, v2)
	}
	if vs := s.Versions("p"); len(vs) != 1 {
		t.Errorf("idempotent replay wrote %d versions, want 1", len(vs))
	}
}

func TestStoreEncryptionAtRestAndNoPlaintextInLog(t *testing.T) {
	rec := &auditsink.Recorder{}
	s := newStore(t, rec)
	ctx := context.Background()
	secret := []byte("TOPSECRET-PLAINTEXT")
	if _, err := s.Put(ctx, "app/key", secret, ""); err != nil {
		t.Fatal(err)
	}
	// AN-8: the plaintext must never appear in any audit/event payload.
	for _, r := range rec.Records() {
		if bytes.Contains(r.Data, secret) {
			t.Fatalf("plaintext leaked into event %q", r.Type)
		}
	}
}

func TestStoreVersionHistoryReconstructsFromEvents(t *testing.T) {
	rec := &auditsink.Recorder{}
	kek, _ := crypto.NewKEK()
	w, err := seal.NewLocalKEK(kek)
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(kek) // the Store now holds the KEK in locked memory, not on the heap
	defer w.Destroy()
	s, err := New(Config{TenantID: "t1", KeyWrapper: w, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _ = s.Put(ctx, "app/db", []byte("v1"), "")
	_, _ = s.Put(ctx, "app/db", []byte("v2"), "")

	// AN-2: the current write event carries the binary seal container, not a raw
	// JSON envelope — Put seals through internal/crypto/seal like the served vault.
	records := rec.Records()
	var written writeEvent
	if err := json.Unmarshal(records[0].Data, &written); err != nil {
		t.Fatal(err)
	}
	if len(written.Sealed) == 0 {
		t.Fatalf("version-written event carries no binary sealed payload: %+v", written)
	}
	if written.Envelope.Ciphertext != nil {
		t.Fatalf("current write event still uses the legacy JSON envelope")
	}

	// Rebuild from the event log alone (AN-2 projection) and open with the wrapper.
	rebuilt, err := Reconstruct(records, "t1")
	if err != nil {
		t.Fatal(err)
	}
	revs := rebuilt["app/db"]
	if len(revs) != 2 {
		t.Fatalf("reconstructed %d versions, want 2", len(revs))
	}
	pt, err := revs[1].Open(w, "t1", "app/db")
	if err != nil || string(pt) != "v2" {
		t.Fatalf("decrypt reconstructed v2 = %q (err %v), want v2", pt, err)
	}
}

func TestStoreReconstructAcceptsLegacyEnvelopeVersion(t *testing.T) {
	// A pre-CRYPTO-004 event recorded a raw JSON envelope. Replay must still decode
	// and open it, so historical history is not lost by the binary-container switch.
	kek, _ := crypto.NewKEK()
	env, err := crypto.SealEnvelope(kek, []byte("legacy-v1"), []byte("t1|app/db"))
	if err != nil {
		t.Fatal(err)
	}
	env.Format = ""
	env.Version = 0 // a pre-SCHEMA-006 envelope with no metadata
	payload, err := json.Marshal(writeEvent{Path: "app/db", Version: 1, Envelope: env})
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := Reconstruct([]auditsink.Record{{
		Type:     EventVersionWritten,
		TenantID: "t1",
		Data:     payload,
	}}, "t1")
	if err != nil {
		t.Fatal(err)
	}
	revs := rebuilt["app/db"]
	if len(revs) != 1 || revs[0].Legacy == nil {
		t.Fatalf("legacy record did not reconstruct as a legacy Rev: %+v", revs)
	}
	w, err := seal.NewLocalKEK(kek)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	secret.Wipe(kek)
	pt, err := revs[0].Open(w, "t1", "app/db")
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "legacy-v1" {
		t.Fatalf("legacy reconstructed plaintext = %q, want legacy-v1", pt)
	}
}

func TestStoreReconstructRejectsUnknownEnvelopeVersion(t *testing.T) {
	kek, _ := crypto.NewKEK()
	env, err := crypto.SealEnvelope(kek, []byte("future"), []byte("t1|app/db"))
	if err != nil {
		t.Fatal(err)
	}
	env.Version = crypto.EnvelopeVersion + 1
	payload, err := json.Marshal(writeEvent{Path: "app/db", Version: 1, Envelope: env})
	if err != nil {
		t.Fatal(err)
	}

	_, err = Reconstruct([]auditsink.Record{{
		Type:     EventVersionWritten,
		TenantID: "t1",
		Data:     payload,
	}}, "t1")
	if err == nil {
		t.Fatal("Reconstruct accepted an explicitly unknown legacy envelope version")
	}
}

func TestStoreSoftDelete(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	_, _ = s.Put(ctx, "p", []byte("v1"), "")
	if err := s.Delete(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, "p"); err == nil {
		t.Error("Get returned a soft-deleted secret")
	}
}

// TestStoreKEKIsAWrapperNotHeapBytes pins CRYPTO-004: the Store must hold the KEK
// behind the crypto boundary (a seal.KeyWrapper in locked memory), never as a raw
// []byte field on the Go heap. This fails before the fix (when the field was
// `kek []byte`) and passes after.
func TestStoreKEKIsAWrapperNotHeapBytes(t *testing.T) {
	st := reflect.TypeOf(Store{})
	wrapperIface := reflect.TypeOf((*seal.KeyWrapper)(nil)).Elem()
	foundWrapper := false
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		// No field may be a raw byte slice holding key material on the heap.
		if f.Type == reflect.TypeOf([]byte(nil)) {
			t.Fatalf("Store.%s is a []byte on the heap — the KEK must stay in locked memory behind a wrapper (CRYPTO-004)", f.Name)
		}
		if f.Type.Implements(wrapperIface) || reflect.PtrTo(f.Type).Implements(wrapperIface) {
			foundWrapper = true
		}
	}
	if !foundWrapper {
		t.Fatal("Store holds no seal.KeyWrapper field; the KEK must be wrapped, not raw bytes (CRYPTO-004)")
	}
}

// TestRollbackWipesIntermediatePlaintext pins that Rollback zeroizes the exact
// plaintext buffer it lifts out of the store before returning (via secret.Wipe
// through the crypto boundary, not an elidable hand loop). A test seam captures the
// buffer's slice header just before the wipe; after Rollback returns it must be all
// zero. This fails if the wipe is removed or replaced by a loop the optimizer elides
// (CRYPTO-004 / CRYPTO-006).
func TestRollbackWipesIntermediatePlaintext(t *testing.T) {
	kek, _ := crypto.NewKEK()
	base, err := seal.NewLocalKEK(kek)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Destroy()
	secret.Wipe(kek)

	s, err := New(Config{TenantID: "t1", KeyWrapper: base})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Put(ctx, "p", []byte("SECRET-ROLLBACK"), ""); err != nil {
		t.Fatal(err)
	}

	var captured []byte
	rollbackPlaintextHook = func(pt []byte) { captured = pt } // aliases the live buffer
	defer func() { rollbackPlaintextHook = nil }()

	if _, err := s.Rollback(ctx, "p", 1); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("rollback never produced an intermediate plaintext buffer")
	}
	for i, b := range captured {
		if b != 0 {
			t.Fatalf("rollback plaintext byte %d = %d after return, want 0 (secret.Wipe not applied)", i, b)
		}
	}
	got, _, err := s.Get(ctx, "p")
	if err != nil || string(got) != "SECRET-ROLLBACK" {
		t.Fatalf("rollback re-publish = %q (err %v), want SECRET-ROLLBACK", got, err)
	}
}
