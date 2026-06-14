package secretstore

import (
	"bytes"
	"context"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
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
	s := newStore(t, rec)
	ctx := context.Background()
	_, _ = s.Put(ctx, "app/db", []byte("v1"), "")
	_, _ = s.Put(ctx, "app/db", []byte("v2"), "")

	// Rebuild from the event log alone (AN-2 projection).
	rebuilt := Reconstruct(rec.Records(), "t1")
	envs := rebuilt["app/db"]
	if len(envs) != 2 {
		t.Fatalf("reconstructed %d versions, want 2", len(envs))
	}
	kek := s.kek
	pt, err := crypto.OpenEnvelope(kek, envs[1], []byte("t1|app/db"))
	if err != nil || string(pt) != "v2" {
		t.Fatalf("decrypt reconstructed v2 = %q (err %v), want v2", pt, err)
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
