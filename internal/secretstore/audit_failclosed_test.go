package secretstore

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// failingAuditor returns an error from every Audit call, modelling an event log
// that cannot accept an append (NATS down / backpressure / marshal error).
type failingAuditor struct{ err error }

func (f failingAuditor) Audit(context.Context, string, string, []byte) error { return f.err }

// TestSecretWriteFailsClosedWhenEventDropped is the CODE-001 acceptance: the
// version-written event is the AN-2 source of truth for a secret's history, so a
// write whose event cannot be recorded must FAIL CLOSED — Put returns the error
// rather than silently committing a local version with no event behind it. It
// FAILS on the pre-fix tree (emitWrite discarded the error with `_ =` and Put
// returned success) and PASSES after.
func TestSecretWriteFailsClosedWhenEventDropped(t *testing.T) {
	wantErr := errors.New("event log unavailable")
	s, err := New(Config{TenantID: "t1", KEK: make([]byte, 32), Audit: failingAuditor{err: wantErr}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, putErr := s.Put(ctx, "app/db", []byte("v1"), "")
	if putErr == nil {
		t.Fatal("Put returned nil error when the source-of-truth event was dropped; want a fail-closed error")
	}
	if !errors.Is(putErr, wantErr) {
		t.Fatalf("Put error = %v; want it to wrap the dropped-event error %v", putErr, wantErr)
	}
	// And the write must NOT have left an orphaned local version behind the dropped event.
	if vs := s.Versions("app/db"); len(vs) != 0 {
		t.Errorf("a write whose event was dropped left %d local version(s); want 0 (no orphaned state)", len(vs))
	}
}

// TestSecretDeleteAndPurgeFailClosedWhenEventDropped extends the CODE-001
// acceptance to the delete tombstone and the destructive purge: both are
// event-sourced state changes that must fail closed if the event cannot be
// recorded, rather than mutating local state with no audit/event trail.
func TestSecretDeleteAndPurgeFailClosedWhenEventDropped(t *testing.T) {
	ctx := context.Background()

	// Seed a secret with a working auditor, then swap in a failing one.
	rec := &auditsink.Recorder{}
	s, err := New(Config{TenantID: "t1", KEK: make([]byte, 32), Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "app/db", []byte("v1"), ""); err != nil {
		t.Fatal(err)
	}
	s.audit = failingAuditor{err: errors.New("event log unavailable")}

	if err := s.Delete(ctx, "app/db"); err == nil {
		t.Error("Delete returned nil error when its tombstone event was dropped; want a fail-closed error")
	}
	if err := s.Purge(ctx, "app/db"); err == nil {
		t.Error("Purge returned nil error when its purge event was dropped; want a fail-closed error")
	}
	// Purge must not have destroyed local state when its event could not be recorded.
	if vs := s.Versions("app/db"); len(vs) == 0 {
		t.Error("Purge destroyed local state despite a dropped event; want the secret preserved (fail closed)")
	}
}
