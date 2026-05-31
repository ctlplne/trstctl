package audit_test

import (
	"context"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/audit"
	"certctl.io/certctl/internal/events"
)

// appendActor appends an event attributed to subject (R2.1 attribution).
func appendActor(t *testing.T, log *events.Log, tenantID, typ, subject string, roles ...string) {
	t.Helper()
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: subject, Roles: roles})
	if _, err := log.Append(ctx, events.Event{Type: typ, TenantID: tenantID, Data: []byte(`{}`)}); err != nil {
		t.Fatalf("append: %v", err)
	}
}

// TestRecordCarriesActor: the audit record surfaces who performed the mutation,
// so a "who did what, when" trail is reconstructable from the log.
func TestRecordCarriesActor(t *testing.T) {
	log := openLog(t)
	appendActor(t, log, tenantA, "owner.created", "bob@example.com", "operator")
	svc := newService(t, log)

	recs, err := svc.Search(context.Background(), audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Actor == nil || recs[0].Actor.Subject != "bob@example.com" {
		t.Fatalf("record actor = %+v, want subject bob@example.com", recs[0].Actor)
	}
	if len(recs[0].Actor.Roles) != 1 || recs[0].Actor.Roles[0] != "operator" {
		t.Errorf("record actor roles = %v, want [operator]", recs[0].Actor.Roles)
	}
}

// TestChainDetectsTampering is the R2.1 tamper-evidence acceptance: audit records
// are hash-linked, and the chain-verification routine detects any alteration of a
// stored event.
func TestChainDetectsTampering(t *testing.T) {
	log := openLog(t)
	appendActor(t, log, tenantA, "owner.created", "alice", "admin")
	appendActor(t, log, tenantA, "identity.issued", "alice", "admin")
	appendActor(t, log, tenantA, "identity.revoked", "alice", "admin")
	svc := newService(t, log)

	recs, err := svc.Search(context.Background(), audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	// The untouched chain verifies, returning a non-empty head.
	head, err := audit.VerifyChain(recs)
	if err != nil {
		t.Fatalf("VerifyChain on an intact chain: %v", err)
	}
	if head == "" {
		t.Fatal("VerifyChain returned an empty head for a non-empty chain")
	}

	// Tamper the middle record's payload (the attacker cannot also recompute every
	// downstream hash without the chain breaking). Verification must detect it.
	tampered := append([]audit.Record(nil), recs...)
	tampered[1].Data = []byte(`{"tampered":true}`)
	if _, err := audit.VerifyChain(tampered); err == nil {
		t.Fatal("VerifyChain did not detect a tampered stored event")
	}

	// Dropping an event (truncation) is also detected.
	dropped := []audit.Record{recs[0], recs[2]}
	if _, err := audit.VerifyChain(dropped); err == nil {
		t.Fatal("VerifyChain did not detect a dropped event")
	}
}

// TestExportPersistentKeyVerifiesAcrossRestart is the R2.1 persistent-key
// acceptance: a signed evidence bundle exported before a restart still verifies
// after the export key is reloaded from disk, and the bundle's chain head anchors
// the records so post-export tampering is detectable.
func TestExportPersistentKeyVerifiesAcrossRestart(t *testing.T) {
	log := openLog(t)
	appendActor(t, log, tenantA, "owner.created", "alice", "admin")
	appendActor(t, log, tenantA, "identity.issued", "alice", "admin")

	keyPath := filepath.Join(t.TempDir(), "signing-key.pem")

	// First boot: create + persist the key, export a signed bundle.
	sk1, err := audit.LoadOrCreateSigningKey(keyPath, "audit-export")
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey (create): %v", err)
	}
	svc1 := audit.NewService(log, sk1)
	signed, err := svc1.Export(context.Background(), audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Restart: reload the SAME key from disk (no rotation).
	sk2, err := audit.LoadOrCreateSigningKey(keyPath, "audit-export")
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey (load): %v", err)
	}
	svc2 := audit.NewService(log, sk2)

	bundle, err := audit.VerifyBundle(signed, svc2.VerificationKeys())
	if err != nil {
		t.Fatalf("a pre-restart bundle must verify after the key reloads: %v", err)
	}
	if bundle.ChainHead == "" {
		t.Fatal("verified bundle has no chain head to anchor tamper-evidence")
	}
	if bundle.Count != 2 || len(bundle.Records) != 2 {
		t.Fatalf("bundle has %d records, want 2", len(bundle.Records))
	}
	// The bundle's records reproduce its signed chain head.
	head, err := audit.VerifyChain(bundle.Records)
	if err != nil {
		t.Fatalf("VerifyChain on bundle records: %v", err)
	}
	if head != bundle.ChainHead {
		t.Errorf("recomputed head %q != signed ChainHead %q", head, bundle.ChainHead)
	}
}
