// SPDX-License-Identifier: MPL-2.0

package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func newService(t *testing.T, log *events.Log) *audit.Service {
	t.Helper()
	sk, err := jose.GenerateRSASigningKey("audit-key-1")
	if err != nil {
		t.Fatal(err)
	}
	return audit.NewService(log, sk)
}

func TestPublicVerificationJWKSContainsNoPrivateAuditKeyMaterialAUD53(t *testing.T) {
	t.Parallel()
	svc := newService(t, openLog(t))

	raw, err := svc.PublicVerificationJWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jose.ParseJWKSet(raw)
	if err != nil {
		t.Fatalf("parse served public JWK set: %v", err)
	}
	if keys == nil || !strings.Contains(string(raw), `"kid":"audit-key-1"`) {
		t.Fatalf("public JWK set = %s, want the audit verification key", raw)
	}
	for _, privateField := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(raw), privateField+":") {
			t.Fatalf("public JWK set contains private RSA field %s: %s", privateField, raw)
		}
	}

	unsigned := audit.NewService(openLog(t), nil)
	if _, err := unsigned.PublicVerificationJWKS(); !errors.Is(err, audit.ErrMissingSigner) {
		t.Fatalf("unsigned service error = %v, want ErrMissingSigner", err)
	}
}

func appendEvent(t *testing.T, log *events.Log, tenantID, typ string) uint64 {
	t.Helper()
	ev, err := log.Append(context.Background(), events.Event{Type: typ, TenantID: tenantID, Data: []byte(`{}`)})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return ev.Sequence
}

// TestSearchFiltersByTenantAndType is the acceptance: audit queries return the
// correct slice of the log, tenant-scoped (AN-1) and type-filtered.
func TestSearchFiltersByTenantAndType(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	appendEvent(t, log, tenantA, "identity.issued")
	appendEvent(t, log, tenantA, "identity.deployed")
	appendEvent(t, log, tenantB, "identity.issued")

	svc := newService(t, log)

	recs, err := svc.Search(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("tenant A search returned %d, want 2 (tenant B must be excluded)", len(recs))
	}
	for _, r := range recs {
		if r.TenantID != tenantA {
			t.Errorf("record leaked tenant %s", r.TenantID)
		}
	}

	recs, err = svc.Search(ctx, audit.Query{TenantID: tenantA, Types: []string{"identity.deployed"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Type != "identity.deployed" {
		t.Fatalf("type filter = %v, want one identity.deployed", recs)
	}
}

func TestSearchFailsClosedBeforeFilteringUnsafeLegacySchedulerHistory(t *testing.T) {
	log := openLog(t)
	secret := "postgres://audit-user:credential@provider.internal/db"
	_, err := log.Append(context.Background(), events.Event{
		Type: schedulerhistory.EventType, TenantID: tenantA,
		SchemaVersion: schedulerhistory.LegacySchemaVersion,
		Data:          []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secret + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	records, err := newService(t, log).Search(context.Background(), audit.Query{
		TenantID: tenantA, Types: []string{"identity.issued"},
	})
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("Search error = %v, want sanitation-required", err)
	}
	if records != nil {
		t.Fatalf("Search returned partial records: %#v", records)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("Search error disclosed unsafe scheduler data")
	}
}

type fixedAuditCheckpoint struct{ checkpoint audit.Checkpoint }

func (s fixedAuditCheckpoint) LatestAuditCheckpoint(context.Context, string) (audit.Checkpoint, bool, error) {
	return s.checkpoint, true, nil
}

func TestSearchPreflightsUnsafeRetainedPrefixBelowCheckpoint(t *testing.T) {
	log := openLog(t)
	secret := "credential-hidden-below-retention-floor"
	unsafe, err := log.Append(context.Background(), events.Event{
		Type: schedulerhistory.EventType, TenantID: tenantA, SchemaVersion: 1,
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secret + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	appendEvent(t, log, tenantA, "identity.issued")
	key, err := jose.GenerateRSASigningKey("audit-prefix-preflight")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(fixedAuditCheckpoint{checkpoint: audit.Checkpoint{
		TenantID: tenantA, BoundarySeq: unsafe.Sequence, BoundaryHash: "sealed-prefix-head", RecordCount: 1,
	}}))
	records, err := svc.Search(context.Background(), audit.Query{
		TenantID: tenantA, Types: []string{"identity.issued"}, Limit: 1,
	})
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) || records != nil {
		t.Fatalf("Search below checkpoint = (%#v, %v), want fixed sanitation failure", records, err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("retained-prefix preflight error disclosed unsafe data")
	}
}

// TestTenantAuditUsesTenantLocalSequence is the TENANT-003 regression: a tenant's
// public audit sequence is a tenant-local ordinal, not the global JetStream
// sequence. Foreign-tenant activity may be interleaved in the stream, but it must
// not show up as gaps in another tenant's audit trail.
func TestTenantAuditUsesTenantLocalSequence(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	appendEvent(t, log, tenantA, "identity.requested")
	foreignGlobalSeq := appendEvent(t, log, tenantB, "identity.issued")
	appendEvent(t, log, tenantA, "identity.issued")

	svc := newService(t, log)
	recs, err := svc.Search(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("tenant A records = %d, want 2", len(recs))
	}
	if got := []uint64{recs[0].Sequence, recs[1].Sequence}; got[0] != 1 || got[1] != 2 {
		t.Fatalf("tenant-local sequences = %v, want [1 2] with foreign global seq %d hidden", got, foreignGlobalSeq)
	}

	asOf, err := svc.Search(ctx, audit.Query{TenantID: tenantA, AsOfSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(asOf) != 1 || asOf[0].Type != "identity.requested" {
		t.Fatalf("tenant-local as_of=1 returned %#v, want only the first tenant-A event", asOf)
	}
}

// TestPointInTimeQuery is the acceptance: a point-in-time query returns the log
// as of a sequence.
func TestPointInTimeQuery(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	var seqs []uint64
	for i := 0; i < 4; i++ {
		seqs = append(seqs, appendEvent(t, log, tenantA, "x"))
	}
	svc := newService(t, log)

	recs, err := svc.Search(ctx, audit.Query{TenantID: tenantA, AsOfSequence: seqs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("point-in-time (as of seq %d) returned %d, want 2", seqs[1], len(recs))
	}
	for _, r := range recs {
		if r.Sequence > seqs[1] {
			t.Errorf("record seq %d is after the as-of point %d", r.Sequence, seqs[1])
		}
	}
}

// TestEvidenceBundleVerifies is kept for the docs governance guard that protects
// the existing signed evidence-bundle regression.
func TestEvidenceBundleVerifies(t *testing.T) {
	testVerifyBundle(t)
}

// TestVerifyBundle is the PKIGOV-005 acceptance: an exported evidence bundle
// verifies its signature and hash chain, and a tampered one does not.
func TestVerifyBundle(t *testing.T) {
	testVerifyBundle(t)
}

func TestVerifyBundleRejectsSameKeyWrongArtifactDomainAUD120(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(audit.Bundle{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	wrongKind, err := key.SignArtifact(jose.ArtifactDoctorReceipt, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.VerifyBundle(wrongKind, key.JWKS()); err == nil {
		t.Fatal("doctor receipt with a bundle-shaped body verified as an audit export")
	}
}

func testVerifyBundle(t *testing.T) {
	t.Helper()
	log := openLog(t)
	ctx := context.Background()
	appendEvent(t, log, tenantA, "identity.issued")
	appendEvent(t, log, tenantA, "identity.revoked")
	svc := newService(t, log)

	jws, err := svc.Export(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	bundle, err := audit.VerifyBundle(jws, svc.VerificationKeys())
	if err != nil {
		t.Fatalf("a valid bundle must verify: %v", err)
	}
	if bundle.TenantID != tenantA || bundle.Count != 2 || len(bundle.Records) != 2 {
		t.Errorf("bundle = %+v, want 2 records for tenant A", bundle)
	}

	parts := strings.Split(jws, ".")
	parts[1] = "ZXZpbA" + parts[1][6:] // corrupt the payload segment
	if _, err := audit.VerifyBundle(strings.Join(parts, "."), svc.VerificationKeys()); err == nil {
		t.Error("a tampered evidence bundle must not verify")
	}
}

func TestExportRequiresSigner(t *testing.T) {
	log := openLog(t)
	appendEvent(t, log, tenantA, "identity.issued")
	svc := audit.NewService(log, nil)

	if _, err := svc.Export(context.Background(), audit.Query{TenantID: tenantA}); !errors.Is(err, audit.ErrMissingSigner) {
		t.Fatalf("Export without signer error = %v, want audit.ErrMissingSigner", err)
	}
	if keys := svc.VerificationKeys(); keys != nil {
		t.Fatalf("VerificationKeys without signer = %#v, want nil", keys)
	}
}

// TestSearchFailsClosedOnEmptyTenant is the TENANT-003 acceptance: an audit query
// with an empty TenantID is rejected (fail closed) rather than returning the full
// cross-tenant log. It fails on the pre-fix tree (Search returned every tenant's
// records when TenantID was "") and passes once Search rejects the empty scope.
// Export and VerifyChain route through Search, so they fail closed too.
func TestSearchFailsClosedOnEmptyTenant(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	// Seed two tenants so a fail-open would visibly leak across them.
	appendEvent(t, log, tenantA, "identity.issued")
	appendEvent(t, log, tenantB, "identity.issued")
	svc := newService(t, log)

	recs, err := svc.Search(ctx, audit.Query{TenantID: ""})
	if err == nil {
		t.Fatalf("Search with empty TenantID returned %d records instead of failing closed (cross-tenant leak)", len(recs))
	}
	if !errors.Is(err, audit.ErrMissingTenant) {
		t.Errorf("Search empty-tenant error = %v, want audit.ErrMissingTenant", err)
	}
	if recs != nil {
		t.Errorf("Search returned %d records alongside the error; must return none", len(recs))
	}

	// Export must also fail closed on the empty scope (it runs Search).
	if _, err := svc.Export(ctx, audit.Query{TenantID: ""}); !errors.Is(err, audit.ErrMissingTenant) {
		t.Errorf("Export empty-tenant error = %v, want audit.ErrMissingTenant", err)
	}
	// VerifyChain must also fail closed on the empty scope.
	if _, err := svc.VerifyChain(ctx, ""); !errors.Is(err, audit.ErrMissingTenant) {
		t.Errorf("VerifyChain empty-tenant error = %v, want audit.ErrMissingTenant", err)
	}

	// Sanity: a scoped query still works (the fix didn't break the normal path).
	if got, err := svc.Search(ctx, audit.Query{TenantID: tenantA}); err != nil || len(got) != 1 {
		t.Errorf("scoped search after fix: got %d recs, err %v; want 1, nil", len(got), err)
	}
}
