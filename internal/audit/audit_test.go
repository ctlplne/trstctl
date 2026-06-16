package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
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

// TestEvidenceBundleVerifies is the acceptance: an exported evidence bundle
// verifies its signature, and a tampered one does not.
func TestEvidenceBundleVerifies(t *testing.T) {
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
