package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// newAuditServer builds an API with the audit service wired over a fresh event
// log, and returns the server, the log (to seed events), and the audit service
// (for its verification keys).
func newAuditServer(t *testing.T) (*httptest.Server, *events.Log, *audit.Service) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	sk, err := jose.GenerateRSASigningKey("audit-1")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, sk)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)),
		api.WithAudit(svc), api.WithInsecureHeaderResolver())
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, log, svc
}

func TestAuditAPIQueryAndExport(t *testing.T) {
	srv, log, svc := newAuditServer(t)
	ctx := context.Background()
	for _, ty := range []string{"identity.issued", "identity.deployed"} {
		if _, err := log.Append(ctx, events.Event{Type: ty, TenantID: tenantA, Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: "identity.issued", TenantID: tenantB, Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}

	// An admin queries the audit log; only tenant A's events come back.
	st, _, body := do(t, srv, "GET", "/api/v1/audit/events", reqOpts{tenant: tenantA})
	if st != http.StatusOK {
		t.Fatalf("audit query = %d: %s", st, body)
	}
	if n := int(decode(t, body)["count"].(float64)); n != 2 {
		t.Errorf("audit query count = %d, want 2 (tenant B excluded)", n)
	}

	// Export a signed evidence bundle and verify it against the service's keys.
	st, _, body = do(t, srv, "GET", "/api/v1/audit/export", reqOpts{tenant: tenantA})
	if st != http.StatusOK {
		t.Fatalf("audit export = %d: %s", st, body)
	}
	jws, _ := decode(t, body)["bundle"].(string)
	if jws == "" {
		t.Fatal("export returned no bundle")
	}
	bundle, err := audit.VerifyBundle(jws, svc.VerificationKeys())
	if err != nil {
		t.Fatalf("exported bundle did not verify: %v", err)
	}
	if bundle.TenantID != tenantA || bundle.Count != 2 {
		t.Errorf("bundle = %+v, want 2 records for tenant A", bundle)
	}
}

func TestAuditAPIRBAC(t *testing.T) {
	srv, _, _ := newAuditServer(t)
	// An auditor may read the audit log.
	if st, _, body := do(t, srv, "GET", "/api/v1/audit/events", reqOpts{tenant: tenantA, roles: "auditor"}); st != http.StatusOK {
		t.Fatalf("auditor audit query = %d, want 200: %s", st, body)
	}
	// A viewer (no audit:read) may not.
	st, hdr, body := do(t, srv, "GET", "/api/v1/audit/events", reqOpts{tenant: tenantA, roles: "viewer"})
	if st != http.StatusForbidden {
		t.Fatalf("viewer audit query = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)
}
