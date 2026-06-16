package projections_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func tptr(tm time.Time) *time.Time { return &tm }

func sampleCert(tenant, fp, subject string, notAfter time.Time) store.Certificate {
	return store.Certificate{
		TenantID: tenant, Subject: subject, SANs: []string{subject},
		Issuer: "CN=Acme Root", Serial: "01", Fingerprint: fp, KeyAlgorithm: "ECDSA",
		NotBefore: tptr(notAfter.Add(-24 * time.Hour)), NotAfter: tptr(notAfter),
		DeploymentLocation: "edge-lb", Source: "import",
	}
}

// TestCertificateStoreAndQuery: a certificate stores and loads with full
// metadata, and re-ingesting the same fingerprint updates rather than duplicates.
func TestCertificateStoreAndQuery(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	c, err := s.UpsertCertificate(ctx, sampleCert(tenantA, "fp-aaa", "CN=svc.acme", time.Now().Add(720*time.Hour)))
	if err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	if c.ID == "" {
		t.Fatal("no id returned")
	}
	got, err := s.GetCertificate(ctx, tenantA, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "CN=svc.acme" || got.Fingerprint != "fp-aaa" || got.DeploymentLocation != "edge-lb" ||
		got.KeyAlgorithm != "ECDSA" || got.NotAfter == nil || len(got.SANs) != 1 {
		t.Errorf("certificate round-trip = %+v", got)
	}

	c2, err := s.UpsertCertificate(ctx, sampleCert(tenantA, "fp-aaa", "CN=svc.acme.v2", time.Now().Add(720*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if c2.ID != c.ID {
		t.Errorf("re-ingesting fingerprint fp-aaa created a new row (%s != %s)", c2.ID, c.ID)
	}
	list, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Subject != "CN=svc.acme.v2" {
		t.Errorf("inventory = %v, want one updated cert", list)
	}
}

// TestCertificateInventoryTenantScopedAndPaginated is the acceptance: inventory
// queries are tenant-scoped and paginated.
func TestCertificateInventoryTenantScopedAndPaginated(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.UpsertCertificate(ctx, sampleCert(tenantA, fmt.Sprintf("fp-a-%d", i), "CN=a", time.Now().Add(720*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpsertCertificate(ctx, sampleCert(tenantB, "fp-b", "CN=b", time.Now().Add(720*time.Hour))); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	after := store.ZeroUUID
	for pages := 0; pages < 10; pages++ {
		page, err := s.ListCertificatesPage(ctx, tenantA, after, nil, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range page {
			if c.TenantID != tenantA {
				t.Errorf("tenant A page leaked tenant %s", c.TenantID)
			}
			seen[c.ID] = true
		}
		if len(page) < 2 {
			break
		}
		after = page[len(page)-1].ID
	}
	if len(seen) != 5 {
		t.Errorf("paginated inventory yielded %d certs, want 5", len(seen))
	}
	b, err := s.ListCertificatesPage(ctx, tenantB, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 {
		t.Errorf("tenant B sees %d certs, want only its own 1", len(b))
	}
}

func TestCertificateExpiringFilter(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := s.UpsertCertificate(ctx, sampleCert(tenantA, "soon", "CN=soon", now.Add(120*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertCertificate(ctx, sampleCert(tenantA, "later", "CN=later", now.Add(2160*time.Hour))); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(720 * time.Hour) // 30 days
	page, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 100, &cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].Fingerprint != "soon" {
		t.Errorf("expiring-before filter = %v, want only the soon-expiring cert", page)
	}
}

// TestCertificateAPIIngestAndQuery exercises the ingest and query paths end to
// end: POST a PEM certificate (parsed into metadata), then list and get it.
func TestCertificateAPIIngestAndQuery(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)), api.WithInsecureHeaderResolver())
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)

	ca, err := mtls.NewCA("root")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCertificate([]string{"svc.acme.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	st, _, body := do(t, srv, "POST", "/api/v1/certificates", reqOpts{
		tenant: tenantA, idem: "c1",
		body: map[string]any{"pem": string(pemBytes), "deployment_location": "edge"},
	})
	if st != http.StatusCreated {
		t.Fatalf("ingest = %d: %s", st, body)
	}
	m := decode(t, body)
	id, _ := m["id"].(string)
	if id == "" || m["subject"] == "" {
		t.Fatalf("ingested cert missing metadata: %s", body)
	}
	sans, _ := m["sans"].([]any)
	found := false
	for _, s := range sans {
		if s == "svc.acme.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("ingested SANs = %v, want svc.acme.test parsed from the cert", sans)
	}

	_, _, lb := do(t, srv, "GET", "/api/v1/certificates", reqOpts{tenant: tenantA})
	if items, _ := decode(t, lb)["items"].([]any); len(items) != 1 {
		t.Errorf("inventory list = %d items, want 1", len(items))
	}
	if st, _, _ := do(t, srv, "GET", "/api/v1/certificates/"+id, reqOpts{tenant: tenantA}); st != http.StatusOK {
		t.Errorf("get certificate = %d, want 200", st)
	}
}
