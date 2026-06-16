package projections_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// transition POSTs a lifecycle transition to "to" with an idempotency key unique
// to (identity, target state). The shared req helper keys its idempotency header
// on method+path, so two transitions on the same identity (issue then revoke)
// would otherwise collide and the second would replay the first's cached result
// instead of executing — distinct keys keep them independent (AN-5).
func transition(t *testing.T, ts *httptest.Server, token, identityID, to string) {
	t.Helper()
	r := strings.NewReader(`{"to":"` + to + `"}`)
	httpReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities/"+identityID+"/transitions", r)
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Idempotency-Key", "rev-e2e-"+identityID+"-"+to)
	resp, err := ts.Client().Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transition to %q = %d: %s", to, resp.StatusCode, b)
	}
}

// countRevokedIssuedCerts counts the rows in ca_issued_certs (the OCSP/CRL
// responder's backing table) that are marked revoked for the tenant — the
// CORRECT-001 / RED-001 probe asserts this is >= 1 after a served revoke. The
// query runs under the tenant's RLS context (AN-1).
func countRevokedIssuedCerts(t *testing.T, st *store.Store, tenantID string) int {
	t.Helper()
	var n int
	if err := st.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT count(*) FROM ca_issued_certs
			  WHERE tenant_id = $1 AND revoked_at IS NOT NULL`, tenantID).Scan(&n)
	}); err != nil {
		t.Fatalf("count revoked ca_issued_certs: %v", err)
	}
	return n
}

// TestServedRevokeInvalidatesCert is the CORRECT-001 / RED-001 disconfirming
// test for the headline blocker "served revocation is a no-op: a revoked
// certificate still validates".
//
// Against the assembled, authenticated control plane (real out-of-process
// signer), it drives a full served issue -> revoke -> drain and asserts that the
// revoked certificate STOPS VALIDATING: the inventory read model reports the
// cert "revoked" (was "active"), and the responder's backing table
// ca_issued_certs records a revoked row for its serial (so OCSP/CRL reflect it).
//
// Before the fix the served outbox handler silently ACKs revocation.publish, so
// the cert row keeps status "active" and ca_issued_certs has 0 revoked rows —
// this test fails. After the fix the served revoke path flips both.
func TestServedRevokeInvalidatesCert(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue")

	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	issuerID := created(t, ts, token, "/api/v1/issuers",
		`{"kind":"x509_ca","name":"Acme CA","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"payments.svc","owner_id":"`+ownerID+`","issuer_id":"`+issuerID+`"}`)

	// Issue: transition to "issued" and drain so the real ca.issue handler mints
	// a leaf via the signer and records it in inventory.
	transition(t, ts, token, identityID, "issued")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (issue): %v", err)
	}

	items := list(t, ts, token, "/api/v1/certificates")
	if len(items) != 1 {
		t.Fatalf("after issuance, inventory has %d certificates, want 1", len(items))
	}
	cert := items[0]
	serial, _ := cert["serial"].(string)
	if serial == "" {
		t.Fatal("issued certificate has no serial; it was not really minted")
	}
	if status, _ := cert["status"].(string); status != "active" {
		t.Fatalf("freshly issued certificate status = %q, want \"active\"", status)
	}
	// The freshly issued cert must already be known to the responder's table so
	// OCSP answers good vs. unknown (the bridge that was missing).
	if n := countRevokedIssuedCerts(t, st, tenantA); n != 0 {
		t.Fatalf("ca_issued_certs revoked rows before revoke = %d, want 0", n)
	}

	// Revoke: transition issued -> revoked, then drain so the served revocation
	// handler runs.
	transition(t, ts, token, identityID, "revoked")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (revoke): %v", err)
	}

	// ASSERT 1 — the inventory read model now reports the cert revoked: the
	// served binary's status surface reflects the revocation (it stops being a
	// trusted/active cert). Pre-fix this is still "active".
	items = list(t, ts, token, "/api/v1/certificates")
	if len(items) != 1 {
		t.Fatalf("after revoke, inventory has %d certificates, want 1", len(items))
	}
	if status, _ := items[0]["status"].(string); status != "revoked" {
		t.Fatalf("after served revoke, certificate status = %q, want \"revoked\" "+
			"(a revoked cert must stop validating; this is the CORRECT-001 blocker)", status)
	}

	// ASSERT 2 — the responder's backing table records the serial revoked, so a
	// relying party's OCSP/CRL query will reflect it (CORRECT-001 / RED-001
	// literal acceptance: ca_issued_certs revoked rows >= 1). Pre-fix: 0.
	if n := countRevokedIssuedCerts(t, st, tenantA); n < 1 {
		t.Fatalf("after served revoke, ca_issued_certs revoked rows = %d, want >= 1 "+
			"(the revocation.publish outbox entry was silently dropped — served revoke is a no-op)", n)
	}

	// ASSERT 3 — the recorded serial is the leaf's serial (the revocation points
	// at the certificate that was actually minted, not a stray row).
	rec, found, err := st.LookupIssuedCert(context.Background(), tenantA, server.IssuingCAID(), serial)
	if err != nil {
		t.Fatalf("LookupIssuedCert: %v", err)
	}
	if !found || !rec.Revoked() {
		t.Fatalf("issued-cert record for serial %s: found=%v revoked=%v, want found & revoked", serial, found, rec.Revoked())
	}
}

// TestServedRevokeIsIdempotent asserts AN-5 on the served revoke path:
// redelivering the revocation.publish outbox entry (a retry) does not produce a
// second revocation or change the recorded revocation time. The first revocation
// wins.
func TestServedRevokeIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"idem.svc","owner_id":"`+ownerID+`"}`)

	transition(t, ts, token, identityID, "issued")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (issue): %v", err)
	}
	serial, _ := list(t, ts, token, "/api/v1/certificates")[0]["serial"].(string)

	transition(t, ts, token, identityID, "revoked")
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (revoke): %v", err)
	}

	first, _, err := st.LookupIssuedCert(context.Background(), tenantA, server.IssuingCAID(), serial)
	if err != nil {
		t.Fatalf("LookupIssuedCert (1): %v", err)
	}
	if first.RevokedAt == nil {
		t.Fatal("serial not revoked after served revoke")
	}

	// Simulate an at-least-once redelivery of the revocation to the responder
	// table with a LATER timestamp: the revocation-of-record must not move and
	// must not duplicate (the store keeps the first revocation time — AN-5). This
	// is what guarantees a retried revoke does not rewrite the revocation moment a
	// CRL/OCSP consumer already observed.
	later := first.RevokedAt.Add(time.Hour)
	if err := st.RevokeIssuedCert(context.Background(), tenantA, server.IssuingCAID(), serial, 0, later); err != nil {
		t.Fatalf("RevokeIssuedCert (retry): %v", err)
	}
	second, _, err := st.LookupIssuedCert(context.Background(), tenantA, server.IssuingCAID(), serial)
	if err != nil {
		t.Fatalf("LookupIssuedCert (2): %v", err)
	}
	if second.RevokedAt == nil || !second.RevokedAt.Equal(*first.RevokedAt) {
		t.Fatalf("revocation time changed on retry: %v -> %v (AN-5 idempotency violated)", first.RevokedAt, second.RevokedAt)
	}
	if n := countRevokedIssuedCerts(t, st, tenantA); n != 1 {
		t.Fatalf("revoked ca_issued_certs rows after retry = %d, want exactly 1 (no duplicate revocation)", n)
	}
}
