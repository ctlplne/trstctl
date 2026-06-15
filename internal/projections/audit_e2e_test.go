package projections_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/audit"
	"trustctl.io/trustctl/internal/crypto/jose"
	"trustctl.io/trustctl/internal/server"
)

// TestAssembledServerAuditTrailAndExport is the R2.1 disconfirming test for B5:
// against the assembled, authenticated control plane with the audit subsystem
// wired, the audit query/export endpoints return real data (not HTTP 500), the
// trail reconstructs "who did what, when, under what authorization" for an admin
// action, an issuance, and a revocation, and a signed evidence bundle verifies
// against the service's keys with a tamper-anchoring chain head.
func TestAssembledServerAuditTrailAndExport(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	// The audit export key is injected (a real deployment loads it from disk so it
	// persists across restarts; see TestExportPersistentKeyVerifiesAcrossRestart).
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov, AuditSigningKey: auditKey})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// certs:issue is the separate privileged-issue authority (RED-004) the issuance
	// transition requires on top of the management scopes.
	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue", "audit:read")

	// Admin action, then issuance and revocation of an identity.
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	issuerID := created(t, ts, token, "/api/v1/issuers",
		`{"kind":"x509_ca","name":"Acme CA","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"payments.svc","owner_id":"`+ownerID+`","issuer_id":"`+issuerID+`"}`)
	// Distinct idempotency keys: both transitions hit the same path, so a shared
	// key would make the second a no-op replay of the first.
	if code, body := postIdem(t, ts, "/api/v1/identities/"+identityID+"/transitions", token, `{"to":"issued"}`, "issue-1"); code != http.StatusOK {
		t.Fatalf("transition to issued = %d: %s", code, body)
	}
	if code, body := postIdem(t, ts, "/api/v1/identities/"+identityID+"/transitions", token, `{"to":"revoked"}`, "revoke-1"); code != http.StatusOK {
		t.Fatalf("transition to revoked = %d: %s", code, body)
	}

	// 1) The audit query endpoint returns real data (not 500), and the trail
	//    attributes each mutation to the caller and its authorization.
	code, body := req(t, ts, http.MethodGet, "/api/v1/audit/events", token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit/events = %d (want 200 — audit must be wired into the serving path): %s", code, body)
	}
	var listing struct {
		Events []audit.Record `json:"events"`
		Count  int            `json:"count"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	for _, want := range []string{"owner.created", "identity.issued", "identity.revoked"} {
		rec := findRecord(listing.Events, want)
		if rec == nil {
			t.Fatalf("audit trail is missing a %q event (completeness)", want)
		}
		if rec.Actor == nil || rec.Actor.Subject != "ci-bot" {
			t.Errorf("%s actor = %+v, want subject ci-bot (attribution)", want, rec.Actor)
		}
		if rec.Actor != nil && !containsString(rec.Actor.Roles, "api-token") {
			t.Errorf("%s actor roles = %v, want to include api-token (authorization)", want, rec.Actor.Roles)
		}
		if rec.Time.IsZero() {
			t.Errorf("%s record has no timestamp (the 'when')", want)
		}
	}

	// 2) The export endpoint returns a signed bundle that verifies against the
	//    service's keys, with a chain head anchoring the records.
	code, body = req(t, ts, http.MethodGet, "/api/v1/audit/export", token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit/export = %d (want 200): %s", code, body)
	}
	var exp struct {
		Format string `json:"format"`
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(body, &exp); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	bundle, err := audit.VerifyBundle(exp.Bundle, auditKey.JWKS())
	if err != nil {
		t.Fatalf("exported bundle does not verify against the audit key: %v", err)
	}
	if bundle.ChainHead == "" {
		t.Error("exported bundle has no chain head (no tamper-evidence anchor)")
	}
	if findRecord(bundle.Records, "identity.revoked") == nil {
		t.Error("exported bundle is missing the revocation event")
	}
	head, err := audit.VerifyChain(bundle.Records)
	if err != nil {
		t.Fatalf("VerifyChain on exported records: %v", err)
	}
	if head != bundle.ChainHead {
		t.Errorf("recomputed chain head %q != signed ChainHead %q", head, bundle.ChainHead)
	}
}

// postIdem POSTs with an explicit Idempotency-Key, so repeated calls to the same
// path (e.g. successive lifecycle transitions) are not collapsed into one.
func postIdem(t *testing.T, ts *httptest.Server, path, token, body, key string) (int, []byte) {
	t.Helper()
	httpReq, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Idempotency-Key", key)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func findRecord(recs []audit.Record, typ string) *audit.Record {
	for i := range recs {
		if recs[i].Type == typ {
			return &recs[i]
		}
	}
	return nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
