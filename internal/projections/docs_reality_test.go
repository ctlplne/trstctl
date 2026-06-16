package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/server"
)

// TestDocsFirstCertFlowReallyIssues is the R2.6 behavioral docs-reality test: it
// makes the "first certificate" claim in getting-started.md *behavioral* rather
// than keyword-checked. It reads the documented flow, then actually drives it
// against the assembled control plane and asserts a real certificate lands in
// inventory. This is the test that would have caught DRIFT-1 (the documented
// "issue your first cert" flow that recorded an identity and showed a hard-coded
// success screen, issuing nothing): if the flow were wired to a no-op, the
// inventory would stay empty and this test fails.
func TestDocsFirstCertFlowReallyIssues(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}

	// The doc must promise a real certificate reachable in inventory — not a
	// success screen. (The behavioral assertion below proves the promise.)
	doc, err := os.ReadFile("../../docs/getting-started.md")
	if err != nil {
		t.Fatalf("read getting-started.md: %v", err)
	}
	lower := strings.ToLower(string(doc))
	if !strings.Contains(lower, "first cert") {
		t.Fatal("getting-started.md should document reaching a first certificate")
	}
	if !strings.Contains(lower, "inventory") {
		t.Error("getting-started.md should state the issued certificate appears in inventory (the verifiable outcome)")
	}

	// Now prove the documented flow behaviorally: create identity -> transition to
	// issued -> the real outbox handler mints a leaf and records it in inventory.
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

	// certs:issue is the separate privileged-issue authority (RED-004) the issuance
	// transition requires on top of the management scopes.
	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	issuerID := created(t, ts, token, "/api/v1/issuers",
		`{"kind":"x509_ca","name":"Acme CA","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"payments.svc","owner_id":"`+ownerID+`","issuer_id":"`+issuerID+`"}`)

	if items := list(t, ts, token, "/api/v1/certificates"); len(items) != 0 {
		t.Fatalf("inventory should be empty before issuance, got %d", len(items))
	}
	if code, body := req(t, ts, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, `{"to":"issued"}`); code != http.StatusOK {
		t.Fatalf("transition to issued = %d: %s", code, body)
	}
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (run outbox): %v", err)
	}

	items := list(t, ts, token, "/api/v1/certificates")
	if len(items) != 1 {
		t.Fatalf("the documented first-cert flow put %d certificates in inventory, want 1 (the doc's promise must be real, not a no-op)", len(items))
	}
	if fp, _ := items[0]["fingerprint"].(string); fp == "" {
		t.Error("the issued certificate has no fingerprint; the documented flow did not really mint one")
	}
}
