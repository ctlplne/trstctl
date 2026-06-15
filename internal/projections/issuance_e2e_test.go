package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/server"
)

// TestAssembledServerIssuesCertIntoInventory is the R1.4 disconfirming test for
// DRIFT-1 / B3: against the assembled, authenticated control plane (with a real
// out-of-process signer), creating an identity and transitioning it to "issued"
// drives the running outbox handler to mint a certificate from the assembled CA
// and record it in inventory — the flagship flow now mints a real certificate
// rather than showing a hard-coded success. Before R1.4 the ca.issue outbox
// entry hit a no-op and no certificate ever appeared.
func TestAssembledServerIssuesCertIntoInventory(t *testing.T) {
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

	// certs:issue is the separate privileged-issue authority (RED-004): minting a
	// credential requires it on top of the certs:read/write management scopes, so the
	// requester scope cannot self-issue. This test drives a real issuance, so it mints
	// an authorized-issuer token.
	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue")

	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	issuerID := created(t, ts, token, "/api/v1/issuers",
		`{"kind":"x509_ca","name":"Acme CA","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}`)
	identityID := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"payments.svc","owner_id":"`+ownerID+`","issuer_id":"`+issuerID+`"}`)

	// Before issuance the inventory is empty.
	if items := list(t, ts, token, "/api/v1/certificates"); len(items) != 0 {
		t.Fatalf("inventory should be empty before issuance, got %d", len(items))
	}

	// Transition the identity to "issued": this enqueues the ca.issue outbox entry.
	start := time.Now()
	if code, body := req(t, ts, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, `{"to":"issued"}`); code != http.StatusOK {
		t.Fatalf("transition to issued = %d: %s", code, body)
	}

	// Run the outbox: the real ca.issue handler mints a leaf via the
	// out-of-process signer and records it in inventory (event-sourced).
	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (run outbox): %v", err)
	}
	elapsed := time.Since(start)

	// The flagship result: a real certificate now exists in inventory, issued by
	// the assembled CA, for the identity's subject.
	items := list(t, ts, token, "/api/v1/certificates")
	if len(items) != 1 {
		t.Fatalf("after issuance, inventory has %d certificates, want 1 (the flagship flow must mint one)", len(items))
	}
	cert := items[0]
	if subj, _ := cert["subject"].(string); !strings.Contains(subj, "payments.svc") {
		t.Errorf("issued certificate subject = %q, want it to contain the identity CN payments.svc", subj)
	}
	if iss, _ := cert["issuer"].(string); !strings.Contains(iss, "trustctl Issuing CA") {
		t.Errorf("issued certificate issuer = %q, want the assembled CA (trustctl Issuing CA)", iss)
	}
	if src, _ := cert["source"].(string); src != "issued" {
		t.Errorf("issued certificate source = %q, want \"issued\"", src)
	}
	if fp, _ := cert["fingerprint"].(string); fp == "" {
		t.Error("issued certificate has no fingerprint; it was not really minted")
	}
	t.Logf("R1.4 measured time-to-first-cert (transition→outbox→inventory): %v", elapsed)
}

// created POSTs body to path with the token and returns the created resource's id.
func created(t *testing.T, ts *httptest.Server, token, path, body string) string {
	t.Helper()
	code, resp := req(t, ts, http.MethodPost, path, token, body)
	if code != http.StatusCreated {
		t.Fatalf("POST %s = %d: %s", path, code, resp)
	}
	return decode(t, resp)["id"].(string)
}

// list GETs a collection and returns its items.
func list(t *testing.T, ts *httptest.Server, token, path string) []map[string]any {
	t.Helper()
	code, resp := req(t, ts, http.MethodGet, path, token, "")
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, code, resp)
	}
	raw, _ := decode(t, resp)["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
