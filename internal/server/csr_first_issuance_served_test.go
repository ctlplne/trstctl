// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CSR-first issuance, proven on the assembled binary (epic B1).
//
// The direct identity API had no CSR input at all: transitioning an identity to
// issued made the control plane generate the subject key, sign for it, and hand
// the key onward. That is a custody claim nobody wants to defend, and it is why
// the served surface could not say private keys never reach the control plane.
//
// These assert the two halves that matter: a caller who brings their own request
// gets a certificate for the key they made, with no key material anywhere on the
// control plane's side; and a caller who does not still works, but the legacy
// path says so in the event log rather than passing silently.

// subjectCSR builds a caller-side keypair and PKCS#10 request the way a real
// requester would — the key never leaves this function, which is the point.
func subjectCSR(t *testing.T, commonName string, dnsNames ...string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate subject key: %v", err)
	}
	defer key.Destroy()
	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatalf("build subject CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func tenantEventTypes(t *testing.T, log *events.Log, tenantID string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	if err := log.Replay(context.Background(), 0, func(ev events.Event) error {
		if ev.TenantID == tenantID {
			counts[ev.Type]++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return counts
}

func TestServedIssuanceSignsACallerSuppliedCSRAndHoldsNoKey(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "payments", "email": "payments@example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d: %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "csr-first.example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	csr := subjectCSR(t, "csr-first.example.test")
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "caller-generated key", "subject_csr_pem": string(csr),
	})
	if status != http.StatusOK {
		t.Fatalf("issue from CSR = %d: %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain issuance: %v", err)
	}

	// The certificate exists and carries the name the caller asked for.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates = %d: %s", status, body)
	}
	if !bytes.Contains(body, []byte("csr-first.example.test")) {
		t.Fatalf("no certificate was issued for the CSR's subject: %s", body)
	}

	// And no key material exists anywhere the control plane wrote. This is the
	// whole claim: we signed what the caller made and never held a key.
	//
	// Matched on PEM PREAMBLES, not on the words "private key". The earlier
	// form scanned for the phrase, which fired the moment B5's custody summary
	// started being served — that summary reports that this issuance did not
	// receive the requester's private key. A scanner that cannot
	// tell key material from prose describing its absence flags the fix as the
	// bug.
	for _, marker := range [][]byte{
		[]byte("-----BEGIN PRIVATE KEY-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----"),
		[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		[]byte(`"key_pem"`),
	} {
		if bytes.Contains(body, marker) {
			t.Fatalf("served certificate list carries private key material (%s): %s", marker, body)
		}
	}
	counts := tenantEventTypes(t, h.log, h.tenant)
	if counts["issuance.server_side_keygen"] != 0 {
		t.Fatalf("a CSR-first issuance recorded %d server-side keygen deprecations, want 0",
			counts["issuance.server_side_keygen"])
	}
}

// TestServedIssuanceWithoutACSRStillWorksAndRecordsTheDeprecation keeps the
// legacy path working for one release train while making it visible. An operator
// has to be able to find which of their flows still hand key generation to the
// control plane before that path is removed under them.
func TestServedIssuanceWithoutACSRStillWorksAndRecordsTheDeprecation(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "legacy"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "legacy.example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "legacy server-side keygen",
	})
	if status != http.StatusOK {
		t.Fatalf("legacy issuance = %d: %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain issuance: %v", err)
	}

	counts := tenantEventTypes(t, h.log, h.tenant)
	if counts["issuance.server_side_keygen"] == 0 {
		t.Fatal("the deprecated server-side keygen path ran silently; it must record issuance.server_side_keygen so an operator can find it")
	}
}

// TestServedIssuanceRejectsAMalformedCSRAtTheEdge keeps a caller mistake in the
// response to the request that caused it, rather than surfacing minutes later as
// a failed outbox delivery nobody is watching.
func TestServedIssuanceRejectsAMalformedCSRAtTheEdge(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "bad-csr"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "bad.example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	for name, csr := range map[string]string{
		"not PEM at all":        "this is not a certificate request",
		"wrong PEM block type":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})),
		"unparseable PKCS#10":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x00}})),
		"empty request payload": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST"})),
	} {
		t.Run(name, func(t *testing.T) {
			status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
				"to": "issued", "reason": "bad csr", "subject_csr_pem": csr,
			})
			if status != http.StatusBadRequest {
				t.Fatalf("malformed CSR (%s) = %d, want 400: %s", name, status, body)
			}
			if !strings.Contains(strings.ToLower(string(body)), "subject_csr_pem") {
				t.Fatalf("the problem document does not name the offending field: %s", body)
			}
		})
	}
}

// TestServedIssuanceRejectsACSROnANonIssuingTransition stops a CSR being
// accepted somewhere it would be silently ignored — an accepted-but-inert field
// is how a caller ends up believing their key was used when it was not.
func TestServedIssuanceRejectsACSROnANonIssuingTransition(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "wrong-state"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "wrong-state.example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "revoked", "reason": "unspecified", "subject_csr_pem": string(subjectCSR(t, "wrong-state.example.test")),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("CSR on a revoke transition = %d, want 400: %s", status, body)
	}
}
