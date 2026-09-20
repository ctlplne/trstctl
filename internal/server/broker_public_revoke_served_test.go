// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// BROKER-REVOKE-001: the installed certificate endpoint accepted a real broker
// certificate ID but looked for it in identities. HTTP 200 revoked nothing.
// Exercise the public action and the actual signed CRL, not an internal revoke.
func TestServedBrokerPublicRevocationTargetsCertificateAndPublishesCAState(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "public-revoke-target", body, http.StatusCreated)
	other := servedBrokerIssue(t, h, owner, "public-revoke-unselected", body, http.StatusCreated)
	before, err := h.store.GetBrokerCertificate(t.Context(), h.tenant, issued.CertificateID, time.Now().UTC())
	if err != nil || before.Issuance == nil {
		t.Fatalf("durable baseline missing: %v", err)
	}
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, cert.Serial, "good")
	caID, err := h.store.ExactIssuedCertificateAuthority(t.Context(), h.tenant, cert.Serial)
	if err != nil || caID != h.srv.agentBroker.caID {
		t.Fatalf("fixture does not have one actual issuing authority: %q %v", caID, err)
	}
	const route = "/api/v1/certificates/bulk-revoke"
	request := map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation"}
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, _ := secretsReqKey(t, h, http.MethodPost, route, reader, "public-revoke-reader", request)
	if status != http.StatusForbidden {
		t.Fatalf("read-only principal may not revoke: HTTP %d", status)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, route, owner, "public-revoke-exact", request)
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalMatched != 1 || result.TotalRevoked != 1 || result.TotalFailed != 0 {
		t.Fatalf("public certificate revocation: HTTP %d result=%s; want exactly one revoked certificate", status, raw)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, route, owner, "public-revoke-exact", request)
	if status != http.StatusOK || string(replay) != string(raw) {
		t.Fatal("same-key revocation must return the original result")
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, route, owner, "public-revoke-exact", map[string]any{
		"certificate_ids": []string{other.CertificateID}, "reason": "cessationOfOperation",
	})
	if status != http.StatusConflict {
		t.Fatalf("changed certificate under the same key: HTTP %d, want 409", status)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := h.store.GetBrokerCertificate(t.Context(), h.tenant, issued.CertificateID, time.Now().UTC())
	if err != nil || after.State != "revoked" || !reflect.DeepEqual(after.Issuance, before.Issuance) {
		t.Fatalf("revocation must retain original broker facts: state=%s error=%v", after.State, err)
	}
	untouched, err := h.store.GetCertificate(t.Context(), h.tenant, other.CertificateID)
	if err != nil || untouched.Status != "active" {
		t.Fatal("revoking one certificate must not revoke its same-owner sibling")
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, caID, cert.Serial)
	if err != nil || !found || !ledger.Revoked() || ledger.ReasonCode != crypto.CRLReasonCode(crypto.RevocationReasonCessationOfOperation) {
		t.Fatalf("actual CA ledger did not record exact revocation: %+v found=%v error=%v", ledger, found, err)
	}
	status, crlDER := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("public CRL unavailable: HTTP %d", status)
	}
	crl, err := crypto.ParseCRL(crlDER, h.srv.agentBroker.caCertDER)
	if err != nil || !containsSerial(crl.RevokedSerials, cert.Serial) || containsSerial(crl.RevokedSerials, untouched.Serial) {
		t.Fatalf("signed public CRL does not contain only the selected serial: %v error=%v", crl.RevokedSerials, err)
	}
	assertPublicCertificateOCSP(t, h, cert.Serial, "revoked")
	assertPublicCertificateOCSP(t, h, untouched.Serial, "good")
}

func assertPublicCertificateOCSP(t *testing.T, h *servedHarness, serial, want string) {
	t.Helper()
	requestDER, err := crypto.BuildOCSPRequestForSerial(h.srv.agentBroker.caCertDER, serial)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.ts.URL+"/ocsp/"+h.tenant, bytes.NewReader(requestDER))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/ocsp-request")
	response, err := h.ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	der, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("public OCSP request failed: HTTP %d error=%v", response.StatusCode, err)
	}
	status, err := crypto.ParseOCSPResponse(der, h.srv.agentBroker.caCertDER)
	if err != nil || status.Status != want || status.Serial != serial || status.ResponderIsIssuer || !status.ResponderHasOCSPSigningEKU {
		t.Fatalf("public signed OCSP result = %+v error=%v, want %s for selected serial", status, err, want)
	}
}

func servedPublicBrokerRevocationFixture(t *testing.T, options ...func(*Deps)) (*servedHarness, string, map[string]any) {
	t.Helper()
	return servedPublicBrokerRevocationFixtureWithHistoryOptions(t, nil, options...)
}

func servedPublicBrokerRevocationFixtureWithHistoryOptions(t *testing.T, eventOptions []events.OpenOption, options ...func(*Deps)) (*servedHarness, string, map[string]any) {
	t.Helper()
	authority, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.Destroy)
	jwk, err := crypto.PublicJWK(authority.Public(), "served-clock-key")
	if err != nil {
		t.Fatal(err)
	}
	opts := []func(*Deps){func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
	}}
	opts = append(opts, options...)
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, eventOptions, opts...)
	registerServedTenant(t, h, "Public certificate revocation")
	owner := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", owner, "public-revocation-trust", map[string]any{
		"name": "public-revocation-trust", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl",
		"jwks": crypto.JWKS{Keys: []crypto.JWK{jwk}},
	})
	if status != http.StatusCreated {
		t.Fatalf("register genuine proof trust: HTTP %d", status)
	}
	body := servedClockProofBody(t, authority, servedAttestedPublicKeyPEM(t), nil)
	body["agent_id"], body["scopes"] = "agent-7", []string{"tool:inventory.read"}
	return h, owner, body
}
