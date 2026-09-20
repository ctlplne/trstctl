// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestServedAttestedIssuancePublishesInitialCRLBeforeSuccess(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test"}
	})
	delete(body, "agent_id")
	delete(body, "scopes")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance", owner, "svid-initial-crl", body)
	if status != http.StatusCreated {
		t.Fatalf("attested issuance: HTTP %d", status)
	}
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("initial public CRL after successful attested issuance: HTTP %d, want 200", status)
	}
	crl, err := crypto.ParseCRL(der, h.srv.attestedIssuance.caCertDER)
	if err != nil || len(crl.RevokedSerials) != 0 {
		t.Fatalf("initial signed CRL must be empty: %v, error=%v", crl.RevokedSerials, err)
	}
}

type unavailableCRLSigner struct{ crypto.DigestSigner }

func (s unavailableCRLSigner) SignDigest([]byte, crypto.SignOptions) ([]byte, error) {
	return nil, errors.New("deliberately unavailable CRL signing operation")
}

func TestServedBrokerInitialCRLFailureRecoversWithoutAnotherLeaf(t *testing.T) {
	assertInitialCRLFailureRecovery(t, "broker")
}

func TestServedAttestedInitialCRLFailureRecoversWithoutAnotherLeaf(t *testing.T) {
	assertInitialCRLFailureRecovery(t, "attested")
}

func assertInitialCRLFailureRecovery(t *testing.T, surface string) {
	t.Helper()
	h, owner, body := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test"}
	})
	route := "/api/v1/broker/agent-identities"
	leafSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	h.srv.agentBroker.caSigner = leafSigner
	if surface == "attested" {
		route = "/api/v1/workloads/attested-issuance"
		delete(body, "agent_id")
		delete(body, "scopes")
		leafSigner = &countingEphemeralDigestSigner{DigestSigner: h.srv.attestedIssuance.caSigner}
		h.srv.attestedIssuance.caSigner = leafSigner
	}
	originalCRLSigner := h.srv.revoc.caSigner
	h.srv.revoc.caSigner = unavailableCRLSigner{DigestSigner: originalCRLSigner}
	status, failedBody := secretsReqKey(t, h, http.MethodPost, route, owner, "initial-crl-recovery", body)
	if status < 500 || status > 599 {
		t.Fatalf("publication failure must not report successful issuance: HTTP %d", status)
	}
	var failed struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(failedBody, &failed); err != nil || failed.CertificatePEM != "" {
		t.Fatal("publication failure must not return a certificate as a successful result")
	}
	const firstPage = "00000000-0000-0000-0000-000000000000"
	before, err := h.store.ListCertificatesPage(t.Context(), h.tenant, firstPage, nil, 100, nil)
	if err != nil || len(before) != 1 || leafSigner.calls.Load() != 1 {
		t.Fatalf("one recoverable leaf must remain: count=%d signs=%d error=%v", len(before), leafSigner.calls.Load(), err)
	}
	h.srv.revoc.caSigner = originalCRLSigner
	status, raw := secretsReqKey(t, h, http.MethodPost, route, owner, "initial-crl-recovery", body)
	var recovered struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &recovered) != nil {
		t.Fatalf("unchanged publication recovery failed: HTTP %d", status)
	}
	after, err := h.store.ListCertificatesPage(t.Context(), h.tenant, firstPage, nil, 100, nil)
	expectedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: before[0].CertificateDER})
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID || recovered.CertificatePEM != string(expectedPEM) || leafSigner.calls.Load() != 1 {
		t.Fatal("publication recovery must return the existing leaf without another certificate or leaf signature")
	}
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("recovered initial CRL: HTTP %d", status)
	}
	if _, err := crypto.ParseCRL(der, h.srv.agentBroker.caCertDER); err != nil {
		t.Fatal(err)
	}
}

// BROKER-INITIAL-CRL-001: a freshly installed broker returned a real short-lived
// certificate while its public CRL remained 404. Waiting for the hourly sweep
// cannot qualify a credential whose entire lifetime is only five minutes.
func TestServedBrokerIssuancePublishesInitialCRLBeforeSuccess(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "broker-initial-crl", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	// No Drain, scheduler tick, revocation, private API or database write may
	// manufacture the initial response: 201 means this trusted issuance finished.
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("initial public CRL after successful broker issuance: HTTP %d, want 200", status)
	}
	crl, err := crypto.ParseCRL(der, h.srv.agentBroker.caCertDER)
	if err != nil || len(crl.RevokedSerials) != 0 {
		t.Fatalf("initial signed CRL must be empty: %v, error=%v", crl.RevokedSerials, err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	secondStatus, secondDER := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if secondStatus != http.StatusOK || string(secondDER) != string(der) {
		t.Fatal("anonymous CRL reads must return existing bytes, not generate another artifact")
	}
}
