// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func servedEphemeralInitialCRLFixture(t *testing.T) (*servedHarness, string, map[string]any, *countingEphemeralDigestSigner) {
	t.Helper()
	h, _, body := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: time.Minute,
			MaxTTL: 5 * time.Minute, ApprovalTTL: time.Minute, RequiredApprovals: 1,
		}
	})
	delete(body, "agent_id")
	delete(body, "scopes")
	body["request_id"] = "initial-crl-approved-workload"
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "initial-crl-requester", "certs:request", "certs:read")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "initial-crl-approver", "certs:issue", "certs:read")
	leafSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.ephemeralIssuer.caSigner}
	h.srv.ephemeralIssuer.caSigner = leafSigner
	crlSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.revoc.caSigner}
	h.srv.revoc.caSigner = crlSigner
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/preview", requester, "", body)
	if status != http.StatusOK {
		t.Fatalf("effect-free preview: HTTP %d", status)
	}
	pending := servedEphemeralIssue(t, h, requester, "initial-crl-pending", body, http.StatusAccepted)
	if pending.State != "awaiting_approval" || pending.CertificatePEM != "" {
		t.Fatal("pending approval returned an issued credential")
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusNotFound || leafSigner.calls.Load() != 0 || crlSigner.calls.Load() != 0 {
		t.Fatal("preview or pending submission published a CRL or signed a leaf")
	}
	servedEphemeralApprove(t, h, approver, "initial-crl-approve", pending.ApprovalRequestID, pending.IntentDigest, http.StatusOK)
	status, _ = secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusNotFound || leafSigner.calls.Load() != 0 || crlSigner.calls.Load() != 0 {
		t.Fatal("approval alone published a CRL or signed a leaf")
	}
	return h, requester, body, leafSigner
}

func TestServedEphemeralIssuancePublishesInitialCRLBeforeSuccess(t *testing.T) {
	h, requester, body, leafSigner := servedEphemeralInitialCRLFixture(t)
	issued := servedEphemeralIssue(t, h, requester, "ephemeral-initial-crl", body, http.StatusCreated)
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("initial public CRL after successful approved ephemeral issuance: HTTP %d, want 200", status)
	}
	crl, err := crypto.ParseCRL(der, h.srv.ephemeralIssuer.caCertDER)
	if err != nil || len(crl.RevokedSerials) != 0 {
		t.Fatalf("initial signed CRL must be empty: %v", err)
	}
	assertPublicCertificateOCSP(t, h, cert.Serial, "good")
	replayed := servedEphemeralIssue(t, h, requester, "ephemeral-initial-crl", body, http.StatusCreated)
	if replayed.CertificateID != issued.CertificateID || replayed.CertificatePEM != issued.CertificatePEM || leafSigner.calls.Load() != 1 {
		t.Fatal("successful replay changed the exact credential or signed another leaf")
	}
	status, again := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK || !bytes.Equal(der, again) {
		t.Fatal("public read or replay generated a different initial CRL")
	}
}

func TestServedEphemeralInitialCRLFailureRecoversWithoutAnotherLeaf(t *testing.T) {
	h, requester, body, leafSigner := servedEphemeralInitialCRLFixture(t)
	originalCRLSigner := h.srv.revoc.caSigner
	h.srv.revoc.caSigner = unavailableCRLSigner{DigestSigner: originalCRLSigner}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral", requester, "ephemeral-crl-recovery", body)
	if status < 500 || status > 599 {
		t.Fatalf("publication failure must not report successful issuance: HTTP %d", status)
	}
	var failed struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(raw, &failed); err != nil || failed.CertificatePEM != "" {
		t.Fatal("failed publication returned a successful credential body")
	}
	before, err := h.store.ListCertificatesPage(t.Context(), h.tenant, "00000000-0000-0000-0000-000000000000", nil, 100, nil)
	if err != nil || len(before) != 1 || leafSigner.calls.Load() != 1 {
		t.Fatalf("one recoverable approved leaf must remain: count=%d signs=%d err=%v", len(before), leafSigner.calls.Load(), err)
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusNotFound {
		t.Fatal("failed publication unexpectedly left a public CRL")
	}
	h.srv.revoc.caSigner = originalCRLSigner
	recovered := servedEphemeralIssue(t, h, requester, "ephemeral-crl-recovery", body, http.StatusCreated)
	wantPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: before[0].CertificateDER})
	if recovered.CertificateID != before[0].ID || recovered.CertificatePEM != string(wantPEM) || leafSigner.calls.Load() != 1 {
		t.Fatal("publication recovery changed the approved leaf or signed another")
	}
	after, err := h.store.ListCertificatesPage(t.Context(), h.tenant, "00000000-0000-0000-0000-000000000000", nil, 100, nil)
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID {
		t.Fatal("publication recovery created another certificate row")
	}
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("recovered initial CRL: HTTP %d", status)
	}
	if _, err := crypto.ParseCRL(der, h.srv.ephemeralIssuer.caCertDER); err != nil {
		t.Fatal(err)
	}
}
