// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A secrets PKI leaf must be visible as the same public certificate that the
// responder knows. Operators need its exact inventory ID to revoke it through
// the ordinary certificate workflow; a serial-only record cannot supply that.
func TestServedPKISecretIsInventoriedAndExactlyRevocable(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write", "secrets:read", "certs:read", "certs:issue", "identities:write")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "pki-inventory.example.test"}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "pki-inventory-first", map[string]any{
		"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "ttl_seconds": 900,
	})
	if status != http.StatusCreated {
		t.Fatalf("PKI issue = %d: %s", status, raw)
	}
	var issued struct {
		CertificateID string `json:"certificate_id"`
		Certificate   string `json:"certificate"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect([]byte(issued.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("issued PKI leaf has no exact inventory row: %v", err)
	}
	if cert.Serial != info.SerialNumber || cert.Source != "issued" || cert.KeyOrigin != "requester" || cert.IssuanceEventID == "" {
		t.Fatalf("PKI inventory lost issuer or custody evidence: %+v", cert)
	}
	if issued.CertificateID != cert.ID {
		t.Fatalf("PKI issue did not return its exact revocation inventory ID: response=%s inventory=%s", issued.CertificateID, cert.ID)
	}
	status, inventoryJSON := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+issued.CertificateID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("PKI certificate is absent from operator API: HTTP %d %s", status, inventoryJSON)
	}
	var operatorReadback struct {
		ID          string `json:"id"`
		Serial      string `json:"serial"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(inventoryJSON, &operatorReadback); err != nil ||
		operatorReadback.ID != issued.CertificateID || operatorReadback.Serial != cert.Serial ||
		operatorReadback.Fingerprint != cert.Fingerprint {
		t.Fatalf("operator API inventory readback differs from issued leaf: %s, %v", inventoryJSON, err)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token,
		"pki-inventory-revoke", map[string]any{"certificate_ids": []string{cert.ID}, "reason": "keyCompromise"})
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalRevoked != 1 || result.TotalFailed != 0 {
		t.Fatalf("exact PKI revocation = %d: %s", status, raw)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertExactRevocationViewsAgree(t, h, cert.ID)
	status, crlDER := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	crl, err := crypto.ParseCRL(crlDER, h.srv.caCertDER)
	if status != http.StatusOK || err != nil || !containsSerial(crl.RevokedSerials, cert.Serial) {
		t.Fatalf("signed CA CRL omitted PKI secret revocation: HTTP %d error=%v", status, err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold projection rebuild of issued and revoked PKI leaf: %v", err)
	}
	replayed, err := h.store.GetCertificate(t.Context(), h.tenant, cert.ID)
	if err != nil || replayed.Fingerprint != cert.Fingerprint || replayed.Status != "revoked" ||
		replayed.KeyOrigin != "requester" || replayed.IssuanceEventID != cert.IssuanceEventID {
		t.Fatalf("cold replay changed exact PKI certificate: %+v, %v", replayed, err)
	}
	assertExactRevocationViewsAgree(t, h, cert.ID)
}
