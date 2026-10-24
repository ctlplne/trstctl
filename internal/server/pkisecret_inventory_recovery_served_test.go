// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// legacyPKISecretLeaf signs a leaf with caDER/caSigner and records it the way
// a pre-v3 PKI-secret mint did: a v2 ca.certificate.issued event with the
// public leaf and serial, projected only as a responder serial.
func legacyPKISecretLeaf(t *testing.T, h *servedHarness, cn string, caDER []byte, caSigner crypto.DigestSigner, caID string) (events.Event, certinfo.Info) {
	t.Helper()
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignLeafFromCSR(caDER, caSigner, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.CAIssuedCertificate{CAID: caID, Serial: info.SerialNumber,
		IssuedAt: time.Now().UTC(), Source: "pkisecret", CertificateDER: der, Fingerprint: info.SHA256Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := h.log.Append(context.Background(), events.Event{Type: projections.EventCAIssuedCertificate, TenantID: h.tenant,
		SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(context.Background(), ev); err != nil {
		t.Fatalf("project legacy mint: %v", err)
	}
	return ev, info
}

// A111: a PKI-secret leaf minted before v3 kept only a responder serial, so
// the inventory revocation workflow could not reach it. The control plane now
// recovers each retained v2 leaf its issuing CA signed into the inventory row
// a v3 mint would have had (custody unknown), once; the leaf is then revoked
// through the ordinary inventory workflow, and a rebuild keeps the row. A
// leaf another CA signed stays serial evidence.
func TestServedLegacyPKISecretLeavesRecoverIntoInventory(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "identities:write", "certs:read", "certs:write", "certs:issue")
	if len(h.srv.caCertDER) == 0 || h.srv.caSigner == nil {
		t.Fatal("harness has no issuing CA")
	}
	original, leaf := legacyPKISecretLeaf(t, h, "legacy-pki.example.test", h.srv.caCertDER, h.srv.caSigner, IssuingCAID())

	// A leaf a different CA signed, recorded under the issuing CA's ID.
	foreignKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignKey.Destroy()
	foreignDER, err := crypto.SelfSignedCACert(foreignKey, "not the issuing CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, foreign := legacyPKISecretLeaf(t, h, "foreign.example.test", foreignDER, foreignKey, IssuingCAID())

	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leaf.SHA256Fingerprint); err == nil {
		t.Fatal("a legacy v2 mint already had an inventory row before recovery")
	}

	result, err := h.srv.recoverLegacyPKISecretInventory(ctx)
	if err != nil || result.Recovered != 1 || result.Unverifiable != 1 {
		t.Fatalf("recovery = %+v, %v", result, err)
	}
	row, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leaf.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("recovered leaf: %v", err)
	}
	wantID := projections.RecoveredSecretPKIInventoryID(h.tenant, original.ID)
	if row.ID != wantID || row.Source != "issued" || row.Serial != leaf.SerialNumber || row.KeyOrigin != "" {
		t.Fatalf("recovered row = id %s source %s serial %s origin %q", row.ID, row.Source, row.Serial, row.KeyOrigin)
	}
	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, foreign.SHA256Fingerprint); err == nil {
		t.Fatal("a leaf the issuing CA did not sign was inventoried")
	}
	if again, err := h.srv.recoverLegacyPKISecretInventory(ctx); err != nil || again.Recovered != 0 || again.AlreadyRecovered != 1 {
		t.Fatalf("second recovery = %+v, %v", again, err)
	}

	// The inventory revocation workflow now reaches the leaf.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "a111-revoke", map[string]any{
		"certificate_ids": []string{row.ID}, "reason": "keyCompromise",
	})
	if status != http.StatusOK {
		t.Fatalf("revoke recovered leaf = %d %s", status, body)
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), leaf.SerialNumber)
	if err != nil || !found || issued.RevokedAt == nil {
		t.Fatalf("CA ledger after revocation = %+v found=%v err=%v", issued, found, err)
	}

	// A rebuild from the log keeps the recovered row and its identity.
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	rebuilt, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leaf.SHA256Fingerprint)
	if err != nil || rebuilt.ID != wantID {
		t.Fatalf("rebuilt row = %+v, %v", rebuilt, err)
	}
}

// legacyPKISecretSerialMint signs a leaf with the issuing CA and records it
// the way the oldest PKI-secret mint did: a v1 event holding only the serial.
func legacyPKISecretSerialMint(t *testing.T, h *servedHarness, cn string, record bool) (events.Event, certinfo.Info, []byte) {
	t.Helper()
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignLeafFromCSR(h.srv.caCertDER, h.srv.caSigner, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	if !record {
		return events.Event{}, info, der
	}
	payload, err := json.Marshal(projections.CAIssuedCertificate{CAID: IssuingCAID(), Serial: info.SerialNumber,
		IssuedAt: time.Now().UTC(), Source: "pkisecret"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := h.log.Append(context.Background(), events.Event{Type: projections.EventCAIssuedCertificate, TenantID: h.tenant, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(context.Background(), ev); err != nil {
		t.Fatalf("project legacy serial mint: %v", err)
	}
	return ev, info, der
}

func recoverLeaf(t *testing.T, h *servedHarness, token, key string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/certificates/pki-secret-recoveries", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Idempotency-Key", key)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A111: the oldest PKI-secret mints kept only a serial. An operator who still
// holds such a leaf's public certificate supplies it; the control plane takes
// it only when its issuing CA signed it and a PKI-secret mint recorded its
// serial, and then gives it the inventory row that mint would have had. A
// retry returns the same row; anything else is refused and records nothing.
func TestServedPKISecretLeafRecoveryFromAnOperatorCertificate(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "identities:write", "certs:read", "certs:write", "certs:issue")
	original, leaf, der := legacyPKISecretSerialMint(t, h, "serial-only.example.test", true)

	status, body := recoverLeaf(t, h, token, "a111-v1", certPEM(der))
	var recovered struct {
		CertificateID    string `json:"certificate_id"`
		Evidence         string `json:"evidence"`
		OriginalEventID  string `json:"original_event_id"`
		AlreadyRecovered bool   `json:"already_recovered"`
	}
	wantID := projections.RecoveredSecretPKIInventoryID(h.tenant, original.ID)
	if status != http.StatusOK || json.Unmarshal(body, &recovered) != nil || recovered.CertificateID != wantID ||
		recovered.Evidence != projections.RecoveredFromOperatorLeaf || recovered.OriginalEventID != original.ID || recovered.AlreadyRecovered {
		t.Fatalf("recover v1 leaf = %d %s", status, body)
	}
	if status, replay := recoverLeaf(t, h, token, "a111-v1", certPEM(der)); status != http.StatusOK || !bytes.Equal(replay, body) {
		t.Fatalf("idempotent replay = %d %s", status, replay)
	}
	if status, again := recoverLeaf(t, h, token, "a111-v1-again", certPEM(der)); status != http.StatusOK || !bytes.Contains(again, []byte(`"already_recovered":true`)) {
		t.Fatalf("second recovery = %d %s", status, again)
	}
	row, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leaf.SHA256Fingerprint)
	if err != nil || row.ID != wantID || row.KeyOrigin != "" {
		t.Fatalf("recovered row = %+v, %v", row, err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "a111-v1-revoke", map[string]any{
		"certificate_ids": []string{row.ID}, "reason": "superseded",
	}); status != http.StatusOK {
		t.Fatalf("revoke recovered v1 leaf = %d %s", status, body)
	}

	// A v2 mint's retained leaf goes through the same route.
	v2, v2Leaf := legacyPKISecretLeaf(t, h, "retained.example.test", h.srv.caCertDER, h.srv.caSigner, IssuingCAID())
	v2Row, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, v2Leaf.SHA256Fingerprint)
	if err == nil {
		t.Fatalf("v2 leaf inventoried before recovery: %+v", v2Row)
	}
	retained, found, err := h.log.EventByID(ctx, v2.ID)
	if err != nil || !found {
		t.Fatalf("retained v2 mint: found=%v %v", found, err)
	}
	var retainedFact projections.CAIssuedCertificate
	if err := json.Unmarshal(retained.Data, &retainedFact); err != nil {
		t.Fatal(err)
	}
	if status, body := recoverLeaf(t, h, token, "a111-v2", certPEM(retainedFact.CertificateDER)); status != http.StatusOK ||
		!bytes.Contains(body, []byte(`"evidence":"retained_v2_leaf"`)) {
		t.Fatalf("recover v2 leaf = %d %s", status, body)
	}

	// Refusals record nothing.
	foreignKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignKey.Destroy()
	foreignCA, err := crypto.SelfSignedCACert(foreignKey, "another CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, unminted := legacyPKISecretSerialMint(t, h, "never-recorded.example.test", false)
	for name, body := range map[string][]byte{
		"not a certificate":       []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"a CA certificate":        certPEM(foreignCA),
		"a serial never minted":   certPEM(unminted),
		"another CA's end entity": certPEM(foreignLeaf(t, foreignCA, foreignKey)),
	} {
		if status, out := recoverLeaf(t, h, token, "a111-refuse-"+name, body); status != http.StatusUnprocessableEntity {
			t.Fatalf("%s: recover = %d %s", name, status, out)
		}
	}
	if status, out := recoverLeaf(t, h, token, "a111-empty", nil); status != http.StatusBadRequest {
		t.Fatalf("empty body: recover = %d %s", status, out)
	}
}

func foreignLeaf(t *testing.T, caDER []byte, caKey crypto.DigestSigner) []byte {
	t.Helper()
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "foreign.example.test"}, subject)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignLeafFromCSR(caDER, caKey, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
