// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
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
