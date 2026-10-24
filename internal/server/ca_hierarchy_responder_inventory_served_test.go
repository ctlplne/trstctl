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

// A113: an issuance surface could record a managed CA leaf only in the v2
// responder form of ca.endentity.issued (public leaf, no subject), which the
// projector keeps as serial evidence because another event usually
// inventories that leaf. When none did, the lifecycle recovery checks the
// leaf against the managed CA's stored certificate and the CA ledger, gives
// it its own inventory row once, and the inventory workflow then revokes it
// against that managed CA. A rebuild keeps the row.
func TestServedManagedCAResponderLeavesRecoverIntoInventory(t *testing.T) {
	ctx := context.Background()
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
	registerServedTenant(t, h, "Managed responder leaf fixture")
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "responder-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue", "certs:read", "certs:write", "identities:write",
	})
	first := seedServedAPIToken(t, ctx, h.store, h.tenant, "responder-custodian-one", []string{"issuers:write", "issuers:read", "certs:issue"})
	second := seedServedAPIToken(t, ctx, h.store, h.tenant, "responder-custodian-two", []string{"issuers:write", "issuers:read", "certs:issue"})
	rootSpec := map[string]any{
		"common_name": "responder inventory root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"responder.example.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "responder-root-ceremony")
	approveCACeremony(t, h, first, rootCeremony.ID, 1, "responder-root-first")
	approveCACeremony(t, h, second, rootCeremony.ID, 2, "responder-root-second")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "responder-root-create")
	issuerSpec := map[string]any{
		"common_name": "responder inventory issuer", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"responder.example.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, issuerSpec, 2, "responder-issuer-ceremony")
	approveCACeremony(t, h, first, ceremony.ID, 1, "responder-issuer-first")
	approveCACeremony(t, h, second, ceremony.ID, 2, "responder-issuer-second")
	issuer := createIntermediateCA(t, h, operator, ceremony.ID, root.ID, issuerSpec, "responder-issuer-create")
	storedIssuer, err := h.store.GetCAAuthority(ctx, h.tenant, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := h.srv.caHierarchy.signerForAuthority(ctx, storedIssuer)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := h.signer.Client().GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "responder.example.test", DNSNames: []string{"responder.example.test"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerDER, err := firstCertDER(issuer.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := h.srv.caHierarchy.leafProfileForAuthority(h.tenant, storedIssuer, h.srv.caHierarchy.leafProfile)
	if err != nil {
		t.Fatal(err)
	}
	profile.ClampTTLToIssuer = true
	leafDER, err := crypto.SignLeafFromCSRWithProfile(issuerDER, remote, csrDER, time.Hour, profile)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	// The responder form: public leaf and serial, no subject.
	payload, err := json.Marshal(map[string]any{
		"ca_id": issuer.ID, "serial": info.SerialNumber, "issued_at": time.Now().UTC(), "source": "acme",
		"certificate_der": leafDER, "fingerprint": info.SHA256Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: projections.EventCAEndEntityIssued,
		SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, original); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint); err == nil {
		t.Fatal("a responder-form mint was inventoried before recovery")
	}

	result, err := h.srv.recoverLegacyPKISecretInventory(ctx)
	if err != nil || result.Recovered != 1 {
		t.Fatalf("recovery = %+v, %v", result, err)
	}
	row, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
	wantID := projections.RecoveredInventoryID(h.tenant, projections.CACertificateInventoryRecovered{
		OriginalEventID: original.ID, Evidence: projections.RecoveredFromRetainedResponderLeaf})
	if err != nil || row.ID != wantID || row.Source != "issued" || row.KeyOrigin != "" || row.Serial != info.SerialNumber {
		t.Fatalf("recovered responder row = %+v, %v", row, err)
	}
	if authority, err := h.srv.certificateRevocationAuthority(ctx, row); err != nil || authority != issuer.ID {
		t.Fatalf("recovered responder leaf cannot use its managed CA for revocation: authority=%q error=%v", authority, err)
	}
	if again, err := h.srv.recoverLegacyPKISecretInventory(ctx); err != nil || again.Recovered != 0 || again.AlreadyRecovered != 1 {
		t.Fatalf("second recovery = %+v, %v", again, err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", operator, "a113-revoke", map[string]any{
		"certificate_ids": []string{row.ID}, "reason": "superseded",
	}); status != http.StatusOK {
		t.Fatalf("revoke recovered responder leaf = %d %s", status, body)
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, issuer.ID, info.SerialNumber)
	if err != nil || !found || issued.RevokedAt == nil {
		t.Fatalf("managed CA ledger after revocation = %+v found=%v err=%v", issued, found, err)
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint); err != nil || rebuilt.ID != wantID {
		t.Fatalf("rebuilt responder row = %+v, %v", rebuilt, err)
	}
}
