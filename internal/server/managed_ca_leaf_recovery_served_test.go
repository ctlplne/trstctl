// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
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

func postManagedCALeaf(t *testing.T, h *servedHarness, token, key string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/certificates/managed-ca-recoveries", bytes.NewReader(body))
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

// A209: a managed CA leaf a v1 ca.endentity.issued mint recorded by serial
// only had no inventory row, so the inventory revocation workflow could not
// reach it. An operator who still holds the public certificate supplies it;
// the control plane accepts it only when the tenant's managed CA signed it by
// that CA's stored certificate and a v1 mint of that CA recorded its serial,
// and the leaf joins inventory once, revocable against that managed CA. A
// certificate another CA signed, a managed CA leaf no mint recorded, and a
// leaf whose mint retained it are refused; a rebuild keeps the row.
func TestServedManagedCASerialOnlyLeafRecoversFromItsCertificate(t *testing.T) {
	ctx := context.Background()
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
	registerServedTenant(t, h, "Managed serial-only leaf fixture")
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "a209-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue", "certs:read", "certs:write", "identities:write",
	})
	first := seedServedAPIToken(t, ctx, h.store, h.tenant, "a209-custodian-one", []string{"issuers:write", "issuers:read", "certs:issue"})
	second := seedServedAPIToken(t, ctx, h.store, h.tenant, "a209-custodian-two", []string{"issuers:write", "issuers:read", "certs:issue"})
	rootSpec := map[string]any{
		"common_name": "a209 root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"a209.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "a209-root-ceremony")
	approveCACeremony(t, h, first, rootCeremony.ID, 1, "a209-root-first")
	approveCACeremony(t, h, second, rootCeremony.ID, 2, "a209-root-second")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "a209-root-create")
	issuerSpec := map[string]any{
		"common_name": "a209 issuer", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"a209.example.test"}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, issuerSpec, 2, "a209-issuer-ceremony")
	approveCACeremony(t, h, first, ceremony.ID, 1, "a209-issuer-first")
	approveCACeremony(t, h, second, ceremony.ID, 2, "a209-issuer-second")
	issuer := createIntermediateCA(t, h, operator, ceremony.ID, root.ID, issuerSpec, "a209-issuer-create")
	storedIssuer, err := h.store.GetCAAuthority(ctx, h.tenant, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := h.srv.caHierarchy.signerForAuthority(ctx, storedIssuer)
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
	signLeaf := func(cn string) ([]byte, certinfo.Info) {
		t.Helper()
		key, err := h.signer.Client().GenerateKey(ctx, crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSRWithProfile(issuerDER, remote, csr, time.Hour, profile)
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(der)
		if err != nil {
			t.Fatal(err)
		}
		return der, info
	}
	mint := func(version int, payload map[string]any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: projections.EventCAEndEntityIssued, SchemaVersion: version, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.proj.Apply(ctx, ev); err != nil {
			t.Fatal(err)
		}
		return ev
	}

	// The v1 mint: serial only.
	leafDER, info := signLeaf("legacy.a209.example.test")
	original := mint(1, map[string]any{"ca_id": issuer.ID, "serial": info.SerialNumber, "issued_at": time.Now().UTC(), "source": "acme"})
	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint); err == nil {
		t.Fatal("a serial-only mint was inventoried before recovery")
	}

	status, body := postManagedCALeaf(t, h, operator, "a209-recover", certPEM(leafDER))
	if status != http.StatusOK {
		t.Fatalf("recover = %d %s", status, body)
	}
	var out struct {
		CertificateID    string `json:"certificate_id"`
		Evidence         string `json:"evidence"`
		OriginalEventID  string `json:"original_event_id"`
		AlreadyRecovered bool   `json:"already_recovered"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	wantID := projections.RecoveredInventoryID(h.tenant, projections.CACertificateInventoryRecovered{
		OriginalEventID: original.ID, Evidence: projections.RecoveredFromOperatorManagedLeaf})
	if out.CertificateID != wantID || out.Evidence != projections.RecoveredFromOperatorManagedLeaf || out.OriginalEventID != original.ID || out.AlreadyRecovered {
		t.Fatalf("recovery = %+v", out)
	}
	row, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
	if err != nil || row.ID != wantID || row.Source != "issued" || row.KeyOrigin != "" || row.Serial != info.SerialNumber {
		t.Fatalf("recovered row = %+v, %v", row, err)
	}
	if authority, err := h.srv.certificateRevocationAuthority(ctx, row); err != nil || authority != issuer.ID {
		t.Fatalf("the recovered leaf cannot use its managed CA for revocation: %q %v", authority, err)
	}
	status, body = postManagedCALeaf(t, h, operator, "a209-recover-again", certPEM(leafDER))
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"already_recovered":true`)) {
		t.Fatalf("a second recovery = %d %s", status, body)
	}

	// Refusals record nothing.
	foreignKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignKey.Destroy()
	foreignCA, err := crypto.SelfSignedCACert(foreignKey, "a209 foreign CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreignCSRKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignCSRKey.Destroy()
	foreignCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "foreign.a209.example.test"}, foreignCSRKey)
	if err != nil {
		t.Fatal(err)
	}
	foreignLeaf, err := crypto.SignLeafFromCSR(foreignCA, foreignKey, foreignCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := postManagedCALeaf(t, h, operator, "a209-foreign", certPEM(foreignLeaf)); status != http.StatusUnprocessableEntity {
		t.Fatalf("a leaf another CA signed = %d %s", status, body)
	}
	// The projector itself refuses a recovery event that names an issuer other
	// than the managed CA's stored certificate, even one that signed the leaf.
	foreignInfo, err := certinfo.Inspect(foreignLeaf)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := json.Marshal(projections.CACertificateInventoryRecovered{
		OriginalEventID: original.ID, CAID: issuer.ID, Serial: foreignInfo.SerialNumber, Fingerprint: foreignInfo.SHA256Fingerprint,
		CertificateDER: foreignLeaf, IssuerCertificateDER: foreignCA, Evidence: projections.RecoveredFromOperatorManagedLeaf,
		RecoveredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, events.Event{ID: "a2090000-0000-4000-8000-0000000000f1", TenantID: h.tenant, Sequence: 1 << 40,
		Type: projections.EventCACertificateInventoryRecovered, SchemaVersion: 1, Data: forged, Time: time.Now().UTC()}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("names an issuer other than the CA's stored certificate")) {
		t.Fatalf("a recovery naming another issuer projected: %v", err)
	}
	unminted, _ := signLeaf("unminted.a209.example.test")
	if status, body := postManagedCALeaf(t, h, operator, "a209-unminted", certPEM(unminted)); status != http.StatusUnprocessableEntity {
		t.Fatalf("a managed CA leaf no mint recorded = %d %s", status, body)
	}
	retainedDER, retainedInfo := signLeaf("retained.a209.example.test")
	mint(projections.CAIssuedCertificateEvidenceSchemaVersion, map[string]any{"ca_id": issuer.ID, "serial": retainedInfo.SerialNumber,
		"issued_at": time.Now().UTC(), "source": "acme", "certificate_der": retainedDER, "fingerprint": retainedInfo.SHA256Fingerprint})
	if status, body := postManagedCALeaf(t, h, operator, "a209-retained", certPEM(retainedDER)); status != http.StatusConflict {
		t.Fatalf("a leaf whose mint retained it = %d %s", status, body)
	}

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", operator, "a209-revoke", map[string]any{
		"certificate_ids": []string{row.ID}, "reason": "superseded",
	}); status != http.StatusOK {
		t.Fatalf("revoke the recovered leaf = %d %s", status, body)
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, issuer.ID, info.SerialNumber)
	if err != nil || !found || issued.RevokedAt == nil {
		t.Fatalf("managed CA ledger after revocation = %+v found=%v err=%v", issued, found, err)
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint); err != nil || rebuilt.ID != wantID {
		t.Fatalf("rebuilt row = %+v, %v", rebuilt, err)
	}
}
