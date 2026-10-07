// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A v2 managed leaf has retained public DER, unlike the serial-only v1 event.
// Replaying it must recover one exact, revocable inventory row without asking
// the operator to reissue the certificate or claiming its old key custody.
func TestLegacyManagedCALeafRebuildsExactInventoryFromRetainedV2Event(t *testing.T) {
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
	registerServedTenant(t, h, "Legacy managed CA inventory fixture")
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "legacy-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue", "certs:read",
	})
	first := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "legacy-custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	second := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "legacy-custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	rootSpec := map[string]any{
		"common_name": "legacy inventory root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"legacy.example.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "legacy-root-ceremony")
	approveCACeremony(t, h, first, rootCeremony.ID, 1, "legacy-root-first")
	approveCACeremony(t, h, second, rootCeremony.ID, 2, "legacy-root-second")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "legacy-root-create")
	issuerSpec := map[string]any{
		"common_name": "legacy inventory issuer", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"legacy.example.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, issuerSpec, 2, "legacy-issuer-ceremony")
	approveCACeremony(t, h, first, ceremony.ID, 1, "legacy-issuer-first")
	approveCACeremony(t, h, second, ceremony.ID, 2, "legacy-issuer-second")
	issuer := createIntermediateCA(t, h, operator, ceremony.ID, root.ID, issuerSpec, "legacy-issuer-create")
	storedIssuer, err := h.store.GetCAAuthority(t.Context(), h.tenant, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := h.srv.caHierarchy.signerForAuthority(t.Context(), storedIssuer)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := h.signer.Client().GenerateKey(t.Context(), crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "legacy.example.test", DNSNames: []string{"legacy.example.test"},
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
	payload, err := json.Marshal(map[string]any{
		"ca_id": issuer.ID, "serial": info.SerialNumber, "subject": info.Subject,
		"certificate_der": leafDER, "fingerprint": info.SHA256Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(t.Context(), events.Event{
		ID: "legacy-v2-exact-leaf", TenantID: h.tenant,
		Type:          projections.EventCAEndEntityIssued,
		SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion,
		Data:          payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	before, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("retained public v2 managed CA leaf missing from inventory: %v", err)
	}
	if before.Serial != info.SerialNumber || before.Issuer != info.Issuer || before.Source != "issued" ||
		before.IssuanceEventID != event.ID || before.KeyOrigin != "" {
		t.Fatalf("legacy inventory misstates signed leaf or inferred custody: %+v", before)
	}
	if _, err := h.store.GetCertificateByFingerprint(t.Context(), "11111111-1111-4111-8111-111111111112", info.SHA256Fingerprint); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("neighbor tenant read recovered leaf: %v", err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("legacy managed leaf rebuild: %v", err)
	}
	after, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
	if err != nil || after.ID != before.ID || after.IssuanceEventID != event.ID {
		t.Fatalf("rebuild changed legacy leaf identity: before=%+v after=%+v error=%v", before, after, err)
	}
	if after.ID == "" || h.tenant == "" {
		t.Fatalf("legacy leaf has empty SQL identity: id=%q tenant=%q", after.ID, h.tenant)
	}
	issued, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, issuer.ID, info.SerialNumber)
	if err != nil || !found || issued.Revoked() {
		t.Fatalf("rebuild lost exact responder serial: found=%v row=%+v error=%v", found, issued, err)
	}
	if authority, err := h.srv.certificateRevocationAuthority(t.Context(), after); err != nil || authority != issuer.ID {
		t.Fatalf("historical signed leaf cannot use its exact managed CA for revocation: authority=%q error=%v", authority, err)
	}

	// Emulate the pre-upgrade responder-only read model while preserving its
	// immutable source event and already-applied global checkpoint. Startup must
	// notice the old event, then rebuild the missing inventory row automatically.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM certificates WHERE tenant_id=$1 AND id=$2`, h.tenant, after.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM certificate_metadata_receipts
			WHERE tenant_id=$1 AND event_id=$2`, h.tenant, event.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE projection_checkpoint
		SET legacy_managed_ca_inventory_checked_through=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatalf("warm upgrade failed to recover pre-upgrade managed inventory: %v", err)
	}
	recovered, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
	if err != nil || recovered.ID != before.ID || recovered.IssuanceEventID != event.ID {
		t.Fatalf("warm upgrade did not recover exact retained public leaf: %+v, %v", recovered, err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatalf("second warm boot should not rebuild already recovered leaf: %v", err)
	}
	stable, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
	if err != nil || stable.ID != before.ID {
		t.Fatalf("subsequent warm boot lost legacy managed leaf: %+v, %v", stable, err)
	}

	// A serial-only v1 event remains responder evidence, not a fabricated
	// certificate. The public v2 event must also refuse a mismatched CA.
	v1Data, err := json.Marshal(map[string]string{"ca_id": issuer.ID, "serial": "7f10"})
	if err != nil {
		t.Fatal(err)
	}
	v1, err := h.log.Append(t.Context(), events.Event{ID: "legacy-v1-serial-only", TenantID: h.tenant,
		Type: projections.EventCAEndEntityIssued, SchemaVersion: 1, Data: v1Data})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(t.Context(), v1); err != nil {
		t.Fatal(err)
	}
	var inventoryCount int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM certificates WHERE tenant_id=$1`, h.tenant).Scan(&inventoryCount)
	}); err != nil || inventoryCount != 1 {
		t.Fatalf("v1 serial-only event fabricated inventory: count=%d error=%v", inventoryCount, err)
	}
	wrongIssuerData, err := json.Marshal(map[string]any{
		"ca_id": root.ID, "serial": info.SerialNumber, "subject": info.Subject,
		"certificate_der": leafDER, "fingerprint": info.SHA256Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuer, err := h.log.Append(t.Context(), events.Event{ID: "legacy-v2-wrong-issuer", TenantID: h.tenant,
		Type: projections.EventCAEndEntityIssued, SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion,
		Data: wrongIssuerData})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(t.Context(), wrongIssuer); err == nil ||
		!strings.Contains(err.Error(), "no exact issuer signature") {
		t.Fatalf("v2 public leaf must fail at exact issuer signature check: %v", err)
	}
}
