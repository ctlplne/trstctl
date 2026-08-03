// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

// Custody is recorded at issuance and survives every later observation (B5).
//
// The dangerous case is ordinary: trstctl issues a certificate from an
// operator's CSR — recording that the control plane never held the key — and
// then a cloud scan finds the same certificate deployed on a load balancer and
// re-upserts the row. The scan knows the subject, the serial and where it is
// deployed. It knows nothing about where the key was made. If its blank custody
// won, the audit fact would silently become an unknown, and nobody would see it
// happen because the row would still be there and still look complete.
func TestUpsertCertificateNeverDowngradesRecordedCustody(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().UTC().Add(-time.Hour)
	notAfter := notBefore.Add(24 * time.Hour)

	issued, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "CN=api.example.test", Issuer: "CN=Acme Issuing",
		Serial: "01", Fingerprint: "fp-custody-preserved", KeyAlgorithm: "ECDSA-P256",
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "issued",
		KeyOrigin: string(custody.OriginRequester), KeyGeneratedBy: "operator-csr",
	})
	if err != nil {
		t.Fatalf("record issued certificate: %v", err)
	}

	// The same certificate, later, as a discovery scan sees it.
	if _, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "CN=api.example.test", Issuer: "CN=Acme Issuing",
		Serial: "01", Fingerprint: "fp-custody-preserved", KeyAlgorithm: "ECDSA-P256",
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "cloud-aws",
		DeploymentLocation: "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/x",
	}); err != nil {
		t.Fatalf("rediscover certificate: %v", err)
	}

	got, err := s.GetCertificate(ctx, tenantA, issued.ID)
	if err != nil {
		t.Fatalf("reload certificate: %v", err)
	}
	if got.KeyOrigin != string(custody.OriginRequester) {
		t.Errorf("key_origin = %q after rediscovery, want %q — a scan blanked custody it "+
			"had no knowledge of, turning a recorded audit fact into an unknown",
			got.KeyOrigin, custody.OriginRequester)
	}
	if got.KeyGeneratedBy != "operator-csr" {
		t.Errorf("key_generated_by = %q after rediscovery, want %q", got.KeyGeneratedBy, "operator-csr")
	}
	// The scan's own facts must still win — this rule protects custody, not
	// the whole row.
	if got.DeploymentLocation == "" {
		t.Error("deployment_location is empty: the rediscovery upsert should still " +
			"apply what the scan actually observed")
	}
	if got.Source != "cloud-aws" {
		t.Errorf("source = %q, want cloud-aws", got.Source)
	}
}

// A certificate nobody watched being issued reads as unrecorded, and unrecorded
// is a distinct answer rather than a comfortable default.
func TestDiscoveredCertificateHasNoCustodyClaim(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().UTC().Add(-time.Hour)
	notAfter := notBefore.Add(24 * time.Hour)

	found, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "CN=legacy.example.test", Issuer: "CN=Somebody Else",
		Serial: "02", Fingerprint: "fp-discovered-only", KeyAlgorithm: "RSA-2048",
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "cloud-azure",
	})
	if err != nil {
		t.Fatalf("record discovered certificate: %v", err)
	}
	got, err := s.GetCertificate(ctx, tenantA, found.ID)
	if err != nil {
		t.Fatalf("reload certificate: %v", err)
	}
	record := custody.Record{
		Origin:     custody.KeyOrigin(got.KeyOrigin),
		Storage:    custody.StorageClass(got.KeyStorage),
		Exportable: custody.Exportability(got.KeyExportable),
	}
	if record.Recorded() {
		t.Errorf("a discovered certificate reports custody %+v; trstctl did not witness "+
			"its issuance and must not make a claim about it", record)
	}
	if record.ControlPlaneHeldKey() {
		t.Error("unrecorded custody must not answer the control-plane question either way")
	}
}
