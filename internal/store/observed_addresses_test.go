// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A212: the addresses a tenant's own sources recorded — a certificate's
// deployment location and a destination's verification address here — come
// back once each with the sources that saw them; another tenant's do not.
func TestObservedAddressesCollectEachSourcePerTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const shared, onlyCert = "203.0.113.212:443", "203.0.113.213:8443"
	for _, location := range []string{shared, onlyCert} {
		if _, err := s.UpsertCertificate(ctx, store.Certificate{
			TenantID: tenantA, Subject: "CN=" + location, Issuer: "CN=A212", Serial: "a212",
			Fingerprint: crypto.SHA256Hex([]byte("a212 store " + location)), DeploymentLocation: location,
			Source: "a212-store", Status: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
		ID: googleuuid.NewString(), TenantID: tenantA, Name: "a212-target", Type: "nginx",
		Config: json.RawMessage(`{"cert_path":"/etc/nginx/a.crt","key_path":"/etc/nginx/a.key","verify_address":"` + shared + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	seen, err := s.ObservedAddresses(ctx, tenantA, time.Now().Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	byAddress := map[string]store.ObservedAddress{}
	for _, address := range seen {
		byAddress[address.Address] = address
	}
	if got := byAddress[shared]; !slices.Equal(got.Sources, []string{"certificate_location", "verification_target"}) || got.Observations != 2 {
		t.Fatalf("shared address = %+v; want both sources once each", got)
	}
	if got := byAddress[onlyCert]; !slices.Equal(got.Sources, []string{"certificate_location"}) {
		t.Fatalf("certificate-only address = %+v", got)
	}
	other, err := s.ObservedAddresses(ctx, tenantB, time.Now().Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range other {
		if address.Address == shared || address.Address == onlyCert {
			t.Fatalf("tenant B read tenant A's address %s", address.Address)
		}
	}
}
