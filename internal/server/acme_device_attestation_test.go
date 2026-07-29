// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestDeviceAttestTPMProfileRootsAndIdentifiersAreCrossTenantIsolated(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const (
		tenantA = "11111111-1111-4111-8111-111111111111"
		tenantB = "22222222-2222-4222-8222-222222222222"
		name    = "device-enrollment"
	)
	for tenant, root := range map[string]string{
		tenantA: "-----BEGIN CERTIFICATE-----\ntenant-a-root\n-----END CERTIFICATE-----",
		tenantB: "-----BEGIN CERTIFICATE-----\ntenant-b-root\n-----END CERTIFICATE-----",
	} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatalf("upsert tenant %s: %v", tenant, err)
		}
		spec, err := json.Marshal(profile.CertificateProfile{
			Name:    name,
			Version: 1,
			ACMEDeviceAttestation: profile.ACMEDeviceAttestationPolicy{
				Enabled:             true,
				Format:              "tpm",
				AttestationRootsPEM: []string{root},
				AllowedIdentifiers:  []string{map[string]string{tenantA: "a.devices.test", tenantB: "b.devices.test"}[tenant]},
				AllowedAlgorithms:   []int64{-7},
				MaxAge:              profile.Duration(5 * time.Minute),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateProfileVersion(ctx, store.ProfileRecord{
			TenantID:  tenant,
			Name:      name,
			Spec:      spec,
			CreatedBy: "test",
		}); err != nil {
			t.Fatalf("create profile for %s: %v", tenant, err)
		}
	}

	source := acmeDeviceAttestationProfiles{store: st, profileName: name}
	policyA, enabled, err := source.DeviceAttestationPolicy(ctx, tenantA, "a.devices.test")
	if err != nil || !enabled {
		t.Fatalf("tenant A policy enabled=%v err=%v", enabled, err)
	}
	if got := string(policyA.TrustedRootsPEM[0]); got != "-----BEGIN CERTIFICATE-----\ntenant-a-root\n-----END CERTIFICATE-----" {
		t.Fatalf("tenant A received root %q", got)
	}
	if _, enabled, err := source.DeviceAttestationPolicy(ctx, tenantA, "b.devices.test"); err != nil || enabled {
		t.Fatalf("tenant A resolved tenant B identifier: enabled=%v err=%v", enabled, err)
	}
	policyB, enabled, err := source.DeviceAttestationPolicy(ctx, tenantB, "b.devices.test")
	if err != nil || !enabled {
		t.Fatalf("tenant B policy enabled=%v err=%v", enabled, err)
	}
	if got := string(policyB.TrustedRootsPEM[0]); got != "-----BEGIN CERTIFICATE-----\ntenant-b-root\n-----END CERTIFICATE-----" {
		t.Fatalf("tenant B received root %q", got)
	}
}
