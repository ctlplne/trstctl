// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A168-L1: a gcpkms block becomes one Cloud KMS source per authority id and an
// azurekv block one Key Vault source, with their scope, token file and egress
// carried over.
func TestReconcileGCPAndAzureKMSSourcesFromConfigA168L1(t *testing.T) {
	gcp := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindGCPKMS, KeyRing: " projects/p/locations/l/keyRings/r ", // #nosec G101 -- credential file paths only, no credential value (CWE-798)
		Address: " https://kms.private.internal ", TokenFile: " /run/gcp/token ", AllCustomerKeys: true, MaxObjects: 300,
		PrivateEndpointCIDRs: []string{"10.40.0.0/16"}}
	azure := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindAzureKV, Address: " https://lab.vault.azure.net ", // #nosec G101 -- credential file paths only, no credential value (CWE-798)
		TokenFile: " /run/azure/token ", MaxObjects: 200}
	c := config.Reconcile{Schedules: []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "gcp-kms-prod", Source: gcp}, {AuthorityID: "azure-kv-prod", Source: azure}}},
		{TenantID: "t2", Authorities: []config.ReconcileAuthority{{AuthorityID: "gcp-kms-prod", Source: gcp}, {AuthorityID: "azure-kv-prod", Source: azure}}},
	}}
	gcps := reconcileGCPKMSSourcesFromConfig(c)
	if len(gcps) != 1 {
		t.Fatalf("gcpkms sources = %+v, want one", gcps)
	}
	if s := gcps[0]; s.AuthorityID != "gcp-kms-prod" || s.KeyRing != "projects/p/locations/l/keyRings/r" || s.Address != "https://kms.private.internal" ||
		s.TokenFile != "/run/gcp/token" || !s.AllCustomerKeys || s.MaxObjects != 300 || len(s.PrivateEndpointCIDRs) != 1 {
		t.Fatalf("gcpkms source = %+v", s)
	}
	azures := reconcileAzureKVKeySourcesFromConfig(c)
	if len(azures) != 1 {
		t.Fatalf("azurekv sources = %+v, want one", azures)
	}
	if s := azures[0]; s.AuthorityID != "azure-kv-prod" || s.VaultURL != "https://lab.vault.azure.net" || s.TokenFile != "/run/azure/token" ||
		s.AllCustomerKeys || s.MaxObjects != 200 {
		t.Fatalf("azurekv source = %+v", s)
	}
}
