// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A168-L1: a gcpkms source names a Cloud KMS key ring and a token file, an
// azurekv source a vault URL and a token file, and a managed_keys authority
// may now assert gcp-kms or azure-key-vault. Each kind's fields are refused on
// the others.
func TestReconcileGCPAndAzureKMSSourcesValidateA168L1(t *testing.T) {
	valid := func(sources ...*ReconcileAuthoritySource) *Config {
		c := Default()
		authorities := []ReconcileAuthority{}
		for i, src := range sources {
			authorities = append(authorities, ReconcileAuthority{AuthorityID: []string{"kms", "managed-keys", "other"}[i], Source: src})
		}
		c.Reconcile.Schedules = []ReconcileSchedule{{TenantID: "t", Authorities: authorities}}
		return c
	}
	gcp := func() *ReconcileAuthoritySource {
		return &ReconcileAuthoritySource{Kind: "gcpkms", KeyRing: "projects/p/locations/us-east1/keyRings/trstctl", TokenFile: "/run/gcp/token", MaxObjects: 5000} // #nosec G101 -- credential file paths only, no credential value (CWE-798)
	}
	azure := func() *ReconcileAuthoritySource {
		return &ReconcileAuthoritySource{Kind: "azurekv", Address: "https://lab.vault.azure.net", TokenFile: "/run/azure/token", AllCustomerKeys: true} // #nosec G101 -- credential file paths only, no credential value (CWE-798)
	}
	for provider, source := range map[string]func() *ReconcileAuthoritySource{"gcp-kms": gcp, "azure-key-vault": azure} {
		if err := valid(source(), &ReconcileAuthoritySource{Kind: "managed_keys", Provider: provider}).Validate(); err != nil {
			t.Fatalf("a valid %s pair was refused: %v", provider, err)
		}
	}
	for name, tc := range map[string]struct {
		src  func() *ReconcileAuthoritySource
		edit func(*ReconcileAuthoritySource)
		want string
	}{
		"gcp without a ring":      {gcp, func(s *ReconcileAuthoritySource) { s.KeyRing = "" }, "key_ring must be projects/"},
		"gcp with a short ring":   {gcp, func(s *ReconcileAuthoritySource) { s.KeyRing = "projects/p/keyRings/r" }, "key_ring must be projects/"},
		"gcp without a token":     {gcp, func(s *ReconcileAuthoritySource) { s.TokenFile = "" }, "token_file is required"},
		"gcp over plain http":     {gcp, func(s *ReconcileAuthoritySource) { s.Address = "http://kms.internal" }, "https URL"},
		"gcp with a path":         {gcp, func(s *ReconcileAuthoritySource) { s.Address = "https://kms.internal/v1" }, "https URL with no path"},
		"gcp with aws fields":     {gcp, func(s *ReconcileAuthoritySource) { s.Region = "us-east-1" }, "belong to an awskms source"},
		"azure without a vault":   {azure, func(s *ReconcileAuthoritySource) { s.Address = "" }, "address (the vault URL) is required"},
		"azure with a key ring":   {azure, func(s *ReconcileAuthoritySource) { s.KeyRing = "projects/p/locations/l/keyRings/r" }, "key_ring belongs to a gcpkms source"},
		"azure with vault mounts": {azure, func(s *ReconcileAuthoritySource) { s.KVMounts = []string{"secret"} }, "azurekv source takes"},
		"azure with a provider":   {azure, func(s *ReconcileAuthoritySource) { s.Provider = "azure-key-vault" }, "provider belongs to a managed_keys"},
	} {
		t.Run(name, func(t *testing.T) {
			src := tc.src()
			tc.edit(src)
			err := valid(src, &ReconcileAuthoritySource{Kind: "managed_keys", Provider: "gcp-kms"}).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v; want an error containing %q", err, tc.want)
			}
		})
	}
	vault := &ReconcileAuthoritySource{Kind: "vault", Address: "https://vault.internal", TokenFile: "/run/token", KVMounts: []string{"secret"}, AllCustomerKeys: true}
	if err := valid(gcp(), &ReconcileAuthoritySource{Kind: "managed_keys", Provider: "gcp-kms"}, vault).Validate(); err == nil ||
		!strings.Contains(err.Error(), "all_customer_keys belongs to an awskms, gcpkms or azurekv source, not a vault one") {
		t.Fatalf("all_customer_keys on a vault source = %v; want it refused", err)
	}
}
