// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A169: Azure managed-key custody takes exactly one credential, the static
// bearer token (or its file) or a workload identity, and the workload identity
// is set from config or its environment mirrors.
func TestManagedKeysAzureWorkloadIdentityValidates(t *testing.T) {
	wi := func() *ManagedKeysAzureWorkloadIdentity {
		return &ManagedKeysAzureWorkloadIdentity{TenantID: "11111111-2222-4333-8444-555555555555", // #nosec G101 -- fixture tenant/client UUIDs and a token path, no credential value (CWE-798)
			ClientID: "66666666-7777-4888-9999-000000000000", FederatedTokenFile: "/var/run/secrets/azure/tokens/azure-identity-token"}
	}
	azure := func(mutate func(*ManagedKeysAzureKV)) ManagedKeysAzureKV {
		a := ManagedKeysAzureKV{VaultURL: "https://pool.managedhsm.azure.net", WorkloadIdentity: wi()}
		mutate(&a)
		return a
	}
	if errs := validateManagedKeysAzureCredential(azure(func(*ManagedKeysAzureKV) {})); len(errs) != 0 {
		t.Fatalf("a valid workload identity was refused: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*ManagedKeysAzureKV)
		want   string
	}{
		"both credentials": {func(a *ManagedKeysAzureKV) { a.BearerTokenFile = "/run/token" }, "set one, not both"},
		"neither":          {func(a *ManagedKeysAzureKV) { a.WorkloadIdentity = nil }, "workload_identity is required"},
		"tenant not uuid":  {func(a *ManagedKeysAzureKV) { a.WorkloadIdentity.TenantID = "contoso" }, "tenant_id must be"},
		"no token file":    {func(a *ManagedKeysAzureKV) { a.WorkloadIdentity.FederatedTokenFile = "" }, "federated_token_file is required"},
		"plain http host":  {func(a *ManagedKeysAzureKV) { a.WorkloadIdentity.AuthorityHost = "http://login.example" }, "authority_host"},
	} {
		t.Run(name, func(t *testing.T) {
			errs := validateManagedKeysAzureCredential(azure(tc.mutate))
			if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
				t.Fatalf("errors = %v; want one containing %q", errs, tc.want)
			}
		})
	}
	env := map[string]string{ // #nosec G101 -- fixture tenant/client UUIDs and a token path, no credential value (CWE-798)
		"TRSTCTL_MANAGED_KEYS_AZURE_WORKLOAD_TENANT_ID":            "11111111-2222-4333-8444-555555555555",
		"TRSTCTL_MANAGED_KEYS_AZURE_WORKLOAD_CLIENT_ID":            "66666666-7777-4888-9999-000000000000",
		"TRSTCTL_MANAGED_KEYS_AZURE_WORKLOAD_FEDERATED_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token",
	}
	c := Default()
	c.applyEnv(func(key string) string { return env[key] })
	if got := c.ManagedKeys.Azure.WorkloadIdentity; got == nil || got.TenantID != env["TRSTCTL_MANAGED_KEYS_AZURE_WORKLOAD_TENANT_ID"] ||
		got.FederatedTokenFile != env["TRSTCTL_MANAGED_KEYS_AZURE_WORKLOAD_FEDERATED_TOKEN_FILE"] {
		t.Fatalf("workload identity from the environment = %+v", got)
	}
}
