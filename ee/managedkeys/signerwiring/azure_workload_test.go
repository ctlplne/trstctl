// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A169: the child signer builds the Azure managed-key provider from a workload
// identity with no static bearer token, picks the Managed HSM scope from the
// vault URL, and refuses a configuration that sets both credentials.
func TestAzureManagedKeyProviderRunsOnWorkloadIdentity(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "azure-identity-token")
	bearerFile := filepath.Join(dir, "bearer")
	for path, value := range map[string]string{tokenFile: "projected-jwt", bearerFile: "static-token"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(extra string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"enabled":true,"provider":"azure-key-vault","azure":{"vault_url":"https://pool.managedhsm.azure.net",` + extra +
			`"workload_identity":{"tenant_id":"11111111-2222-4333-8444-555555555555","client_id":"66666666-7777-4888-9999-000000000000","federated_token_file":"` + tokenFile + `"}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if option, err := ProviderOption(write(""), t.TempDir()); err != nil || option == nil {
		t.Fatalf("workload identity provider: option=%v err=%v", option != nil, err)
	}
	if _, err := ProviderOption(write(`"bearer_token_file":"`+bearerFile+`",`), t.TempDir()); err == nil || !strings.Contains(err.Error(), "set one, not both") {
		t.Fatalf("both credentials = %v; want them refused", err)
	}
	if got := azureKeyVaultScope("https://pool.managedhsm.azure.net"); got != "https://managedhsm.azure.net/.default" {
		t.Fatalf("Managed HSM scope = %q", got)
	}
	if got := azureKeyVaultScope("https://vault1.vault.azure.net"); got != "https://vault.azure.net/.default" {
		t.Fatalf("Key Vault scope = %q", got)
	}
}
