// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A199: the signer builds every listed provider (one when only provider is
// set) and names the provider whose configuration fails.
func TestProviderOptionBuildsEveryListedProvider(t *testing.T) {
	if got := enabledProviders(managedKeyConfig{Provider: "pkcs11"}); !slices.Equal(got, []string{"pkcs11"}) {
		t.Fatalf("single provider = %v", got)
	}
	if got := enabledProviders(managedKeyConfig{}); !slices.Equal(got, []string{providerAWS}) {
		t.Fatalf("no provider = %v, want the AWS default", got)
	}
	if got := enabledProviders(managedKeyConfig{Provider: "pkcs11", Providers: []string{" GCP-KMS ", "aws"}}); !slices.Equal(got, []string{"gcp-kms", "aws"}) {
		t.Fatalf("listed providers = %v", got)
	}

	dir := t.TempDir()
	awsKeyFile := filepath.Join(dir, "aws-secret")
	gcpAccessFile := filepath.Join(dir, "gcp-token")
	for path, value := range map[string]string{awsKeyFile: "aws-secret-value", gcpAccessFile: "gcp-token-value"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(gcpFile string) string {
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"enabled":true,"provider":"aws","providers":["aws","gcp-kms"],` +
			`"tenant_providers":[{"tenant_id":"11111111-1111-4111-8111-111111111111","provider":"gcp-kms"}],` +
			`"aws":{"region":"us-east-1","endpoint":"http://127.0.0.1:1","allow_insecure_loopback":true,"access_key_id":"AKIAEXAMPLE","secret_access_key_file":"` + awsKeyFile + `"},` +
			`"gcp":{"parent":"projects/p/locations/l/keyRings/r","endpoint":"http://127.0.0.1:1/v1","allow_insecure_loopback":true,"bearer_token_file":"` + gcpFile + `"}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	option, err := ProviderOption(write(gcpAccessFile), t.TempDir())
	if err != nil || option == nil {
		t.Fatalf("two listed providers: option=%v err=%v", option != nil, err)
	}
	if _, err := ProviderOption(write(filepath.Join(dir, "missing-token")), t.TempDir()); err == nil || !strings.Contains(err.Error(), "gcp-kms") {
		t.Fatalf("a listed provider's broken configuration = %v, want an error naming gcp-kms", err)
	}
}
