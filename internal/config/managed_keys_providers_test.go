// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	managedKeyTenantA = "11111111-1111-4111-8111-111111111111"
	managedKeyTenantB = "22222222-2222-4222-8222-222222222222"
)

func twoProviderManagedKeys() ManagedKeys {
	return ManagedKeys{
		Enabled: true, Provider: ManagedKeyProviderPKCS11,
		Providers: []string{"PKCS11", " aws "},
		TenantProviders: []ManagedKeyTenantProvider{
			{TenantID: managedKeyTenantA, Provider: "pkcs11"},
			{TenantID: managedKeyTenantB, Provider: "aws"},
		},
		AWS:    ManagedKeysAWSKMS{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessKeyFile: filepath.Join("/etc", "trstctl", "aws-secret")},
		PKCS11: ManagedKeysPKCS11HSM{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "trstctl", UserPINFile: "/etc/trstctl/pin"},
	}
}

// A199: a deployment runs several managed-key providers at once, each one's
// block validated; tenants may be pinned to one of them.
func TestManagedKeysRunSeveralProvidersWithTenantPins(t *testing.T) {
	m := twoProviderManagedKeys()
	if got := m.EnabledProviders(); !slices.Equal(got, []string{"pkcs11", "aws"}) {
		t.Fatalf("enabled providers = %v", got)
	}
	if got := m.DefaultProvider(); got != "pkcs11" {
		t.Fatalf("default = %q", got)
	}
	if got, ok := m.TenantProvider(managedKeyTenantB); !ok || got != "aws" {
		t.Fatalf("tenant B pin = %q %v", got, ok)
	}
	if _, ok := m.TenantProvider("33333333-3333-4333-8333-333333333333"); ok {
		t.Fatal("an unpinned tenant reported a pin")
	}
	if errs := validateManagedKeys(m); len(errs) != 0 {
		t.Fatalf("a valid two-provider configuration was refused: %v", errs)
	}

	single := ManagedKeys{Enabled: true, Provider: "pkcs11"}
	if got := single.EnabledProviders(); !slices.Equal(got, []string{"pkcs11"}) {
		t.Fatalf("a single-provider configuration runs %v", got)
	}
	if got := (ManagedKeys{Providers: []string{"gcp-kms", "aws"}}).DefaultProvider(); got != "gcp-kms" {
		t.Fatalf("without provider the default is %q, want the first listed", got)
	}

	for name, mutate := range map[string]func(*ManagedKeys){
		"a listed provider's block is incomplete": func(m *ManagedKeys) { m.AWS.Region = "" },
		"the default is not listed":               func(m *ManagedKeys) { m.Provider = "gcp-kms" },
		"a provider is listed twice":              func(m *ManagedKeys) { m.Providers = append(m.Providers, "pkcs11") },
		"an unknown provider is listed":           func(m *ManagedKeys) { m.Providers = append(m.Providers, "vault") },
		"a pin names an unlisted provider":        func(m *ManagedKeys) { m.TenantProviders[1].Provider = "gcp-kms" },
		"a pin names no tenant":                   func(m *ManagedKeys) { m.TenantProviders[0].TenantID = "not-a-uuid" },
		"a tenant is pinned twice": func(m *ManagedKeys) {
			m.TenantProviders = append(m.TenantProviders, ManagedKeyTenantProvider{TenantID: managedKeyTenantA, Provider: "aws"})
		},
	} {
		broken := twoProviderManagedKeys()
		mutate(&broken)
		if errs := validateManagedKeys(broken); len(errs) == 0 {
			t.Errorf("%s: the configuration was accepted", name)
		}
	}
}

func TestManagedKeysProvidersAndPinsFromEnvironment(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture values; nothing here is real (CWE-798)
		"TRSTCTL_MANAGED_KEYS_ENABLED":                    "true",
		"TRSTCTL_MANAGED_KEYS_PROVIDER":                   "pkcs11",
		"TRSTCTL_MANAGED_KEYS_PROVIDERS":                  "pkcs11,aws",
		"TRSTCTL_MANAGED_KEYS_TENANT_PROVIDERS":           managedKeyTenantA + ":pkcs11, " + managedKeyTenantB + ":aws",
		"TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH":         "/usr/lib/softhsm/libsofthsm2.so",
		"TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL":         "trstctl",
		"TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE":       "/etc/trstctl/pin",
		"TRSTCTL_MANAGED_KEYS_AWS_REGION":                 "us-east-1",
		"TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID":          "AKIAEXAMPLE",
		"TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE": "/etc/trstctl/aws-secret",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ManagedKeys.EnabledProviders(); !slices.Equal(got, []string{"pkcs11", "aws"}) {
		t.Fatalf("providers from the environment = %v", got)
	}
	if got, ok := cfg.ManagedKeys.TenantProvider(managedKeyTenantB); !ok || got != "aws" {
		t.Fatalf("tenant pin from the environment = %q %v", got, ok)
	}
	env["TRSTCTL_MANAGED_KEYS_TENANT_PROVIDERS"] = "missing-colon"
	if _, err := Load(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "tenant_providers") {
		t.Fatalf("a malformed pin = %v, want a tenant_providers error", err)
	}
}
