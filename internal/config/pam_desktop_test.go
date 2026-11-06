// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/accessdesktop"
)

func TestDesktopProviderRequiresStaticAccountAndFixedRoute(t *testing.T) {
	ref := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(ref, []byte("owned-fixture-material"), 0600); err != nil {
		t.Fatal(err)
	}
	good := DynamicSecretProviderConfig{TenantID: "54500000-0000-4000-8000-000000000001", ID: "desktop", Type: "unix", Addr: "host.example:22", AdminUser: "root", PrivateKeyRef: "file:" + ref, HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), AllowedRoles: []string{"desktop/account"}, RoleBindings: map[string]string{"desktop/account": "service"}, AllowStaticRotation: true, MaxTTL: "1h", Desktop: &accessdesktop.Binding{Address: "host.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DynamicSecretProviderConfig){func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, func(c *DynamicSecretProviderConfig) { c.Desktop.Width = 1281 }, func(c *DynamicSecretProviderConfig) { c.Desktop.CertificateSHA256 = "bad" }, func(c *DynamicSecretProviderConfig) {
		c.Gateway = &DynamicSecretGatewayConfig{Endpoint: "https://foreign.example"}
	}} {
		bad := good
		b := *good.Desktop
		bad.Desktop = &b
		change(&bad)
		if validate(bad) == nil {
			t.Fatal("unsafe desktop provider accepted")
		}
	}
}
