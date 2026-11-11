// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLDAPStartTLSConfigurationA239L3: start_tls points the backend at the
// plain LDAP port and upgrades there, so its leases name an ldap:// URL with
// start_tls set; it can't be combined with plaintext, needs a server name to
// verify when addr is an IP, and isn't offered for active_directory, which
// keeps verified LDAPS.
func TestLDAPStartTLSConfigurationA239L3(t *testing.T) {
	directory := newFakeDirectory()
	base := LDAPConfig{
		Addr: "ldap.lab.test:389", StartTLS: true, BindDN: directory.admin, BindPassword: []byte(directory.adminPW),
		UsersDN: "ou=leases,dc=lab,dc=test", UsernamePrefix: "trstctl",
		RoleGroups: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test"},
	}
	b, err := NewLDAPBackend(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if !b.startTLS || b.url != "ldap://ldap.lab.test:389" || b.serverName != "ldap.lab.test" {
		t.Fatalf("a StartTLS backend: startTLS %v url %q server name %q", b.startTLS, b.url, b.serverName)
	}
	b.dial = newTestLDAPBackend(t, directory).dial
	_, raw, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readonly", LeaseID: "lease-starttls"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		URL      string `json:"url"`
		StartTLS bool   `json:"start_tls"`
	}
	if err := json.Unmarshal(raw, &credential); err != nil || credential.URL != "ldap://ldap.lab.test:389" || !credential.StartTLS {
		t.Fatalf("the lease's credential names %q start_tls %v (%v)", credential.URL, credential.StartTLS, err)
	}
	for name, tc := range map[string]struct {
		mutate func(*LDAPConfig)
		want   string
	}{
		"with plaintext":       {func(c *LDAPConfig) { c.Addr, c.AllowPlaintext = "10.0.0.5:389", true }, "exclusive"},
		"an IP without a name": {func(c *LDAPConfig) { c.Addr = "10.0.0.5:389" }, "tls_server_name is required"},
		"active_directory":     {func(c *LDAPConfig) { c.DirectoryMode = "active_directory" }, "verified LDAPS is required"},
	} {
		c := base
		tc.mutate(&c)
		if b, err := NewLDAPBackend(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			if b != nil {
				b.Close()
			}
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
