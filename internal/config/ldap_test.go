// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func fullLDAP() LDAP {
	return LDAP{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		Enabled:            true,
		URL:                "ldap://127.0.0.1:389",
		UserDNTemplate:     "uid={username},ou=people,dc=example,dc=org",
		GroupSearchBaseDN:  "ou=groups,dc=example,dc=org",
		GroupFilter:        "(member={user_dn})",
		GroupNameAttribute: "cn",
		EmailAttribute:     "mail",
		SessionSecretFile:  "/tmp/trstctl-ldap-session.secret",
		SessionTTL:         "1h",
		Timeout:            "5s",
		TenantMappings: []TenantMapping{
			{Group: "admins", TenantID: "tenant-a", Roles: []string{"admin"}},
		},
	}
}

func TestLDAPDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.LDAP = LDAP{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled LDAP must not fail validation: %v", err)
	}
}

func TestLDAPEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(*LDAP){
		"missing url":             func(l *LDAP) { l.URL = "" },
		"missing session secret":  func(l *LDAP) { l.SessionSecretFile = "" },
		"missing group base":      func(l *LDAP) { l.GroupSearchBaseDN = "" },
		"missing group filter":    func(l *LDAP) { l.GroupFilter = "" },
		"missing group name attr": func(l *LDAP) { l.GroupNameAttribute = "" },
		"missing user locator": func(l *LDAP) {
			l.UserDNTemplate = ""
			l.UserSearchBaseDN = ""
			l.UserFilter = ""
		},
		"non-loopback plaintext": func(l *LDAP) { l.URL = "ldap://ldap.example.com:389" },
		"no tenant mapping":      func(l *LDAP) { l.TenantMappings = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			l := fullLDAP()
			mutate(&l)
			c.Auth.LDAP = l
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: enabled LDAP must fail validation", name)
			}
		})
	}
}

func TestLDAPEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Auth.LDAP = fullLDAP()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured LDAP must validate: %v", err)
	}
}

func TestLDAPLDAPSAllowedForNonLoopback(t *testing.T) {
	c := Default()
	l := fullLDAP()
	l.URL = "ldaps://ldap.example.com:636"
	c.Auth.LDAP = l
	if err := c.Validate(); err != nil {
		t.Fatalf("ldaps LDAP config must validate: %v", err)
	}
}
