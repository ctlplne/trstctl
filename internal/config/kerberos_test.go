// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func fullKerberos() Kerberos {
	return Kerberos{ // #nosec G101 -- fabricated fixture paths and identifiers; the test needs the shape, no value is real (CWE-798)
		Enabled: true, KeytabFile: "/etc/trstctl/http.keytab", SessionSecretFile: "/var/lib/trstctl/kerberos-session.secret",
		TenantMappings: []TenantMapping{{Subject: "alice@EXAMPLE.TEST", TenantID: "11111111-1111-4111-8111-111111111111", Roles: []string{"admin"}}},
	}
}

func TestKerberosDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.Kerberos = Kerberos{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled Kerberos must not fail validation: %v", err)
	}
}

func TestKerberosEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(*Kerberos){
		"missing keytab":         func(k *Kerberos) { k.KeytabFile = "" },
		"missing session secret": func(k *Kerberos) { k.SessionSecretFile = "" },
		"bad session ttl":        func(k *Kerberos) { k.SessionTTL = "soon" },
		"negative clock skew":    func(k *Kerberos) { k.MaxClockSkew = "-1m" },
		"no tenant mapping at all": func(k *Kerberos) {
			k.TenantMappings = nil
			k.AllowDefaultTenant = false
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			k := fullKerberos()
			mut(&k)
			c.Auth.Kerberos = k
			if err := c.Validate(); err == nil {
				t.Fatal("expected validation to fail closed")
			}
		})
	}
	c := Default()
	c.Auth.Kerberos = fullKerberos()
	if err := c.Validate(); err != nil {
		t.Fatalf("full Kerberos config rejected: %v", err)
	}
}
