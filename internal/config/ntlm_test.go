// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func fullNTLM() NTLM {
	return NTLM{ // #nosec G101 -- fabricated fixture paths and identifiers; the test needs the shape, no value is real (CWE-798)
		Enabled: true, HelperCommand: "/usr/bin/ntlm_auth", SessionSecretFile: "/var/lib/trstctl/ntlm-session.secret",
		TenantMappings: []TenantMapping{{Subject: "alice@ADLAB.TEST", TenantID: "11111111-1111-4111-8111-111111111111", Roles: []string{"admin"}}},
	}
}

func TestNTLMEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(*NTLM){
		"no helper":              func(n *NTLM) { n.HelperCommand = "" },
		"both helpers":           func(n *NTLM) { n.HelperAddress = "tcp://127.0.0.1:3101" },
		"relative command":       func(n *NTLM) { n.HelperCommand = "ntlm_auth" },
		"bad address scheme":     func(n *NTLM) { n.HelperCommand = ""; n.HelperAddress = "127.0.0.1:3101" },
		"missing session secret": func(n *NTLM) { n.SessionSecretFile = "" },
		"bad helper timeout":     func(n *NTLM) { n.HelperTimeout = "later" },
		"no tenant mapping at all": func(n *NTLM) {
			n.TenantMappings = nil
			n.AllowDefaultTenant = false
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			n := fullNTLM()
			mut(&n)
			c.Auth.NTLM = n
			if err := c.Validate(); err == nil {
				t.Fatal("expected validation to fail closed")
			}
		})
	}
	for name, n := range map[string]NTLM{"command": fullNTLM(), "address": func() NTLM {
		n := fullNTLM()
		n.HelperCommand = ""
		n.HelperAddress = "tcp://127.0.0.1:3101"
		return n
	}()} {
		c := Default()
		c.Auth.NTLM = n
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: full NTLM config rejected: %v", name, err)
		}
	}
	c := Default()
	c.Auth.NTLM = NTLM{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled NTLM must not fail validation: %v", err)
	}
}
