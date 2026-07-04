// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

func fullSCIM() SCIM {
	return SCIM{
		Enabled: true,
		Tokens: []SCIMToken{{
			Name:      "okta-prod",
			TenantID:  "tenant-a",
			TokenFile: "/var/lib/trstctl/scim-okta.token",
		}},
	}
}

func TestSCIMDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.SCIM = SCIM{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SCIM must not fail validation: %v", err)
	}
}

func TestSCIMEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(*SCIM){
		"missing tokens": func(s *SCIM) { s.Tokens = nil },
		"missing tenant": func(s *SCIM) { s.Tokens[0].TenantID = "" },
		"missing token file": func(s *SCIM) {
			s.Tokens[0].TokenFile = ""
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			s := fullSCIM()
			mutate(&s)
			c.Auth.SCIM = s
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: enabled SCIM must fail validation", name)
			}
		})
	}
}

func TestSCIMEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Auth.SCIM = fullSCIM()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured SCIM must validate: %v", err)
	}
}

func TestSCIMEnvOverlaysSingleTenantToken(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_AUTH_SCIM_ENABLED":         "true",
		"TRSTCTL_AUTH_SCIM_TOKEN_NAME":      "entra",
		"TRSTCTL_AUTH_SCIM_TOKEN_TENANT_ID": "tenant-b",
		"TRSTCTL_AUTH_SCIM_TOKEN_FILE":      "/run/secrets/trstctl-scim-token",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with SCIM env: %v", err)
	}
	if !cfg.Auth.SCIM.Enabled {
		t.Fatal("SCIM env did not enable provisioning")
	}
	if len(cfg.Auth.SCIM.Tokens) != 1 {
		t.Fatalf("expected one SCIM token from env, got %d", len(cfg.Auth.SCIM.Tokens))
	}
	got := cfg.Auth.SCIM.Tokens[0]
	if got.Name != "entra" || got.TenantID != "tenant-b" || got.TokenFile != "/run/secrets/trstctl-scim-token" {
		t.Fatalf("unexpected SCIM token overlay: %#v", got)
	}
}
