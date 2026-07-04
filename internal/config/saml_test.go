// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

func fullSAML() SAML {
	return SAML{
		Enabled:           true,
		EntityID:          "https://app.example.com/auth/saml/metadata",
		MetadataURL:       "https://app.example.com/auth/saml/metadata",
		ACSURL:            "https://app.example.com/auth/saml/acs",
		IDPMetadataXML:    `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml/metadata"></EntityDescriptor>`,
		SessionSecretFile: "/var/lib/trstctl/saml-session.secret",
		TenantClaim:       "tenant",
		ClaimIsTenant:     true,
	}
}

func TestSAMLDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.SAML = SAML{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SAML must not fail validation: %v", err)
	}
}

func TestSAMLEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(*SAML){
		"missing entity id":      func(s *SAML) { s.EntityID = "" },
		"missing metadata url":   func(s *SAML) { s.MetadataURL = "" },
		"missing acs url":        func(s *SAML) { s.ACSURL = "" },
		"missing session secret": func(s *SAML) { s.SessionSecretFile = "" },
		"missing idp metadata":   func(s *SAML) { s.IDPMetadataXML = ""; s.IDPMetadataFile = "" },
		"non-https public acs":   func(s *SAML) { s.ACSURL = "http://app.example.com/auth/saml/acs" },
		"no tenant mapping at all": func(s *SAML) {
			s.TenantClaim = ""
			s.ClaimIsTenant = false
			s.TenantMappings = nil
			s.AllowDefaultTenant = false
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			s := fullSAML()
			mut(&s)
			c.Auth.SAML = s
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: enabled SAML must fail validation", name)
			}
		})
	}
}

func TestSAMLEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Auth.SAML = fullSAML()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured SAML must validate: %v", err)
	}
}

func TestSAMLLoopbackHTTPAllowed(t *testing.T) {
	c := Default()
	s := fullSAML()
	s.EntityID = "http://127.0.0.1:8443/auth/saml/metadata"
	s.MetadataURL = "http://127.0.0.1:8443/auth/saml/metadata"
	s.ACSURL = "http://127.0.0.1:8443/auth/saml/acs"
	c.Auth.SAML = s
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback http endpoints must be allowed: %v", err)
	}
}
