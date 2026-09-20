// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func TestAUD58ProviderSAMLAndSCIMFailClosedWhenPartiallyConfigured(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Provider.SAML.Enabled = true
	c.Provider.SAML.EntityID = "https://provider.example.test/provider/v1/auth/saml/metadata"
	if err := c.Validate(); err == nil {
		t.Fatal("partial provider SAML configuration passed validation")
	}

	c = Default()
	c.Provider.SCIM.Enabled = true
	c.Provider.SCIM.Tokens = []ProviderSCIMToken{{Name: "entra", TokenFile: ""}}
	if err := c.Validate(); err == nil {
		t.Fatal("provider SCIM without a token file passed validation")
	}
}

func TestAUD58ProviderSAMLAndSCIMCompleteConfigurationValidates(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Provider.SAML = ProviderSAML{
		Enabled: true, EntityID: "https://provider.example.test/provider/v1/auth/saml/metadata",
		MetadataURL:       "https://provider.example.test/provider/v1/auth/saml/metadata",
		ACSURL:            "https://provider.example.test/provider/v1/auth/saml/acs",
		IDPMetadataXML:    `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"></EntityDescriptor>`,
		SessionSecretFile: "/run/secrets/provider-saml-session", RoleAttribute: "groups",
		AdminValues: []string{"provider-admin"}, MFAAttribute: "amr", MFAValues: []string{"mfa"},
	}
	c.Provider.SCIM = ProviderSCIM{Enabled: true, Tokens: []ProviderSCIMToken{{Name: "entra", TokenFile: "/run/secrets/provider-scim"}}}
	if err := c.Validate(); err != nil {
		t.Fatalf("complete provider SAML/SCIM config = %v", err)
	}
}

func TestAUD58ProviderIdentityEnvironmentOverlayIsComplete(t *testing.T) {
	t.Parallel()
	env := map[string]string{ // #nosec G101 -- values are configuration names and file paths, never secret bytes (CWE-798).
		"TRSTCTL_PROVIDER_OIDC_MFA_CLAIM":           "authn_methods",
		"TRSTCTL_PROVIDER_OIDC_MFA_VALUES":          "fido2,totp",
		"TRSTCTL_PROVIDER_SAML_ENABLED":             "true",
		"TRSTCTL_PROVIDER_SAML_ENTITY_ID":           "https://provider.example.test/provider/v1/auth/saml/metadata",
		"TRSTCTL_PROVIDER_SAML_METADATA_URL":        "https://provider.example.test/provider/v1/auth/saml/metadata",
		"TRSTCTL_PROVIDER_SAML_ACS_URL":             "https://provider.example.test/provider/v1/auth/saml/acs",
		"TRSTCTL_PROVIDER_SAML_IDP_METADATA_FILE":   "/run/provider/idp.xml",
		"TRSTCTL_PROVIDER_SAML_SESSION_SECRET_FILE": "/run/provider/session.secret",
		"TRSTCTL_PROVIDER_SAML_ROLE_ATTRIBUTE":      "groups",
		"TRSTCTL_PROVIDER_SAML_ADMIN_VALUES":        "provider-admins",
		"TRSTCTL_PROVIDER_SAML_OPERATOR_VALUES":     "provider-operators",
		"TRSTCTL_PROVIDER_SAML_MFA_ATTRIBUTE":       "authn_methods",
		"TRSTCTL_PROVIDER_SAML_MFA_VALUES":          "fido2,totp",
		"TRSTCTL_PROVIDER_SCIM_ENABLED":             "true",
		"TRSTCTL_PROVIDER_SCIM_TOKEN_NAME":          "entra",
		"TRSTCTL_PROVIDER_SCIM_TOKEN_FILE":          "/run/provider/scim.token",
	}
	c := Default()
	c.applyEnv(func(key string) string { return env[key] })
	if c.Provider.OIDC.MFAClaim != "authn_methods" || len(c.Provider.OIDC.MFAValues) != 2 {
		t.Fatalf("provider OIDC MFA overlay = %+v", c.Provider.OIDC)
	}
	if !c.Provider.SAML.Enabled || c.Provider.SAML.ACSURL == "" || c.Provider.SAML.SessionSecretFile == "" ||
		len(c.Provider.SAML.AdminValues) != 1 || len(c.Provider.SAML.OperatorValues) != 1 || len(c.Provider.SAML.MFAValues) != 2 {
		t.Fatalf("provider SAML overlay = %+v", c.Provider.SAML)
	}
	if !c.Provider.SCIM.Enabled || len(c.Provider.SCIM.Tokens) != 1 || c.Provider.SCIM.Tokens[0].Name != "entra" ||
		c.Provider.SCIM.Tokens[0].TokenFile != "/run/provider/scim.token" {
		t.Fatalf("provider SCIM overlay = %+v", c.Provider.SCIM)
	}
}
