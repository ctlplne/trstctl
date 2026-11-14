// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// N3-L1: the denial credential belongs to an aws-sts provider with
// revoke_with_deny_policy, names both an access key ID and a secret reference,
// and its references are credential references.
func TestValidateDenialCredentialN3L1(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	base := func() DynamicSecretProviderConfig {
		return DynamicSecretProviderConfig{TenantID: tenant, ID: "aws", Type: "aws-sts", Endpoint: "https://sts.us-east-1.amazonaws.com",
			Region: "us-east-1", AccessKeyID: "AKIDISSUER", SecretAccessRef: "file:/var/lib/trstctl/issuer", MaxTTL: "1h", // #nosec G101 -- test-only file reference paths, no credential values (CWE-798)
			AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:role/reader"},
			RevokeWithDenyPolicy: true, DenyAccessKeyID: "AKIDDENIER", DenySecretAccessRef: "file:/var/lib/trstctl/denier"} // #nosec G101 -- test-only file reference paths, no credential values (CWE-798)
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{base()}}, true); err != nil {
		t.Fatalf("a valid denial credential was rejected: %v", err)
	}
	for name, c := range map[string]struct {
		edit func(*DynamicSecretProviderConfig)
		want string
	}{
		"no deny policy":   {func(c *DynamicSecretProviderConfig) { c.RevokeWithDenyPolicy = false }, "only valid for aws-sts with revoke_with_deny_policy"},
		"no secret":        {func(c *DynamicSecretProviderConfig) { c.DenySecretAccessRef = "" }, "needs both deny_access_key_id and deny_secret_access_key_ref"},
		"no key ID":        {func(c *DynamicSecretProviderConfig) { c.DenyAccessKeyID = "" }, "needs both deny_access_key_id and deny_secret_access_key_ref"},
		"an inline secret": {func(c *DynamicSecretProviderConfig) { c.DenySecretAccessRef = "plain-value" }, "deny_secret_access_key_ref"},
		"a bad token ref":  {func(c *DynamicSecretProviderConfig) { c.DenySessionTokenRef = "plain-value" }, "deny_session_token_ref"},
	} {
		cfg := base()
		c.edit(&cfg)
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{cfg}}, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v; want an error naming %q", name, err, c.want)
		}
	}
}
