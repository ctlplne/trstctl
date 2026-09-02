// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
)

func TestSecretsMachineAuthValidation(t *testing.T) {
	c := Default()
	c.Secrets.MachineAuth = []MachineAuthMethod{
		{
			Name: "kubernetes", TenantClaim: "trstctl.io/tenant",
			Audience: "trstctl", JWKSJSON: `{"keys":[]}`, Scopes: []string{"secrets:read"},
		},
		{
			Name: "aws-iam", TenantID: "11111111-1111-1111-1111-111111111111",
			AllowedAccounts: []string{"123456789012"}, Scopes: []string{"secrets:read"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid machine_auth config rejected: %v", err)
	}

	badJWT := Default()
	badJWT.Secrets.MachineAuth = []MachineAuthMethod{{Name: "jwt", Audience: "trstctl", JWKSJSON: `{"keys":[]}`}}
	if err := badJWT.Validate(); err == nil || !strings.Contains(err.Error(), "tenant_id or tenant_claim") {
		t.Fatalf("tenantless jwt config error = %v, want tenant binding rejection", err)
	}

	badAWS := Default()
	badAWS.Secrets.MachineAuth = []MachineAuthMethod{{Name: "aws-iam", AllowedAccounts: []string{"123456789012"}}}
	if err := badAWS.Validate(); err == nil || !strings.Contains(err.Error(), "tenant_id is required for aws-iam") {
		t.Fatalf("tenantless aws config error = %v, want tenant_id rejection", err)
	}

	unscoped := Default()
	unscoped.Secrets.MachineAuth = []MachineAuthMethod{{
		Name: "oidc", TenantID: "11111111-1111-1111-1111-111111111111",
		Audience: "trstctl", JWKSJSON: `{"keys":[]}`,
	}}
	if err := unscoped.Validate(); err == nil || !strings.Contains(err.Error(), "scopes or scopes_claim") {
		t.Fatalf("unscoped oidc config error = %v, want explicit authority rejection", err)
	}

	ambiguous := Default()
	ambiguous.Secrets.MachineAuth = []MachineAuthMethod{{
		Name: "jwt", TenantID: "11111111-1111-1111-1111-111111111111",
		Audience: "trstctl", JWKSJSON: `{"keys":[]}`,
		Scopes: []string{"secrets:read"}, ScopesClaim: "permissions",
	}}
	if err := ambiguous.Validate(); err == nil || !strings.Contains(err.Error(), "must not set both scopes and scopes_claim") {
		t.Fatalf("ambiguous jwt authority error = %v, want one scope source: %v", err, err)
	}
}

func TestBuiltinMachineTokenRequiresTenantPinAndExplicitScopes(t *testing.T) {
	c := Default()
	c.Secrets.AuthSecretFile = "/run/secrets/machine-auth"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "auth_token_tenant_id") || !strings.Contains(err.Error(), "auth_token_scopes") {
		t.Fatalf("unbounded builtin token authority error = %v, want tenant and scope failures", err)
	}

	c.Secrets.AuthTokenTenantID = "11111111-1111-1111-1111-111111111111"
	c.Secrets.AuthTokenScopes = []string{" "}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "auth_token_scopes[0]") {
		t.Fatalf("blank builtin token scope error = %v, want non-empty permission rejection", err)
	}
	c.Secrets.AuthTokenScopes = []string{"secrets:read", "secrets:read"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate builtin token scope error = %v, want duplicate rejection", err)
	}
	c.Secrets.AuthTokenScopes = []string{"secrets:read"}
	if err := c.Validate(); err != nil {
		t.Fatalf("tenant-pinned, explicitly scoped builtin token config: %v", err)
	}
}
