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
			Audience: "trstctl", JWKSJSON: `{"keys":[]}`,
		},
		{
			Name: "aws-iam", TenantID: "11111111-1111-1111-1111-111111111111",
			AllowedAccounts: []string{"123456789012"},
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
}
