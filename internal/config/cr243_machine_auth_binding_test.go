// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestCR243MachineAuthRequiresIssuerOrCloudBoundaryAtStartup(t *testing.T) {
	base := MachineAuthMethod{
		TenantID: "11111111-1111-1111-1111-111111111111", Audience: "trstctl",
		JWKSJSON: `{"keys":[]}`, Scopes: []string{"secrets:read"},
	}
	for _, tt := range []struct {
		name   string
		method MachineAuthMethod
		want   string
	}{
		{"gcp without project", MachineAuthMethod{Name: "gcp", Issuer: "https://accounts.google.com"}, "allowed_projects"},
		{"gcp blank project", MachineAuthMethod{Name: "gcp", AllowedProjects: []string{" "}}, "allowed_projects[0]"},
		{"azure without tenant", MachineAuthMethod{Name: "azure"}, "allowed_azure_tenants"},
		{"azure common issuer", MachineAuthMethod{Name: "azure", Issuer: "https://login.microsoftonline.com/common/v2.0"}, "allowed_azure_tenants"},
		{"azure invalid tenant", MachineAuthMethod{Name: "azure", AllowedAzureTenants: []string{"common"}}, "allowed_azure_tenants[0]"},
		{"oidc without issuer", MachineAuthMethod{Name: "oidc"}, "issuer"},
		{"jwt without issuer", MachineAuthMethod{Name: "jwt"}, "issuer"},
		{"kubernetes without issuer", MachineAuthMethod{Name: "kubernetes"}, "issuer"},
		{"gcp with project", MachineAuthMethod{Name: "gcp", AllowedProjects: []string{"project-a"}}, ""},
		{"azure with tenant allowlist", MachineAuthMethod{Name: "azure", AllowedAzureTenants: []string{"22222222-2222-2222-2222-222222222222"}}, ""},
		{"azure with tenant issuer", MachineAuthMethod{Name: "azure", Issuer: "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := base
			m.Name = tt.method.Name
			m.Issuer = tt.method.Issuer
			m.AllowedProjects = tt.method.AllowedProjects
			m.AllowedAzureTenants = tt.method.AllowedAzureTenants
			c := Default()
			c.Secrets.MachineAuth = []MachineAuthMethod{m}
			err := c.Validate()
			if tt.want == "" && err != nil {
				t.Fatalf("bound method refused: %v", err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("unbound method error = %v, want %q", err, tt.want)
			}
		})
	}
}
