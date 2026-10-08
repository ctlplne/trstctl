// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func TestPAMRequiresCompleteOperatorTargetReferences(t *testing.T) {
	const tenantID = "22222222-2222-4222-8222-222222222222"
	valid := PAM{Enabled: true, ApprovalTTL: "15m", RequiredApprovals: 2,
		PostgresTargets: []PAMPostgresTarget{{
			TenantID: tenantID, ID: "incident-db", ProviderID: "tenant-pg-provider",
			AllowedRoles: []string{"readonly"},
		}},
		SSHTargets: []PAMSSHTarget{{
			TenantID: tenantID, ID: "incident-host", Host: "host.lab.local", Port: 22,
			Principals: []string{"incident"},
		}},
	}
	if errs := validatePAM(valid); len(errs) != 0 {
		t.Fatalf("valid protected target refs: %v", errs)
	}
	for _, tc := range []struct {
		name string
		edit func(*PAM)
	}{
		{"no targets", func(p *PAM) { p.PostgresTargets = nil; p.SSHTargets = nil }},
		{"no provider", func(p *PAM) { p.PostgresTargets[0].ProviderID = "" }},
		{"foreign role", func(p *PAM) { p.PostgresTargets[0].AllowedRoles = []string{"superuser"} }},
		{"wildcard principal", func(p *PAM) { p.SSHTargets[0].Principals = []string{"*"} }},
		{"bad approval TTL", func(p *PAM) { p.ApprovalTTL = "garbage" }},
		{"negative quorum", func(p *PAM) { p.RequiredApprovals = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			p.PostgresTargets = append([]PAMPostgresTarget(nil), valid.PostgresTargets...)
			p.SSHTargets = append([]PAMSSHTarget(nil), valid.SSHTargets...)
			tc.edit(&p)
			if errs := validatePAM(p); len(errs) == 0 {
				t.Fatal("invalid PAM configuration passed validation")
			}
		})
	}
}
