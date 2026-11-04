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

// TestPAMDatabaseTargetsNameAKnownTypeAndAGateway: a database target (A256)
// names a known type, its provider and roles, and the gateway it is served
// through; ids are per type.
func TestPAMDatabaseTargetsNameAKnownTypeAndAGateway(t *testing.T) {
	const tenantID = "22222222-2222-4222-8222-222222222222"
	valid := PAM{Enabled: true,
		PostgresTargets: []PAMPostgresTarget{{TenantID: tenantID, ID: "cache", ProviderID: "tenant-pg-provider", AllowedRoles: []string{"readonly"}}},
		DatabaseTargets: []PAMDatabaseTarget{{TenantID: tenantID, ID: "cache", TargetType: "redis", ProviderID: "tenant-redis-provider",
			AllowedRoles: []string{"redis-reader"}, GatewayAgentID: "33333333-3333-4333-8333-333333333333", GatewayAddress: "gw.lab.local:7443"}},
	}
	if errs := validatePAM(valid); len(errs) != 0 {
		t.Fatalf("a Redis target beside a PostgreSQL target of the same id: %v", errs)
	}
	only := PAM{Enabled: true, DatabaseTargets: valid.DatabaseTargets}
	if errs := validatePAM(only); len(errs) != 0 {
		t.Fatalf("database targets alone: %v", errs)
	}
	for _, tc := range []struct {
		name string
		edit func(*PAMDatabaseTarget)
	}{
		{"unknown type", func(d *PAMDatabaseTarget) { d.TargetType = "couchdb" }},
		{"postgres among database targets", func(d *PAMDatabaseTarget) { d.TargetType = "postgres" }},
		{"no gateway", func(d *PAMDatabaseTarget) { d.GatewayAgentID, d.GatewayAddress = "", "" }},
		{"no gateway address", func(d *PAMDatabaseTarget) { d.GatewayAddress = "" }},
		{"no provider", func(d *PAMDatabaseTarget) { d.ProviderID = "" }},
		{"no roles", func(d *PAMDatabaseTarget) { d.AllowedRoles = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			p.DatabaseTargets = append([]PAMDatabaseTarget(nil), valid.DatabaseTargets...)
			tc.edit(&p.DatabaseTargets[0])
			if errs := validatePAM(p); len(errs) == 0 {
				t.Fatal("an invalid database target passed validation")
			}
		})
	}
	dup := valid
	dup.DatabaseTargets = append(append([]PAMDatabaseTarget(nil), valid.DatabaseTargets...), valid.DatabaseTargets...)
	if errs := validatePAM(dup); len(errs) == 0 {
		t.Fatal("a repeated Redis target id passed validation")
	}
}

// TestPAMKubernetesTargetsNameAProviderAndAGateway: a Kubernetes target
// (A256) names its provider, roles and the gateway it is served through.
func TestPAMKubernetesTargetsNameAProviderAndAGateway(t *testing.T) {
	const tenantID = "22222222-2222-4222-8222-222222222222"
	valid := PAM{Enabled: true, KubernetesTargets: []PAMKubernetesTarget{{TenantID: tenantID, ID: "apps", ProviderID: "tenant-k8s",
		AllowedRoles: []string{"operator"}, GatewayAgentID: "33333333-3333-4333-8333-333333333333", GatewayAddress: "gw.lab.local:7443"}}}
	if errs := validatePAM(valid); len(errs) != 0 {
		t.Fatalf("a Kubernetes target alone: %v", errs)
	}
	for _, tc := range []struct {
		name string
		edit func(*PAMKubernetesTarget)
	}{
		{"no gateway", func(k *PAMKubernetesTarget) { k.GatewayAgentID, k.GatewayAddress = "", "" }},
		{"no provider", func(k *PAMKubernetesTarget) { k.ProviderID = "" }},
		{"no roles", func(k *PAMKubernetesTarget) { k.AllowedRoles = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			p.KubernetesTargets = append([]PAMKubernetesTarget(nil), valid.KubernetesTargets...)
			tc.edit(&p.KubernetesTargets[0])
			if errs := validatePAM(p); len(errs) == 0 {
				t.Fatal("an invalid Kubernetes target passed validation")
			}
		})
	}
	dup := valid
	dup.KubernetesTargets = append(append([]PAMKubernetesTarget(nil), valid.KubernetesTargets...), valid.KubernetesTargets...)
	if errs := validatePAM(dup); len(errs) == 0 {
		t.Fatal("a repeated Kubernetes target id passed validation")
	}
}
