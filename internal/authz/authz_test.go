// SPDX-License-Identifier: MPL-2.0

package authz_test

import (
	"reflect"
	"sort"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestRoleAllows(t *testing.T) {
	roles := authz.BuiltinRoles()
	admin, viewer, operator := roles["admin"], roles["viewer"], roles["operator"]

	if !admin.Allows(authz.IdentitiesWrite) || !admin.Allows(authz.OwnersWrite) {
		t.Error("admin (wildcard) must allow everything")
	}
	if !viewer.Allows(authz.IdentitiesRead) {
		t.Error("viewer must allow reads")
	}
	if viewer.Allows(authz.IdentitiesWrite) {
		t.Error("viewer must not allow writes")
	}
	if !operator.Allows(authz.IdentitiesWrite) || !operator.Allows(authz.OwnersWrite) {
		t.Error("operator must allow resource writes")
	}
}

func TestScopeCoverage(t *testing.T) {
	tenantWide := authz.Scope{TenantID: "t1"}
	project := authz.Scope{TenantID: "t1", Project: "alpha"}

	if !tenantWide.Covers(authz.Scope{TenantID: "t1", Project: "alpha"}) {
		t.Error("a tenant-wide grant must cover any project in the tenant")
	}
	if !tenantWide.Covers(authz.Scope{TenantID: "t1"}) {
		t.Error("a tenant-wide grant must cover the tenant-wide target")
	}
	if !project.Covers(authz.Scope{TenantID: "t1", Project: "alpha"}) {
		t.Error("a project grant must cover its own project")
	}
	if project.Covers(authz.Scope{TenantID: "t1", Project: "beta"}) {
		t.Error("a project grant must not cover a different project")
	}
	if project.Covers(authz.Scope{TenantID: "t1"}) {
		t.Error("a project grant must not cover a tenant-wide target")
	}
	if tenantWide.Covers(authz.Scope{TenantID: "t2", Project: "alpha"}) {
		t.Error("a grant must never cover another tenant")
	}
}

func TestPrincipalCanRoleAndScope(t *testing.T) {
	operator := authz.BuiltinRoles()["operator"]
	p := authz.Principal{
		TenantID: "t1", Subject: "svc",
		Grants: []authz.Grant{{Role: operator, Scope: authz.Scope{TenantID: "t1", Project: "alpha"}}},
	}
	if !p.Can(authz.IdentitiesWrite, authz.Scope{TenantID: "t1", Project: "alpha"}) {
		t.Error("operator scoped to alpha must be allowed to write in alpha")
	}
	if p.Can(authz.IdentitiesWrite, authz.Scope{TenantID: "t1", Project: "beta"}) {
		t.Error("operator scoped to alpha must be denied in beta")
	}
	if p.Can(authz.IdentitiesWrite, authz.Scope{TenantID: "t1"}) {
		t.Error("a project-scoped operator must be denied a tenant-wide target")
	}
}

func TestPrincipalCanProfileAndIssuerScopes(t *testing.T) {
	roleIssuer := authz.Role{Name: "issuer", Permissions: []authz.Permission{authz.CertsIssue, authz.IssuersWrite}}
	p := authz.Principal{
		TenantID: "t1", Subject: "svc",
		Grants: []authz.Grant{
			{Role: roleIssuer, Scope: authz.Scope{TenantID: "t1", Profile: "tls-prod"}},
			{Role: roleIssuer, Scope: authz.Scope{TenantID: "t1", Issuer: "issuer-prod"}},
		},
	}
	if !p.Can(authz.CertsIssue, authz.Scope{TenantID: "t1", Profile: "tls-prod"}) {
		t.Fatal("profile-scoped role must issue with the matching profile")
	}
	if p.Can(authz.CertsIssue, authz.Scope{TenantID: "t1", Profile: "tls-dev"}) {
		t.Fatal("profile-scoped role must not issue with another profile")
	}
	if p.Can(authz.CertsIssue, authz.Scope{TenantID: "t1"}) {
		t.Fatal("profile-scoped role must not authorize tenant-wide issue")
	}
	if !p.Can(authz.IssuersWrite, authz.Scope{TenantID: "t1", Issuer: "issuer-prod"}) {
		t.Fatal("issuer-scoped role must manage the matching issuer")
	}
	if p.Can(authz.IssuersWrite, authz.Scope{TenantID: "t1", Issuer: "issuer-dev"}) {
		t.Fatal("issuer-scoped role must not manage another issuer")
	}
	if p.Can(authz.IssuersWrite, authz.Scope{TenantID: "t2", Issuer: "issuer-prod"}) {
		t.Fatal("issuer scope must never cross the tenant boundary")
	}
}

func TestPrincipalCanTenantBoundary(t *testing.T) {
	admin := authz.BuiltinRoles()["admin"]
	p := authz.Principal{
		TenantID: "t1",
		Grants:   []authz.Grant{{Role: admin, Scope: authz.Scope{TenantID: "t1"}}},
	}
	if p.Can(authz.OwnersRead, authz.Scope{TenantID: "t2"}) {
		t.Error("even admin must be denied across tenant boundaries")
	}
}

// TestPrincipalCanDeniesOnTenantMismatchIndependentOfGrants is the M1 mutation
// guard (TEST-AUTHZ-XTENANT-001). It isolates the Principal.Can tenant check:
// an adversarial principal whose OWN tenant differs from the target must be
// denied even when it holds a grant scoped to the target tenant. Because
// Scope.Covers ALSO checks tenant, only a grant that references the target
// tenant can reach — and expose — the Principal.Can guard; removing that guard
// (the M1 mutant) makes exactly these rows pass, so the suite must fail.
func TestPrincipalCanDeniesOnTenantMismatchIndependentOfGrants(t *testing.T) {
	admin := authz.BuiltinRoles()["admin"]
	for _, tc := range []struct {
		name         string
		principal    string
		grantTenant  string
		targetTenant string
		wantAllowed  bool
	}{
		{"principal-tenant-matches-target", "t1", "t1", "t1", true},
		{"principal-tenant-differs-but-holds-target-grant", "t1", "t2", "t2", false},
		{"principal-and-grant-in-t1-target-t2", "t1", "t1", "t2", false},
		{"principal-t2-grant-and-target-t1", "t2", "t1", "t1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := authz.Principal{
				TenantID: tc.principal,
				Grants:   []authz.Grant{{Role: admin, Scope: authz.Scope{TenantID: tc.grantTenant}}},
			}
			got := p.Can(authz.OwnersRead, authz.Scope{TenantID: tc.targetTenant})
			if got != tc.wantAllowed {
				t.Fatalf("Can(tenant=%s, grant=%s, target=%s) = %v, want %v — the principal's OWN tenant must gate access, not merely the grant it carries",
					tc.principal, tc.grantTenant, tc.targetTenant, got, tc.wantAllowed)
			}
		})
	}
}

func TestCustomRole(t *testing.T) {
	deployer := authz.Role{Name: "deployer", Permissions: []authz.Permission{authz.IdentitiesRead, authz.IdentitiesWrite}}
	reg := authz.NewRegistry(deployer)

	got, ok := reg.Role("deployer")
	if !ok {
		t.Fatal("custom role not found in registry")
	}
	if _, ok := reg.Role("admin"); !ok {
		t.Error("registry must still expose built-in roles")
	}

	p := authz.Principal{
		TenantID: "t1",
		Grants:   []authz.Grant{{Role: got, Scope: authz.Scope{TenantID: "t1"}}},
	}
	if !p.Can(authz.IdentitiesWrite, authz.Scope{TenantID: "t1"}) {
		t.Error("custom deployer role must grant identities:write")
	}
	if p.Can(authz.OwnersWrite, authz.Scope{TenantID: "t1"}) {
		t.Error("custom deployer role must not grant owners:write")
	}
}

func TestPrincipalWithoutGrantsIsDenied(t *testing.T) {
	p := authz.Principal{TenantID: "t1"}
	if p.Can(authz.OwnersRead, authz.Scope{TenantID: "t1"}) {
		t.Error("a principal with no grants must be denied")
	}
}

// TestRegistrationAuthoritySeparation is the S8.1 RA acceptance: the registration
// authority may REQUEST a certificate (and author profiles) but may NOT
// approve/issue one — a requester cannot self-issue. An operator/approver can.
func TestRegistrationAuthoritySeparation(t *testing.T) {
	scope := authz.Scope{TenantID: "t1"}
	ra := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: authz.BuiltinRoles()["ra-officer"], Scope: scope}}}
	op := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: authz.BuiltinRoles()["operator"], Scope: scope}}}

	if !ra.Can(authz.CertsRequest, scope) {
		t.Error("ra-officer must be able to request certificates")
	}
	if !ra.Can(authz.ProfilesWrite, scope) {
		t.Error("ra-officer must be able to author profiles")
	}
	if !ra.Can(authz.OwnersRead, scope) {
		t.Error("ra-officer must be able to choose an accountable tenant owner for a request")
	}
	if ra.Can(authz.IdentitiesWrite, scope) {
		t.Error("SEPARATION VIOLATED: ra-officer must open a request, not create an identity directly")
	}
	if ra.Can(authz.CertsIssue, scope) {
		t.Error("SEPARATION VIOLATED: ra-officer must NOT be able to self-issue (certs:issue)")
	}
	if !op.Can(authz.CertsIssue, scope) {
		t.Error("operator (approver) must be able to issue certificates")
	}
}

func TestAccessRoleAssignIsDedicatedPermission(t *testing.T) {
	scope := authz.Scope{TenantID: "t1"}
	memberWriter := authz.Role{Name: "member-writer", Permissions: []authz.Permission{authz.AccessWrite}}
	roleAssigner := authz.Role{Name: "role-assigner", Permissions: []authz.Permission{authz.AccessWrite, authz.AccessRoleAssign}}

	writer := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: memberWriter, Scope: scope}}}
	assigner := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: roleAssigner, Scope: scope}}}

	if !writer.Can(authz.AccessWrite, scope) {
		t.Fatal("member-writer must retain access:write")
	}
	if writer.Can(authz.AccessRoleAssign, scope) {
		t.Fatal("access:write alone must not imply access:role.assign")
	}
	if !assigner.Can(authz.AccessRoleAssign, scope) {
		t.Fatal("role-assigner must hold access:role.assign")
	}
}

func TestPrivateEgressIsDedicatedPermission(t *testing.T) {
	scope := authz.Scope{TenantID: "t1"}
	incidentWriter := authz.Role{Name: "incident-writer", Permissions: []authz.Permission{authz.IncidentsWrite}}
	privateEgressWriter := authz.Role{Name: "private-egress", Permissions: []authz.Permission{authz.IncidentsWrite, authz.PrivateEgress}}

	writer := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: incidentWriter, Scope: scope}}}
	egressWriter := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: privateEgressWriter, Scope: scope}}}

	if !writer.Can(authz.IncidentsWrite, scope) {
		t.Fatal("incident writer must retain incidents:write")
	}
	if writer.Can(authz.PrivateEgress, scope) {
		t.Fatal("incidents:write alone must not imply egress:private")
	}
	if !egressWriter.Can(authz.PrivateEgress, scope) {
		t.Fatal("private egress role must hold egress:private")
	}
}

func TestIncidentGameDayIsDedicatedPermissionAUD41(t *testing.T) {
	scope := authz.Scope{TenantID: "t1"}
	incidentWriter := authz.Role{Name: "incident-writer", Permissions: []authz.Permission{authz.IncidentsWrite}}
	rehearsalWriter := authz.Role{Name: "rehearsal-writer", Permissions: []authz.Permission{authz.IncidentsWrite, authz.IncidentsGameDay}}

	writer := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: incidentWriter, Scope: scope}}}
	rehearsal := authz.Principal{TenantID: "t1", Grants: []authz.Grant{{Role: rehearsalWriter, Scope: scope}}}
	if writer.Can(authz.IncidentsGameDay, scope) {
		t.Fatal("incidents:write alone must not authorize a game-day run")
	}
	if !rehearsal.Can(authz.IncidentsGameDay, scope) {
		t.Fatal("the dedicated rehearsal permission must authorize a game-day run")
	}
}

func TestMachineBuiltinRolesPinned(t *testing.T) {
	want := map[string][]authz.Permission{
		"agent": {
			authz.CertsRead,
			authz.AgentsHeartbeat,
			authz.AgentsJobPoll,
			authz.AgentsJobComplete,
			authz.AgentsJobReport,
			authz.DiscoveryWrite,
		},
		"mcp": {
			authz.OwnersRead,
			authz.IssuersRead,
			authz.IdentitiesRead,
			authz.CertsRead,
			authz.AuditRead,
			authz.PrivacyRead,
			authz.GraphRead,
			authz.RiskRead,
			authz.AgentsRead,
			authz.DiscoveryRead,
			authz.DiscoveryWrite,
			authz.NHIRead,
			authz.PolicyRead,
			authz.NotificationsRead,
			authz.ConnectorsRead,
			authz.LifecycleRead,
			authz.IncidentsRead,
			authz.CapabilitiesRead,
			authz.AccessRead,
			authz.ProfilesRead,
			authz.CertsRequest,
			authz.SecretsRead,
			authz.KeysRead,
		},
		"cli": {
			authz.OwnersRead,
			authz.OwnersWrite,
			authz.IssuersRead,
			authz.IssuersWrite,
			authz.IdentitiesRead,
			authz.IdentitiesWrite,
			authz.CertsRead,
			authz.CertsWrite,
			authz.AuditRead,
			authz.AuditWrite,
			authz.PrivacyRead,
			authz.PrivacyWrite,
			authz.GraphRead,
			authz.RiskRead,
			authz.AgentsRead,
			authz.AgentsWrite,
			authz.AgentsHeartbeat,
			authz.AgentsJobPoll,
			authz.AgentsJobComplete,
			authz.AgentsJobReport,
			authz.DiscoveryRead,
			authz.DiscoveryWrite,
			authz.NHIRead,
			authz.PolicyRead,
			authz.PolicyWrite,
			authz.NotificationsRead,
			authz.NotificationsWrite,
			authz.ConnectorsRead,
			authz.ConnectorsWrite,
			authz.LifecycleRead,
			authz.IncidentsRead,
			authz.IncidentsWrite,
			authz.IncidentsGameDay,
			authz.PrivateEgress,
			authz.CapabilitiesRead,
			authz.AccessRead,
			authz.AccessWrite,
			authz.ProfilesRead,
			authz.ProfilesWrite,
			authz.CertsRequest,
			authz.CertsIssue,
			authz.SecretsRead,
			authz.SecretsWrite,
			authz.KeysRead,
			authz.KeysWrite,
			authz.KeysApprove,
		},
	}
	roles := authz.BuiltinRoles()
	for name, wantPerms := range want {
		role, ok := roles[name]
		if !ok {
			t.Fatalf("machine role %q missing from BuiltinRoles", name)
		}
		got := sortedPermissions(role.Permissions)
		wantSorted := sortedPermissions(wantPerms)
		if !reflect.DeepEqual(got, wantSorted) {
			t.Fatalf("%s permissions = %v, want exactly %v", name, got, wantSorted)
		}
	}
}

func sortedPermissions(in []authz.Permission) []authz.Permission {
	out := append([]authz.Permission(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
