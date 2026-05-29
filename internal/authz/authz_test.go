package authz_test

import (
	"testing"

	"certctl.io/certctl/internal/authz"
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
