// Package authz implements role-based access control (F8): permissions, roles
// (built-in and custom), project/team scopes, and the allow/deny decision. It is
// a pure decision engine — it holds no transport or storage concerns — so the API
// enforcement middleware and any future caller share one authorization model.
//
// A Principal carries the role grants resolved for a request; each Grant pairs a
// Role with the Scope it applies in. Authorization succeeds only when a grant's
// scope covers the target and its role allows the permission, and never across a
// tenant boundary.
package authz

import "sort"

// Permission is an action on a resource, named "<resource>:<verb>".
type Permission string

// Well-known permissions for the v1 resources.
const (
	OwnersRead       Permission = "owners:read"
	OwnersWrite      Permission = "owners:write"
	IssuersRead      Permission = "issuers:read"
	IssuersWrite     Permission = "issuers:write"
	IdentitiesRead   Permission = "identities:read"
	IdentitiesWrite  Permission = "identities:write"
	CertsRead        Permission = "certs:read"
	CertsWrite       Permission = "certs:write"
	AuditRead        Permission = "audit:read"
	PrivacyRead      Permission = "privacy:read"
	PrivacyWrite     Permission = "privacy:write"
	GraphRead        Permission = "graph:read"
	RiskRead         Permission = "risk:read"
	AgentsRead       Permission = "agents:read"
	AgentsWrite      Permission = "agents:write"
	DiscoveryRead    Permission = "discovery:read"
	DiscoveryWrite   Permission = "discovery:write"
	ConnectorsRead   Permission = "connectors:read"
	LifecycleRead    Permission = "lifecycle:read"
	IncidentsRead    Permission = "incidents:read"
	IncidentsWrite   Permission = "incidents:write"
	AccessRead       Permission = "access:read"
	AccessWrite      Permission = "access:write"
	AccessRoleAssign Permission = "access:role.assign"

	// Secrets-surface permissions (GAP-006 served secrets API). SecretsRead reads a
	// stored secret's value; SecretsWrite creates/rotates/deletes a secret, mints a
	// one-time share, and issues a dynamic PKI secret. The machine-login route
	// (POST /api/v1/secrets/auth/login) is PUBLIC (it authenticates a credential and
	// is the entry point for an unauthenticated workload), so it carries no
	// permission here.
	SecretsRead  Permission = "secrets:read"
	SecretsWrite Permission = "secrets:write"

	// Certificate-profile and registration-authority permissions (S8.1). The RA
	// model separates who may REQUEST a certificate (CertsRequest) from who may
	// APPROVE/ISSUE it (CertsIssue), so a requester cannot self-issue.
	ProfilesRead  Permission = "profiles:read"
	ProfilesWrite Permission = "profiles:write"
	CertsRequest  Permission = "certs:request"
	CertsIssue    Permission = "certs:issue"

	// Managed-key (BYOK/HSM) lifecycle permissions (CRYPTO-005 / EXC-CRYPTO-01).
	// KeysRead lists managed keys; KeysWrite drives the remote-custody lifecycle
	// (generate/rotate/revoke/zeroize). The destructive transitions additionally
	// require a distinct-approver approval (dual control) enforced by the served
	// gate — KeysWrite alone never authorizes a one-person rotate/revoke/zeroize.
	KeysRead  Permission = "keys:read"
	KeysWrite Permission = "keys:write"
)

// Wildcard is a permission that allows every action; it is held by admin.
const Wildcard Permission = "*"

// allResourcePermissions is every concrete (non-wildcard) permission.
func allResourcePermissions() []Permission {
	return []Permission{
		OwnersRead, OwnersWrite, IssuersRead, IssuersWrite,
		IdentitiesRead, IdentitiesWrite, CertsRead, CertsWrite,
		PrivacyRead, PrivacyWrite,
		GraphRead, RiskRead, AgentsRead, AgentsWrite,
		DiscoveryRead, DiscoveryWrite, ConnectorsRead, LifecycleRead,
		IncidentsRead, IncidentsWrite,
		AccessRead, AccessWrite, AccessRoleAssign,
		ProfilesRead, ProfilesWrite, CertsRequest, CertsIssue,
		SecretsRead, SecretsWrite,
		KeysRead, KeysWrite,
	}
}

// Role is a named set of permissions.
type Role struct {
	Name        string
	Permissions []Permission
}

// Allows reports whether the role grants the permission (Wildcard grants all).
func (r Role) Allows(p Permission) bool {
	for _, have := range r.Permissions {
		if have == Wildcard || have == p {
			return true
		}
	}
	return false
}

// BuiltinRoles returns the platform's built-in roles: admin (everything),
// operator (read+write on resources), viewer (read-only), and auditor (read of
// the audit log).
func BuiltinRoles() map[string]Role {
	readOnly := []Permission{OwnersRead, IssuersRead, IdentitiesRead, CertsRead, PrivacyRead, GraphRead, RiskRead, AgentsRead, DiscoveryRead, ConnectorsRead, LifecycleRead, IncidentsRead, AccessRead, ProfilesRead, SecretsRead, KeysRead}
	return map[string]Role{
		"admin":    {Name: "admin", Permissions: []Permission{Wildcard}},
		"operator": {Name: "operator", Permissions: allResourcePermissions()},
		"viewer":   {Name: "viewer", Permissions: readOnly},
		"auditor":  {Name: "auditor", Permissions: []Permission{AuditRead}},
		// Registration authority: may author/read profiles and REQUEST certificates,
		// but may NOT approve/issue them (no certs:issue) — the RA separation (S8.1).
		"ra-officer": {Name: "ra-officer", Permissions: []Permission{ProfilesRead, ProfilesWrite, CertsRead, CertsRequest}},
	}
}

// Scope is the reach of a grant or the target of a request: a tenant, optionally
// narrowed to a project/team. An empty Project means tenant-wide.
type Scope struct {
	TenantID string
	Project  string
}

// Covers reports whether a grant with scope g authorizes an action targeting t.
// It never crosses a tenant boundary; a tenant-wide grant covers any project,
// while a project grant covers only that exact project.
func (g Scope) Covers(t Scope) bool {
	if g.TenantID != t.TenantID {
		return false
	}
	return g.Project == "" || g.Project == t.Project
}

// Grant binds a role to the scope it applies in.
type Grant struct {
	Role  Role
	Scope Scope
}

// Principal is an authenticated caller with its resolved grants.
type Principal struct {
	TenantID string
	Subject  string
	Grants   []Grant
}

// Can reports whether the principal may perform perm on a target scope. It
// requires the principal's tenant to match the target's, then a grant whose
// scope covers the target and whose role allows the permission.
func (p Principal) Can(perm Permission, target Scope) bool {
	if p.TenantID != target.TenantID {
		return false
	}
	for _, g := range p.Grants {
		if g.Scope.Covers(target) && g.Role.Allows(perm) {
			return true
		}
	}
	return false
}

// Registry is the catalog of role definitions — the built-in roles plus any
// custom (tenant-defined) roles. Custom roles are added by name and override a
// built-in of the same name.
type Registry struct {
	roles map[string]Role
}

// NewRegistry returns a registry of the built-in roles plus the given custom
// roles.
func NewRegistry(custom ...Role) *Registry {
	roles := BuiltinRoles()
	for _, r := range custom {
		roles[r.Name] = r
	}
	return &Registry{roles: roles}
}

// Role returns the named role and whether it exists.
func (r *Registry) Role(name string) (Role, bool) {
	role, ok := r.roles[name]
	return role, ok
}

// Roles returns the registered role catalog in stable name order.
func (r *Registry) Roles() []Role {
	if r == nil {
		return nil
	}
	roles := make([]Role, 0, len(r.roles))
	for _, role := range r.roles {
		copied := Role{Name: role.Name, Permissions: append([]Permission(nil), role.Permissions...)}
		roles = append(roles, copied)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles
}
