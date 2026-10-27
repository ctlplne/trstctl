// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A90: arbitrary custom Provider operator roles.
//
// The Provider plane knew two roles, admin and operator, and every mutation
// asked "is this an admin?". That question is now "does this operator hold
// this permission?", drawn from a closed vocabulary below. admin and operator
// remain built in; a Provider admin defines further roles as named subsets of
// the vocabulary, recorded as immutable authority events and projected into
// provider_roles. An operator's effective permissions are the role's set
// intersected with the ceiling the signed IdP role allows, so a custom role
// never grants what the IdP would not.

// Permission is one Provider-plane right.
type Permission string

const (
	PermTenantsProvision  Permission = "tenants:provision"
	PermTenantsLifecycle  Permission = "tenants:lifecycle"
	PermQuotaWrite        Permission = "quota:write"
	PermBrandWrite        Permission = "brand:write"
	PermOperatorsAdmin    Permission = "operators:admin"
	PermRolesAdmin        Permission = "roles:admin"
	PermIsolationDrill    Permission = "isolation:drill"
	PermBreakGlassRequest Permission = "breakglass:request"
	PermBreakGlassConsent Permission = "breakglass:consent"
	PermBreakGlassResults Permission = "breakglass:results"
	PermTemplatesWrite    Permission = "templates:write"
)

// PermissionDescription is the served vocabulary entry.
type PermissionDescription struct {
	Name        Permission `json:"name"`
	Description string     `json:"description"`
}

// ProviderPermissions is the closed vocabulary a custom role draws from. Reads
// (customer list, health, activity within a delegation) need no permission
// beyond being an active operator; every mutation names one of these.
var ProviderPermissions = []PermissionDescription{
	{PermTenantsProvision, "Provision a delegated customer."},
	{PermTenantsLifecycle, "Suspend, resume or offboard a delegated customer."},
	{PermQuotaWrite, "Set a delegated customer's quota."},
	{PermBrandWrite, "Replace a delegated customer's brand."},
	{PermOperatorsAdmin, "Read the workforce and grant, revoke or set another operator's delegations and role."},
	{PermRolesAdmin, "Define or delete custom Provider roles."},
	{PermIsolationDrill, "Run the customer isolation drill."},
	{PermBreakGlassRequest, "Request time-bounded emergency customer access."},
	{PermBreakGlassConsent, "Record a custodian decision on an emergency request."},
	{PermBreakGlassResults, "Read an active two-custodian emergency snapshot."},
	{PermTemplatesWrite, "Record tenant templates, apply them to delegated customers and roll out new versions."},
}

var permissionSet = func() map[Permission]bool {
	out := make(map[Permission]bool, len(ProviderPermissions))
	for _, p := range ProviderPermissions {
		out[p.Name] = true
	}
	return out
}()

// builtInPermissions is what the two built-in roles always meant: admin holds
// everything; operator holds the break-glass trio and nothing else.
func builtInPermissions(role OperatorRole) []Permission {
	switch role {
	case OperatorAdmin:
		out := make([]Permission, 0, len(ProviderPermissions))
		for _, p := range ProviderPermissions {
			out = append(out, p.Name)
		}
		return out
	case OperatorOperator:
		return []Permission{PermBreakGlassRequest, PermBreakGlassConsent, PermBreakGlassResults}
	}
	return nil
}

// ProviderRole is one named role: built in, or defined by a Provider admin.
type ProviderRole struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	BuiltIn     bool         `json:"built_in"`
	CreatedBy   string       `json:"created_by,omitempty"`
	CreatedAt   time.Time    `json:"created_at,omitzero"`
	UpdatedAt   time.Time    `json:"updated_at,omitzero"`
}

// RoleDefinition is the request body of PUT /provider/v1/roles/{name}.
type RoleDefinition struct {
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// RoleCatalog is the response of GET /provider/v1/roles.
type RoleCatalog struct {
	Roles       []ProviderRole          `json:"roles"`
	Permissions []PermissionDescription `json:"permissions"`
}

// RoleStore reads the projected custom roles. PGAccessStore implements it;
// an access store without it serves the built-in roles only.
type RoleStore interface {
	ListRoles(context.Context) ([]ProviderRole, error)
}

const (
	EventRoleUpserted = "provider.role.upserted"
	EventRoleDeleted  = "provider.role.deleted"
)

var (
	ErrRoleInvalid = errors.New("provider: role definition is invalid")
	ErrRoleBuiltIn = errors.New("provider: admin and operator are built in and cannot be redefined or deleted")
	ErrRoleInUse   = errors.New("provider: role is still assigned")
	ErrRoleUnknown = errors.New("provider: role is not defined")
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

func builtInRole(role OperatorRole) bool { return role == OperatorAdmin || role == OperatorOperator }

func builtInRoles() []ProviderRole {
	return []ProviderRole{
		{Name: string(OperatorAdmin), Description: "Every Provider permission.", Permissions: builtInPermissions(OperatorAdmin), BuiltIn: true},
		{Name: string(OperatorOperator), Description: "Emergency access request, consent and results only.", Permissions: builtInPermissions(OperatorOperator), BuiltIn: true},
	}
}

// effectiveRole combines the signed IdP role with the directory row. A built-in
// row keeps the old lesser-of rule; a custom row keeps its name and records
// the IdP role as the ceiling its permissions are later intersected with.
func effectiveRole(idp, row OperatorRole) (role, ceiling OperatorRole) {
	if !validOperatorRole(idp) {
		return "", ""
	}
	if builtInRole(row) {
		lesser := lesserRole(idp, row)
		return lesser, lesser
	}
	if strings.TrimSpace(string(row)) == "" {
		return "", ""
	}
	return row, idp
}

func (s *Service) roleStore() RoleStore {
	if s == nil || s.access == nil {
		return nil
	}
	store, _ := s.access.(RoleStore)
	return store
}

func (s *Service) definedRoles(ctx context.Context) (map[string]ProviderRole, error) {
	out := map[string]ProviderRole{}
	store := s.roleStore()
	if store == nil {
		return out, nil
	}
	roles, err := store.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		out[role.Name] = role
	}
	return out, nil
}

// roleKnown reports whether a role may be stored on an operator: built in, or
// currently defined.
func (s *Service) roleKnown(ctx context.Context, role OperatorRole) (bool, error) {
	if builtInRole(role) {
		return true, nil
	}
	defined, err := s.definedRoles(ctx)
	if err != nil {
		return false, err
	}
	_, ok := defined[string(role)]
	return ok, nil
}

// permissionsFor resolves what an authenticated operator may do right now:
// the role's permissions intersected with the IdP ceiling. A custom role that
// has been deleted since the session was issued grants nothing; a missing
// ceiling is read as the operator ceiling, never as none.
func (s *Service) permissionsFor(ctx context.Context, actor Operator) (map[Permission]bool, error) {
	out := map[Permission]bool{}
	if builtInRole(actor.Role) {
		for _, p := range builtInPermissions(actor.Role) {
			out[p] = true
		}
		return out, nil
	}
	defined, err := s.definedRoles(ctx)
	if err != nil {
		return nil, err
	}
	role, ok := defined[string(actor.Role)]
	if !ok {
		return out, nil
	}
	ceiling := actor.Ceiling
	if !builtInRole(ceiling) {
		ceiling = OperatorOperator
	}
	allowed := map[Permission]bool{}
	for _, p := range builtInPermissions(ceiling) {
		allowed[p] = true
	}
	for _, p := range role.Permissions {
		if allowed[p] {
			out[p] = true
		}
	}
	return out, nil
}

// requirePermission is the one gate every Provider mutation passes: licence
// mode, an authenticated MFA operator, and the named permission.
func (s *Service) requirePermission(ctx context.Context, actor Operator, perm Permission) error {
	if err := s.requireMutationLicence(); err != nil {
		return err
	}
	if err := s.requireOperator(actor); err != nil {
		return err
	}
	perms, err := s.permissionsFor(ctx, actor)
	if err != nil {
		return err
	}
	if !perms[perm] {
		return ErrForbidden
	}
	return nil
}

// ListRoles serves the catalog to anyone who may read the workforce.
func (s *Service) ListRoles(ctx context.Context, actor Operator) (RoleCatalog, error) {
	if err := s.requireAdminAccessRead(ctx, actor); err != nil {
		return RoleCatalog{}, err
	}
	defined, err := s.definedRoles(ctx)
	if err != nil {
		return RoleCatalog{}, err
	}
	roles := builtInRoles()
	names := make([]string, 0, len(defined))
	for name := range defined {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		roles = append(roles, defined[name])
	}
	return RoleCatalog{Roles: roles, Permissions: ProviderPermissions}, nil
}

// UpsertRole defines or replaces a custom role as an immutable authority event.
func (s *Service) UpsertRole(ctx context.Context, actor Operator, name string, def RoleDefinition) (ProviderRole, error) {
	if err := s.requirePermission(ctx, actor, PermRolesAdmin); err != nil {
		return ProviderRole{}, err
	}
	name = strings.TrimSpace(name)
	if builtInRole(OperatorRole(name)) {
		return ProviderRole{}, ErrRoleBuiltIn
	}
	if !roleNamePattern.MatchString(name) {
		return ProviderRole{}, fmt.Errorf("%w: name must be 2-64 lower-case letters, digits or hyphens starting with a letter", ErrRoleInvalid)
	}
	if s.roleStore() == nil {
		return ProviderRole{}, errors.New("provider: custom roles need the PostgreSQL operator access store")
	}
	seen := map[Permission]bool{}
	perms := make([]Permission, 0, len(def.Permissions))
	for _, p := range def.Permissions {
		p = Permission(strings.TrimSpace(string(p)))
		if !permissionSet[p] {
			return ProviderRole{}, fmt.Errorf("%w: unknown permission %q", ErrRoleInvalid, string(p))
		}
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		return ProviderRole{}, fmt.Errorf("%w: a role needs at least one permission", ErrRoleInvalid)
	}
	if len(def.Description) > 512 {
		return ProviderRole{}, fmt.Errorf("%w: description is longer than 512 characters", ErrRoleInvalid)
	}
	defined, err := s.definedRoles(ctx)
	if err != nil {
		return ProviderRole{}, err
	}
	now := s.clock().UTC()
	role := ProviderRole{Name: name, Description: strings.TrimSpace(def.Description), Permissions: perms, CreatedBy: actor.ID, CreatedAt: now, UpdatedAt: now}
	if existing, ok := defined[name]; ok {
		role.CreatedBy, role.CreatedAt = existing.CreatedBy, existing.CreatedAt
	}
	if _, err := s.emit(ctx, EventRoleUpserted, providerAuthorityTenant, AuthorityEvent{
		Role: &role, EffectiveAt: now,
		Audit: AuditEvent{Type: EventRoleUpserted, TenantID: providerAuthorityTenant,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Subject: name,
			Reason: "provider role defined with " + strings.Join(permissionStrings(perms), ","), At: now},
	}); err != nil {
		return ProviderRole{}, err
	}
	return role, nil
}

// DeleteRole removes a custom role nobody holds. A role still on an active
// operator is refused by name, so a deletion never silently strips access the
// operator's next request would then be refused for without explanation.
func (s *Service) DeleteRole(ctx context.Context, actor Operator, name string) error {
	if err := s.requirePermission(ctx, actor, PermRolesAdmin); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if builtInRole(OperatorRole(name)) {
		return ErrRoleBuiltIn
	}
	defined, err := s.definedRoles(ctx)
	if err != nil {
		return err
	}
	role, ok := defined[name]
	if !ok {
		return ErrNotFound
	}
	rows, err := s.access.ListOperatorAccess(ctx)
	if err != nil {
		return err
	}
	var holders []string
	for _, row := range rows {
		if row.Identity.Active && string(row.Identity.Role) == name {
			holders = append(holders, row.Identity.ID)
		}
	}
	if len(holders) > 0 {
		sort.Strings(holders)
		return fmt.Errorf("%w: reassign %s first", ErrRoleInUse, strings.Join(holders, ", "))
	}
	now := s.clock().UTC()
	role.UpdatedAt = now
	_, err = s.emit(ctx, EventRoleDeleted, providerAuthorityTenant, AuthorityEvent{
		Role: &role, EffectiveAt: now,
		Audit: AuditEvent{Type: EventRoleDeleted, TenantID: providerAuthorityTenant,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Subject: name, Reason: "provider role deleted", At: now},
	})
	return err
}

func permissionStrings(perms []Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}
