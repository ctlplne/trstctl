// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"

	"trstctl.com/trstctl/internal/license"
)

// ConsoleAuthority describes which controls this operator can use now. It is
// advisory UI state, not a grant: every action still repeats the existing
// privilege, entitlement, delegation and dependency checks when it executes.
type ConsoleAuthority struct {
	Available      bool `json:"available"`
	AccessRead     bool `json:"access_read"`
	AccessWrite    bool `json:"access_write"`
	Provision      bool `json:"provision"`
	IsolationDrill bool `json:"isolation_drill"`
	// RolesWrite (A90): may define or delete custom Provider roles.
	RolesWrite bool                                `json:"roles_write"`
	Customers  map[string]ConsoleCustomerAuthority `json:"customers"`
}

type ConsoleCustomerAuthority struct {
	ReadQuota       bool `json:"read_quota"`
	WriteQuota      bool `json:"write_quota"`
	WriteBrand      bool `json:"write_brand"`
	Suspend         bool `json:"suspend"`
	Resume          bool `json:"resume"`
	Offboard        bool `json:"offboard"`
	BreakGlass      bool `json:"break_glass"`
	BreakGlassWrite bool `json:"break_glass_write"`
}

func (s *Service) consoleAuthority(ctx context.Context, actor Operator) ConsoleAuthority {
	a := ConsoleAuthority{Customers: map[string]ConsoleCustomerAuthority{}}
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff || s.requireOperator(actor) != nil {
		// Authentication can be valid while MFA or entitlement prevents actions.
		a.Available = true
		return a
	}
	if s.delegations == nil {
		return a
	}
	set, err := s.delegations.Delegations(ctx)
	if err != nil || set == nil {
		// Do not substitute token claims or stale grants when authority cannot
		// be read. Preserve the authenticated identity and disable the controls.
		return a
	}
	a.Available = true
	// A90: each control follows its own permission, not an admin bit.
	can := func(perm Permission) bool { return s.requirePermission(ctx, actor, perm) == nil }
	canProvision, canLifecycle := can(PermTenantsProvision), can(PermTenantsLifecycle)
	canQuota, canBrand := can(PermQuotaWrite), can(PermBrandWrite)
	canBreakGlassWrite := can(PermBreakGlassRequest) || can(PermBreakGlassConsent)
	a.AccessRead = s.requireAdminAccessRead(ctx, actor) == nil && s.access != nil
	a.AccessWrite = a.AccessRead && can(PermOperatorsAdmin)
	a.RolesWrite = can(PermRolesAdmin) && s.roleStore() != nil
	a.IsolationDrill = can(PermIsolationDrill) && s.drills != nil
	for _, customer := range set.CustomersFor(actor.ID) {
		read := set.Authorize(actor, customer, OpRead) == nil
		provision := canProvision && set.Authorize(actor, customer, OpProvision) == nil
		a.Provision = a.Provision || provision
		a.Customers[customer] = ConsoleCustomerAuthority{
			ReadQuota:       read && s.quotas != nil,
			WriteQuota:      canQuota && set.Authorize(actor, customer, OpProvision) == nil && s.quotas != nil,
			WriteBrand:      canBrand && set.Authorize(actor, customer, OpProvision) == nil && s.brands != nil,
			Suspend:         canLifecycle && set.Authorize(actor, customer, OpSuspend) == nil,
			Resume:          canLifecycle && set.Authorize(actor, customer, OpResume) == nil,
			Offboard:        canLifecycle && set.Authorize(actor, customer, OpOffboard) == nil,
			BreakGlass:      s.store != nil && set.Authorize(actor, customer, OpBreakGlass) == nil,
			BreakGlassWrite: canBreakGlassWrite && set.Authorize(actor, customer, OpBreakGlass) == nil,
		}
	}
	return a
}
