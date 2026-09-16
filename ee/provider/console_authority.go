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
	Available      bool                                `json:"available"`
	AccessRead     bool                                `json:"access_read"`
	AccessWrite    bool                                `json:"access_write"`
	Provision      bool                                `json:"provision"`
	IsolationDrill bool                                `json:"isolation_drill"`
	Customers      map[string]ConsoleCustomerAuthority `json:"customers"`
}

type ConsoleCustomerAuthority struct {
	ReadQuota  bool `json:"read_quota"`
	WriteQuota bool `json:"write_quota"`
	WriteBrand bool `json:"write_brand"`
	Suspend    bool `json:"suspend"`
	Offboard   bool `json:"offboard"`
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
	canWrite := s.requireMutation(actor, true) == nil
	a.AccessRead = s.requireAdminAccessRead(actor) == nil && s.access != nil
	a.AccessWrite = a.AccessRead && canWrite
	a.IsolationDrill = canWrite && s.drills != nil
	for _, customer := range set.CustomersFor(actor.ID) {
		read := set.Authorize(actor, customer, OpRead) == nil
		provision := canWrite && set.Authorize(actor, customer, OpProvision) == nil
		a.Provision = a.Provision || provision
		a.Customers[customer] = ConsoleCustomerAuthority{
			ReadQuota:  read && s.quotas != nil,
			WriteQuota: provision && s.quotas != nil,
			WriteBrand: provision && s.brands != nil,
			Suspend:    canWrite && set.Authorize(actor, customer, OpSuspend) == nil,
			Offboard:   canWrite && set.Authorize(actor, customer, OpOffboard) == nil,
		}
	}
	return a
}
