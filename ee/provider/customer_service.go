// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/tenancy"
)

// RequireCustomerService checks the live, event-projected registry on each
// admission. Existing bearer tokens, browser sessions and agent certificates
// cannot carry an old active status through a suspension. A tenant outside this
// registry is not a Provider customer and keeps its ordinary core policy.
func (p *PGStore) RequireCustomerService(ctx context.Context, tenantID string) error {
	tenant, err := p.Tenant(ctx, tenantID)
	if errors.Is(err, ErrNotFound) {
		// Recovery can fold a retained deletion before core's SQL erase has
		// completed. Missing Provider metadata must not reopen that customer.
		return p.store.RequireLiveTenantService(ctx, tenantID)
	}
	if err != nil {
		return err
	}
	if tenant.Status != TenantActive {
		return tenancy.ErrServiceUnavailable
	}
	return nil
}
