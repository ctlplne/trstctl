// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync/atomic"

	"trstctl.com/trstctl/internal/api"
)

// deferredTenantBaselines hands the Provider plane the API's tenant baseline.
// The Provider command surface is assembled before the API, so the baseline is
// reached through this forwarder, which the server fills once the API exists.
type deferredTenantBaselines struct{ api atomic.Pointer[api.API] }

var errTenantBaselinesUnassembled = errors.New("server: the tenant baseline is not assembled yet")

func (d *deferredTenantBaselines) ValidateTenantBaseline(b api.TenantBaseline) error {
	a := d.api.Load()
	if a == nil {
		return errTenantBaselinesUnassembled
	}
	return a.ValidateTenantBaseline(b)
}

func (d *deferredTenantBaselines) ApplyTenantBaseline(ctx context.Context, tenantID, scope string, b api.TenantBaseline) (api.TenantBaselineApplication, error) {
	a := d.api.Load()
	if a == nil {
		return api.TenantBaselineApplication{}, errTenantBaselinesUnassembled
	}
	return a.ApplyTenantBaseline(ctx, tenantID, scope, b)
}

func (d *deferredTenantBaselines) TenantBaselineDrift(ctx context.Context, tenantID, scope string, b api.TenantBaseline) (api.TenantBaselineReport, error) {
	a := d.api.Load()
	if a == nil {
		return api.TenantBaselineReport{}, errTenantBaselinesUnassembled
	}
	return a.TenantBaselineDrift(ctx, tenantID, scope, b)
}
