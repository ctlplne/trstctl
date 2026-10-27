// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync/atomic"

	"trstctl.com/trstctl/internal/api"
)

// deferredTenantServices hands the Provider plane the API's tenant baseline and
// its customers' signed reports. The Provider command surface is assembled
// before the API, so they are reached through this forwarder, which the server
// fills once the API exists.
type deferredTenantServices struct{ api atomic.Pointer[api.API] }

var _ api.ProviderTenantServices = (*deferredTenantServices)(nil)

var errTenantServicesUnassembled = errors.New("server: the tenant services are not assembled yet")

func (d *deferredTenantServices) ValidateTenantBaseline(b api.TenantBaseline) error {
	a := d.api.Load()
	if a == nil {
		return errTenantServicesUnassembled
	}
	return a.ValidateTenantBaseline(b)
}

func (d *deferredTenantServices) ApplyTenantBaseline(ctx context.Context, tenantID, scope string, b api.TenantBaseline) (api.TenantBaselineApplication, error) {
	a := d.api.Load()
	if a == nil {
		return api.TenantBaselineApplication{}, errTenantServicesUnassembled
	}
	return a.ApplyTenantBaseline(ctx, tenantID, scope, b)
}

func (d *deferredTenantServices) TenantBaselineDrift(ctx context.Context, tenantID, scope string, b api.TenantBaseline) (api.TenantBaselineReport, error) {
	a := d.api.Load()
	if a == nil {
		return api.TenantBaselineReport{}, errTenantServicesUnassembled
	}
	return a.TenantBaselineDrift(ctx, tenantID, scope, b)
}

func (d *deferredTenantServices) ReportSigningKey() (api.ReportSigningKey, error) {
	a := d.api.Load()
	if a == nil {
		return api.ReportSigningKey{}, errTenantServicesUnassembled
	}
	return a.ReportSigningKey()
}

func (d *deferredTenantServices) CustomerAssuranceRuns(ctx context.Context, tenantID string) ([]api.ReportRunSummary, error) {
	a := d.api.Load()
	if a == nil {
		return nil, errTenantServicesUnassembled
	}
	return a.CustomerAssuranceRuns(ctx, tenantID)
}

func (d *deferredTenantServices) CustomerAssuranceArtifact(ctx context.Context, tenantID, runID string) ([]byte, error) {
	a := d.api.Load()
	if a == nil {
		return nil, errTenantServicesUnassembled
	}
	return a.CustomerAssuranceArtifact(ctx, tenantID, runID)
}
