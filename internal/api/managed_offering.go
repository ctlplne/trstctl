package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
)

type managedOfferingStatus struct {
	Served              bool          `json:"served"`
	DeploymentModel     string        `json:"deployment_model"`
	Tier                license.Tier  `json:"tier"`
	LicenseState        license.State `json:"license_state"`
	ProviderPlaneMode   license.Mode  `json:"provider_plane_mode"`
	TenantBand          int           `json:"tenant_band,omitempty"`
	IdempotencyRequired bool          `json:"idempotency_required"`
	EventType           string        `json:"event_type"`
	MutationPath        string        `json:"mutation_path"`
}

func (a *API) getManagedOfferingStatus(w http.ResponseWriter, _ *http.Request) {
	mgr := a.licenseManager()
	a.writeJSON(w, http.StatusOK, managedOfferingStatus{
		Served:              true,
		DeploymentModel:     orchestrator.ManagedOfferingDeploymentModel,
		Tier:                mgr.Tier(),
		LicenseState:        mgr.State(),
		ProviderPlaneMode:   mgr.Mode(license.FeatureProviderPlane),
		TenantBand:          mgr.TenantBand(),
		IdempotencyRequired: true,
		EventType:           "tenant.registered",
		MutationPath:        "/api/v1/managed-offering/tenants",
	})
}

func (a *API) provisionManagedTenant(w http.ResponseWriter, r *http.Request) {
	var req orchestrator.ManagedTenantProvisionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, providerTenantID string) (int, any, error) {
		if a.licenseManager().Mode(license.FeatureProviderPlane) != license.ModeEnabled {
			return 0, nil, errStatus(http.StatusForbidden, "provider_plane license is required to provision managed tenants")
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "managed offering provisioning is not configured")
		}
		tenant, err := a.orch.ProvisionManagedTenant(ctx, providerTenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusCreated, tenant, nil
	})
}
