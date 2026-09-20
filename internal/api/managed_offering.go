// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/usage"
)

type managedOfferingStatus struct {
	Served              bool          `json:"served"`
	DeploymentModel     string        `json:"deployment_model"`
	Tier                license.Tier  `json:"tier"`
	LicenseState        license.State `json:"license_state"`
	ProviderPlaneMode   license.Mode  `json:"provider_plane_mode"`
	TenantBand          int           `json:"tenant_band,omitempty"`
	ManagedCustomerBand int           `json:"managed_customer_band,omitempty"`
	BillingUnit         string        `json:"billing_unit"`
	ManagedBoundary     string        `json:"managed_boundary"`
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
		ManagedCustomerBand: mgr.ManagedCustomerBand(),
		BillingUnit:         usage.BillingUnitManagedCustomerBand,
		ManagedBoundary:     "Provider/MSP normally uses one shared control plane with multiple customer tenants; dedicated customer deployments are also supported.",
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
	binding, err := managedTenantProvisionRequestBinding(r, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(ctx context.Context, providerTenantID string) (int, any, error) {
		if a.licenseManager().Mode(license.FeatureProviderPlane) != license.ModeEnabled {
			return 0, nil, errStatus(http.StatusForbidden, "provider_plane license is required to provision managed tenants")
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "managed offering provisioning is not configured")
		}
		tenant, err := a.orch.ProvisionManagedTenant(ctx, providerTenantID, idempotencyKey, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusCreated, tenant, nil
	}, false)
}

func managedTenantProvisionRequestBinding(
	r *http.Request,
	request orchestrator.ManagedTenantProvisionRequest,
) (string, error) {
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return "", err
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Name = strings.TrimSpace(request.Name)
	request.Region = strings.TrimSpace(request.Region)
	request.DataResidency = strings.TrimSpace(request.DataResidency)
	request.Plan = strings.TrimSpace(request.Plan)
	request.SupportTier = strings.TrimSpace(request.SupportTier)
	request.SLOTier = strings.TrimSpace(request.SLOTier)
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	material, err := json.Marshal(struct {
		Domain      string                                     `json:"domain"`
		Principal   string                                     `json:"principal"`
		Method      string                                     `json:"method"`
		EscapedPath string                                     `json:"escaped_path"`
		Request     orchestrator.ManagedTenantProvisionRequest `json:"request"`
	}{
		Domain:    "trstctl.api.managed-tenant-provision-binding.v1",
		Principal: principal, Method: r.Method, EscapedPath: escapedPath,
		Request: request,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}
