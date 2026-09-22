// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
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
	if err := a.checkManagedTenantReviewedAccount(r); err != nil {
		a.writeError(w, err)
		return
	}
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

// The browser's reviewed account is an assertion, never an authentication
// source. Check it before the idempotency recorder too: a cached result must
// not hide a session switch. CLI callers without the assertion keep the normal
// authenticated tenant and actor binding.
func (a *API) checkManagedTenantReviewedAccount(r *http.Request) error {
	values := r.Header.Values("X-Trstctl-Expected-Subject")
	if len(values) == 0 {
		if _, err := r.Cookie(a.browserSessionCookieName()); err == nil {
			return errStatus(http.StatusConflict, "Reload the console and review this request with the original account before retrying. Browser provisioning requires reviewed account assertions.")
		}
		return nil
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(r.Header.Get("X-Tenant-ID")) == "" {
		return errStatus(http.StatusBadRequest, "reviewed account requires X-Tenant-ID and one X-Trstctl-Expected-Subject")
	}
	expectedSubject, err := url.PathUnescape(values[0])
	if err != nil || expectedSubject == "" {
		return errStatus(http.StatusBadRequest, "X-Trstctl-Expected-Subject must contain a percent-encoded subject")
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return err
	}
	tenant, ok := a.tenant(r)
	if !ok {
		return errStatus(http.StatusUnauthorized, "an authenticated tenant is required")
	}
	if expectedSubject != subject || strings.TrimSpace(r.Header.Get("X-Tenant-ID")) != tenant {
		return errStatus(http.StatusConflict, "The signed-in account changed after this request was reviewed. Reload and sign in with the original account before retrying.")
	}
	return nil
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
