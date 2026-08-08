// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/license"
)

// NewHandler returns the licensed Provider/MSP HTTP surface.
func NewHandler(cfg Config) http.Handler {
	return &handler{svc: NewService(cfg)}
}

type handler struct {
	svc *Service
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || h.svc.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/tenants":
		h.createTenant(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/tenants":
		h.listTenants(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/suspend"):
		h.updateTenant(w, r, TenantSuspended, "/suspend")
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/offboard"):
		h.updateTenant(w, r, TenantOffboarded, "/offboard")
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/quota"):
		h.setQuota(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/quota"):
		h.getQuota(w, r)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/brand"):
		h.setBrand(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/breakglass":
		h.requestBreakGlass(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/breakglass/") && strings.HasSuffix(r.URL.Path, "/consent"):
		h.consentBreakGlass(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/provider/v1/breakglass/") && strings.HasSuffix(r.URL.Path, "/results"):
		h.breakGlassResults(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) createTenant(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProviderError(w, err)
		return
	}
	tenant, err := h.svc.Provision(r.Context(), op, req)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenant)
}

func (h *handler) listTenants(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	tenants, err := h.svc.ListTenants(r.Context(), op)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

func (h *handler) updateTenant(w http.ResponseWriter, r *http.Request, status TenantStatus, suffix string) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	tenantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), suffix)
	var err error
	switch status {
	case TenantSuspended:
		err = h.svc.Suspend(r.Context(), op, tenantID)
	case TenantOffboarded:
		err = h.svc.Offboard(r.Context(), op, tenantID)
	default:
		err = ErrForbidden
	}
	if err != nil {
		writeProviderError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) setQuota(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/quota")
	var q billing.Quota
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeProviderError(w, err)
		return
	}
	if err := h.svc.SetTenantQuota(r.Context(), op, customerID, q); err != nil {
		writeProviderError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) setBrand(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/brand")
	var body struct {
		ProductName   string `json:"product_name"`
		LogoDataURI   string `json:"logo_data_uri"`
		LoginMessage  string `json:"login_message"`
		EmailFromName string `json:"email_from_name"`
		EmailFooter   string `json:"email_footer"`
		CustomDomain  string `json:"custom_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	if err := h.svc.SetTenantBrand(r.Context(), op, customerID, TenantBrand{
		ProductName:   body.ProductName,
		LogoDataURI:   body.LogoDataURI,
		LoginMessage:  body.LoginMessage,
		EmailFromName: body.EmailFromName,
		EmailFooter:   body.EmailFooter,
		CustomDomain:  body.CustomDomain,
	}); err != nil {
		writeProviderError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) getQuota(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/quota")
	q, err := h.svc.GetTenantQuota(r.Context(), op, customerID)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(q)
}

func (h *handler) requestBreakGlass(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Reason   string `json:"reason"`
		TTL      string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	ttl := time.Duration(0)
	if body.TTL != "" {
		parsed, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeProviderError(w, err)
			return
		}
		ttl = parsed
	}
	grant, err := h.svc.RequestBreakGlass(r.Context(), op, BreakGlassRequest{TenantID: body.TenantID, Reason: body.Reason, TTL: ttl})
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

// consentBreakGlass records one operator's consent to a break-glass grant.
//
// The consenting subject is the AUTHENTICATED caller, never a field in the
// request body. It used to be the body field, and this handler did not
// authenticate at all — so the operator requesting break-glass supplied
// whatever approver name they liked and consented to their own grant with a
// second call. Two-person control defeated by a JSON string.
//
// A `subject` in the body is now rejected rather than ignored: silently
// discarding it would let a caller keep sending one and believe it had effect,
// and an integration built on that belief looks like it works until the day the
// second person matters.
func (h *handler) consentBreakGlass(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	grantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/breakglass/"), "/consent")
	var body struct {
		TenantID string `json:"tenant_id"`
		Subject  string `json:"subject"`
		Approve  *bool  `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	if strings.TrimSpace(body.Subject) != "" {
		writeProviderError(w, ErrProviderConsentSubjectNotSettable)
		return
	}
	approve := true
	if body.Approve != nil {
		approve = *body.Approve
	}
	grant, err := h.svc.ConsentBreakGlass(r.Context(), body.TenantID, grantID, op.ID, approve)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (h *handler) breakGlassResults(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	grantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/breakglass/"), "/results")
	snapshot, err := h.svc.BreakGlassResults(r.Context(), op, grantID)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// operatorFromRequest authenticates a provider operator, or refuses.
//
// It used to accept "Bearer provider:<id>:<email>" and return
// Operator{Role: OperatorAdmin, MFA: true} — parsing the token for SHAPE and
// verifying nothing. Any caller who knew the format was a provider
// administrator with MFA asserted, and /provider/ is mounted on the root mux
// behind only a bulkhead whenever the provider plane is licensed. Tenant
// create, suspend, offboard and break-glass were all reachable that way.
//
// Now the credential is verified by a configured authenticator or the request
// is refused. A nil authenticator refuses everything: an unconfigured provider
// plane must be closed, not open.
func (h *handler) operatorFromRequest(r *http.Request) (Operator, bool) {
	if h == nil || h.svc == nil || h.svc.authenticator == nil {
		return Operator{}, false
	}
	op, ok := h.svc.authenticator.AuthenticateOperator(r)
	if !ok {
		return Operator{}, false
	}
	// A verifier that returns an operator with no identity is a broken verifier;
	// treat it as a refusal rather than trusting an anonymous admin.
	if strings.TrimSpace(op.ID) == "" {
		return Operator{}, false
	}
	return op, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProviderError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "bad_request"
	switch {
	case errors.Is(err, ErrTenantBandExhausted):
		status, code = http.StatusForbidden, CodeTenantBandExhausted
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrBreakGlassNotConsented), errors.Is(err, ErrBreakGlassWrongOperator), errors.Is(err, ErrBreakGlassExpired):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrProviderUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, ErrProviderConsentSubjectNotSettable):
		status, code = http.StatusBadRequest, "consent_subject_not_settable"
	case errors.Is(err, ErrUnlicensed), errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, ErrReadOnly):
		status, code = http.StatusForbidden, "read_only"
	}
	_ = problem.New(status, err.Error()).
		WithType("urn:trstctl:provider:"+code).
		WithExtension("code", code).
		WithExtension("retry_after_seconds", retryAfterSeconds(err)).
		Write(w)
}

func retryAfterSeconds(err error) int {
	if errors.Is(err, ErrTenantBandExhausted) {
		return 0
	}
	return -1
}
