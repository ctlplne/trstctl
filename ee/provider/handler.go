package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

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
	op, ok := operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrForbidden)
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
	if _, ok := operatorFromRequest(r); !ok {
		writeProviderError(w, ErrForbidden)
		return
	}
	tenants, err := h.svc.ListTenants(r.Context())
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

func (h *handler) updateTenant(w http.ResponseWriter, r *http.Request, status TenantStatus, suffix string) {
	op, ok := operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrForbidden)
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

func (h *handler) requestBreakGlass(w http.ResponseWriter, r *http.Request) {
	op, ok := operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrForbidden)
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

func (h *handler) consentBreakGlass(w http.ResponseWriter, r *http.Request) {
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
	approve := true
	if body.Approve != nil {
		approve = *body.Approve
	}
	grant, err := h.svc.ConsentBreakGlass(r.Context(), body.TenantID, grantID, body.Subject, approve)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (h *handler) breakGlassResults(w http.ResponseWriter, r *http.Request) {
	op, ok := operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrForbidden)
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

func operatorFromRequest(r *http.Request) (Operator, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(auth, "Bearer provider:")
	if !ok {
		return Operator{}, false
	}
	parts := strings.SplitN(token, ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Operator{}, false
	}
	return Operator{ID: parts[0], Email: parts[1], Role: OperatorAdmin, MFA: true}, true
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
