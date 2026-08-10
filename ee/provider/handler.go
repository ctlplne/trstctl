// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// NewHandler returns the licensed Provider/MSP HTTP surface.
func NewHandler(cfg Config) http.Handler {
	return &handler{svc: NewService(cfg), idem: cfg.Idempotency}
}

type handler struct {
	svc  *Service
	idem *orchestrator.Idempotency
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.idem != nil && h.isMutation(r) {
		// Authentication runs before idempotency validation so an anonymous
		// caller receives 401, not details about a missing/reused mutation key.
		if _, ok := h.operatorFromRequest(r); ok {
			h.serveIdempotentMutation(w, r)
			return
		}
	}
	h.serve(w, r)
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || h.svc.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/tenants":
		h.createTenant(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/tenants":
		h.listTenants(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/activity":
		h.listActivity(w, r)
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
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/isolation-drill":
		h.runIsolationDrill(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/breakglass":
		h.requestBreakGlass(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/breakglass/") && strings.HasSuffix(r.URL.Path, "/consent"):
		h.consentBreakGlass(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/breakglass/") && strings.HasSuffix(r.URL.Path, "/results"):
		h.breakGlassResults(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) listActivity(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	limit := defaultProviderActivityLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeProviderError(w, errors.New("provider: activity limit must be a positive integer"))
			return
		}
		limit = parsed
	}
	items, err := h.svc.ListActivity(r.Context(), op, limit)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *handler) isMutation(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.Method == http.MethodPost || r.Method == http.MethodPut
}

const maxProviderMutationBody = 2 << 20

type cachedProviderResponse struct {
	Status int         `json:"status"`
	Header http.Header `json:"header,omitempty"`
	Body   []byte      `json:"body,omitempty"`
}

type providerResponseCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newProviderResponseCapture() *providerResponseCapture {
	return &providerResponseCapture{header: make(http.Header)}
}

func (c *providerResponseCapture) Header() http.Header { return c.header }

func (c *providerResponseCapture) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *providerResponseCapture) Write(body []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(body)
}

func (h *handler) serveIdempotentMutation(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeProviderError(w, errors.New("provider: Idempotency-Key header is required for mutations"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProviderMutationBody+1))
	if err != nil {
		writeProviderError(w, err)
		return
	}
	if len(body) > maxProviderMutationBody {
		writeProviderError(w, errors.New("provider: mutation body exceeds 2 MiB"))
		return
	}
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	bindingMaterial, err := json.Marshal(struct {
		OperatorID string `json:"operator_id"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		Body       []byte `json:"body"`
	}{OperatorID: op.ID, Method: r.Method, Path: r.URL.Path, Body: body})
	if err != nil {
		writeProviderError(w, err)
		return
	}
	binding := "sha256:" + crypto.SHA256Hex(bindingMaterial)
	ctx := ContextWithMutationKey(r.Context(), key)
	ctx = contextWithMutationBinding(ctx, binding)
	idempotencyTenant := h.mutationTenant(r, body)
	encoded, err := h.idem.DoDurableEffectBound(ctx, idempotencyTenant, key, binding,
		func(runCtx context.Context) ([]byte, error) {
			request := r.Clone(runCtx)
			request.Body = io.NopCloser(bytes.NewReader(body))
			capture := newProviderResponseCapture()
			h.serve(capture, request)
			status := capture.status
			if status == 0 {
				status = http.StatusOK
			}
			if status >= http.StatusInternalServerError {
				return nil, fmt.Errorf("%w: handler returned %d: %s", ErrMutationPersistence,
					status, strings.TrimSpace(capture.body.String()))
			}
			return json.Marshal(cachedProviderResponse{
				Status: status, Header: capture.header.Clone(), Body: append([]byte(nil), capture.body.Bytes()...),
			})
		})
	if err != nil {
		writeProviderError(w, err)
		return
	}
	var response cachedProviderResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		writeProviderError(w, fmt.Errorf("provider: decode idempotent response: %w", err))
		return
	}
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if response.Status == 0 {
		response.Status = http.StatusOK
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}

func (h *handler) mutationTenant(r *http.Request, body []byte) string {
	path := strings.TrimPrefix(r.URL.Path, "/provider/v1/")
	if strings.HasPrefix(path, "tenants/") {
		customer := strings.TrimPrefix(path, "tenants/")
		if slash := strings.IndexByte(customer, '/'); slash >= 0 {
			customer = customer[:slash]
		}
		if strings.TrimSpace(customer) != "" {
			return customer
		}
	}
	if path == "tenants" {
		var request ProvisionRequest
		if json.Unmarshal(body, &request) == nil && strings.TrimSpace(request.Slug) != "" {
			return CustomerID(request.Slug)
		}
	}
	if path == "breakglass" || strings.HasSuffix(path, "/consent") {
		var request struct {
			TenantID string `json:"tenant_id"`
		}
		if json.Unmarshal(body, &request) == nil && strings.TrimSpace(request.TenantID) != "" {
			return request.TenantID
		}
	}
	if strings.HasPrefix(path, "breakglass/") && strings.HasSuffix(path, "/results") && h.svc != nil {
		grantID := strings.TrimSuffix(strings.TrimPrefix(path, "breakglass/"), "/results")
		if grant, err := h.svc.store.BreakGlassGrant(r.Context(), grantID); err == nil && grant.TenantID != "" {
			return grant.TenantID
		}
	}
	return corestore.ZeroUUID
}

func (h *handler) createTenant(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
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

func (h *handler) runIsolationDrill(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	report, err := h.svc.RunIsolationDrill(r.Context(), op)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	// A drill that RAN and found isolation broken is a successful request with a
	// failing result, not an HTTP error: the operator asked for the truth and
	// got it. The body carries pass/fail; the status is 200 either way.
	writeJSON(w, http.StatusOK, report)
}

func (h *handler) updateTenant(w http.ResponseWriter, r *http.Request, status TenantStatus, suffix string) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
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
	r, ok = h.withMutationKey(w, r)
	if !ok {
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
	r, ok = h.withMutationKey(w, r)
	if !ok {
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
	r, ok = h.withMutationKey(w, r)
	if !ok {
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
	r, ok = h.withMutationKey(w, r)
	if !ok {
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
	r, ok = h.withMutationKey(w, r)
	if !ok {
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

// withMutationKey runs only after authentication, so an unauthenticated caller
// still receives 401 rather than learning mutation-header validation details.
// The assembled provider plane always has a durable mutation sink and therefore
// requires the key; legacy in-memory unit-service adapters have no event effect
// to key and keep their historical test shape.
func (h *handler) withMutationKey(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if h == nil || h.svc == nil || h.svc.mutations == nil {
		return r, true
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeProviderError(w, errors.New("provider: Idempotency-Key header is required for mutations"))
		return r, false
	}
	return r.WithContext(ContextWithMutationKey(r.Context(), key)), true
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
	case errors.Is(err, ErrMutationConflict), errors.Is(err, orchestrator.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, orchestrator.ErrInProgress), errors.Is(err, orchestrator.ErrEffectIndeterminate):
		status, code = http.StatusConflict, "idempotency_in_progress"
	case errors.Is(err, ErrMutationPersistence):
		status, code = http.StatusInternalServerError, "mutation_persistence_failed"
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
