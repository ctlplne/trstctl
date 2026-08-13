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
	return &handler{
		svc: NewService(cfg), idem: cfg.Idempotency, saml: cfg.SAML,
		scim:     newSCIMHandler(cfg.SCIM, cfg.Access, cfg.Mutations, cfg.Clock),
		evidence: cfg.Evidence, evidenceVerificationJWKS: append([]byte(nil), cfg.EvidenceVerificationJWKS...),
	}
}

type handler struct {
	svc                      *Service
	idem                     *orchestrator.Idempotency
	saml                     *SAMLAuthenticator
	scim                     *providerSCIMHandler
	evidence                 billing.EvidenceDeps
	evidenceVerificationJWKS []byte
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || h.svc.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		http.NotFound(w, r)
		return
	}
	if h.serveIdentityRoute(w, r) {
		return
	}
	if h.isMutation(r) {
		// Authentication runs before idempotency validation so an anonymous
		// caller receives 401, not details about a missing/reused mutation key.
		op, ok := h.operatorForMutation(r)
		if !ok {
			writeProviderError(w, ErrProviderUnauthenticated)
			return
		}
		if op.Session != "" && !validProviderSessionCSRF(r) {
			writeProviderError(w, ErrForbidden)
			return
		}
		if h.idem != nil {
			h.serveIdempotentMutation(w, r)
			return
		}
		h.serve(w, r)
		return
	}
	h.serve(w, r)
}

// serveIdentityRoute handles routes whose authentication model is not the
// normal Provider operator credential: SAML bootstrap is public, and SCIM uses
// its own file-backed bearer. Returning true means the request was consumed.
func (h *handler) serveIdentityRoute(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/auth/methods":
		writeJSON(w, http.StatusOK, map[string]any{"methods": providerAuthMethods(h.svc.authenticator)})
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/auth/session":
		operator, ok := h.operatorFromRequest(r)
		if !ok {
			writeProviderError(w, ErrProviderUnauthenticated)
		} else {
			writeJSON(w, http.StatusOK, operator)
		}
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/auth/saml/login":
		if h.saml == nil {
			http.NotFound(w, r)
		} else {
			h.saml.ServeLogin(w, r)
		}
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/auth/saml/acs":
		if h.saml == nil {
			http.NotFound(w, r)
		} else {
			h.saml.ServeACS(w, r)
		}
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/auth/saml/metadata":
		if h.saml == nil {
			http.NotFound(w, r)
		} else {
			h.saml.ServeMetadata(w, r)
		}
		return true
	case strings.HasPrefix(r.URL.Path, "/provider/scim/v2"):
		if h.scim == nil {
			http.NotFound(w, r)
		} else if h.svc.license.Mode(license.FeatureProviderPlane) == license.ModeReadOnly && r.Method != http.MethodGet {
			writeProviderSCIMError(w, http.StatusForbidden, "mutability", "Provider plane is read-only under the current entitlement")
		} else {
			h.scim.ServeHTTP(w, r)
		}
		return true
	default:
		return false
	}
}

func providerAuthMethods(authenticator OperatorAuthenticator) []string {
	methods := []string{}
	var add func(OperatorAuthenticator)
	seen := map[string]bool{}
	add = func(item OperatorAuthenticator) {
		switch typed := item.(type) {
		case *OIDCAuthenticator:
			if !seen["oidc"] {
				seen["oidc"], methods = true, append(methods, "oidc")
			}
		case *SAMLAuthenticator:
			if !seen["saml"] {
				seen["saml"], methods = true, append(methods, "saml")
			}
		case AnyAuthenticator:
			for _, child := range typed {
				add(child)
			}
		}
	}
	add(authenticator)
	return methods
}

func validProviderSessionCSRF(r *http.Request) bool {
	if r == nil {
		return false
	}
	cookie, err := r.Cookie(providerCSRFCookie)
	header := strings.TrimSpace(r.Header.Get(providerCSRFHeader))
	return err == nil && cookie.Value != "" && header != "" &&
		crypto.ConstantTimeEqual([]byte(cookie.Value), []byte(header))
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
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/operators":
		h.listOperatorAccess(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/access/customers":
		h.listAccessCustomers(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/evidence/verification-keys":
		h.serveEvidenceVerificationKeys(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/provider/v1/tenants/") && strings.HasSuffix(r.URL.Path, "/usage-evidence"):
		h.serveUsageEvidence(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/operators/") && strings.HasSuffix(r.URL.Path, "/delegations"):
		h.grantOperatorAccess(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/operators/") && strings.HasSuffix(r.URL.Path, "/revocations"):
		h.revokeOperatorAccess(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/provider/v1/operators/") && strings.HasSuffix(r.URL.Path, "/role"):
		h.setOperatorRole(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/auth/logout":
		h.logout(w, r)
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
	op, ok := h.operatorForMutation(r)
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
	if strings.HasPrefix(path, "operators/") {
		var request struct {
			CustomerID string `json:"customer_id"`
		}
		if json.Unmarshal(body, &request) == nil && strings.TrimSpace(request.CustomerID) != "" {
			return strings.TrimSpace(request.CustomerID)
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

func (h *handler) listOperatorAccess(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	items, err := h.svc.ListOperatorAccess(r.Context(), op)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operators": items})
}

func (h *handler) listAccessCustomers(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	tenants, err := h.svc.ListAccessCustomers(r.Context(), op)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

type providerDelegationRequest struct {
	CustomerID string      `json:"customer_id"`
	Operations []Operation `json:"operations"`
	ExpiresAt  string      `json:"expires_at,omitempty"`
	Reason     string      `json:"reason,omitempty"`
}

func (h *handler) grantOperatorAccess(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	operatorID := providerOperatorPathID(r.URL.Path, "/delegations")
	var body providerDelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	var expiresAt time.Time
	if strings.TrimSpace(body.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(body.ExpiresAt))
		if err != nil {
			writeProviderError(w, errors.New("provider: expires_at must be RFC3339"))
			return
		}
		expiresAt = parsed
	}
	access, err := h.svc.GrantDelegations(r.Context(), op, operatorID, body.CustomerID, body.Operations, expiresAt)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, access)
}

func (h *handler) revokeOperatorAccess(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	operatorID := providerOperatorPathID(r.URL.Path, "/revocations")
	var body providerDelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	access, err := h.svc.RevokeDelegations(r.Context(), op, operatorID, body.CustomerID, body.Operations, body.Reason)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, access)
}

func providerOperatorPathID(path, suffix string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(path, "/provider/v1/operators/"), suffix))
}

func (h *handler) setOperatorRole(w http.ResponseWriter, r *http.Request) {
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
		Role OperatorRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProviderError(w, err)
		return
	}
	access, err := h.svc.SetOperatorRole(r.Context(), op, providerOperatorPathID(r.URL.Path, "/role"), body.Role)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, access)
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	r, ok = h.withMutationKey(w, r)
	if !ok {
		return
	}
	if op.Session != "" {
		if h.saml == nil {
			writeProviderError(w, errors.New("provider: session authenticator is not configured"))
			return
		}
		if err := h.saml.RevokeSession(w, op.Session); err != nil {
			writeProviderError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
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

// serveUsageEvidence bridges the Provider workforce boundary to L2's one
// canonical invoice builder. The order is the security property: authenticate,
// require a real MFA-backed operator, authorize this exact customer + read
// operation, and only then let billing open that customer's RLS transaction.
func (h *handler) serveUsageEvidence(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	if h.evidence.Reader == nil {
		http.NotFound(w, r)
		return
	}
	customerID, ok := providerTenantPathID(r.URL.Path, "/usage-evidence")
	if !ok {
		writeProviderError(w, errors.New("provider: usage-evidence path must name exactly one customer"))
		return
	}
	if named := strings.TrimSpace(r.URL.Query().Get("customer_id")); named != "" && named != customerID {
		writeProviderError(w, fmt.Errorf("%w: customer_id cannot redirect evidence away from the authorized path", ErrForbidden))
		return
	}
	if err := h.svc.requireOperator(op); err != nil {
		writeProviderError(w, err)
		return
	}
	if err := h.svc.authorize(r.Context(), op, customerID, OpRead); err != nil {
		writeProviderError(w, err)
		return
	}
	billing.ServeEvidenceForCustomer(w, r, h.evidence, customerID)
}

func providerTenantPathID(path, suffix string) (string, bool) {
	const prefix = "/provider/v1/tenants/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix))
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func (h *handler) serveEvidenceVerificationKeys(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	if h.evidence.Reader == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.svc.requireOperator(op); err != nil {
		writeProviderError(w, err)
		return
	}
	if len(h.evidenceVerificationJWKS) == 0 {
		writeProviderError(w, errors.New("provider: invoice evidence verification keys are not attached"))
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.evidenceVerificationJWKS)
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

func (h *handler) operatorForMutation(r *http.Request) (Operator, bool) {
	if op, ok := h.operatorFromRequest(r); ok {
		return op, true
	}
	if h != nil && h.saml != nil && r != nil && r.Method == http.MethodPost && r.URL.Path == "/provider/v1/auth/logout" {
		return h.saml.AuthenticateLogout(r)
	}
	return Operator{}, false
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
