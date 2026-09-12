// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/leaseworker"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type dynamicLeaseIssueRequest struct {
	Provider           string `json:"provider"`
	Role               string `json:"role"`
	TTLSeconds         int    `json:"ttl_seconds"`
	PreviewFingerprint string `json:"preview_fingerprint,omitempty"`
}

type dynamicLeaseRenewRequest struct {
	ExtendSeconds int `json:"extend_seconds"`
}

type dynamicLeaseResponse struct {
	ID                    string          `json:"id"`
	Provider              string          `json:"provider"`
	Role                  string          `json:"role"`
	State                 string          `json:"state"`
	Credential            secretJSONBytes `json:"credential,omitempty"`
	IssuedAt              time.Time       `json:"issued_at"`
	ExpiresAt             time.Time       `json:"expires_at"`
	HardExpiresAt         *time.Time      `json:"hard_expires_at,omitempty"`
	RevocationStatus      string          `json:"revocation_status,omitempty"`
	RevokedAt             *time.Time      `json:"revoked_at,omitempty"`
	RevocationCompletedAt *time.Time      `json:"revocation_completed_at,omitempty"`
}

// ---- dynamic secret leases (dynsecret, F65) --------------------------------

// issueDynamicLease generates one scoped backend credential and opens a lease. The
// credential is returned only in this response (or an idempotent replay of it);
// later reads return metadata only.
//
//trstctl:mutation
func (a *API) issueDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req dynamicLeaseIssueRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req, err := normalizeDynamicLeaseIssueRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := dynamicLeaseIssueBinding(principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateSealedDynamicLease(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		provider, found := a.secrets.configuredDynamicSecretProvider(tenantID, req.Provider)
		if !found {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "dynamic secret provider is not configured for this tenant")
		}
		if err := validateDynamicLeaseProviderRequest(provider, req); err != nil {
			return 0, nil, err
		}
		if req.PreviewFingerprint != "" {
			want, fingerprintErr := a.dynamicSecretPreviewFingerprint(tenantID, principal, provider, req)
			if fingerprintErr != nil {
				return 0, nil, fingerprintErr
			}
			if !crypto.ConstantTimeEqual([]byte(req.PreviewFingerprint), []byte(want)) {
				return 0, nil, errStatus(http.StatusConflict, "reviewed dynamic-secret plan is stale; preview the current request again")
			}
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		var lease dynsecret.Lease
		var credential []byte
		if issuer, ok := engine.(boundDynamicLeaseIssuer); ok {
			lease, credential, err = issuer.IssueBound(ctx, req.Provider, req.Role, ttl, idempotencyKey, binding)
		} else {
			lease, credential, err = engine.Issue(ctx, req.Provider, req.Role, ttl, idempotencyKey)
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		return http.StatusCreated, toDynamicLeaseResponse(lease, credential), nil
	})
}

type boundDynamicLeaseIssuer interface {
	IssueBound(context.Context, string, string, time.Duration, string, string) (dynsecret.Lease, []byte, error)
}

type boundDynamicLeaseRenewer interface {
	RenewBound(context.Context, string, time.Duration, string, string) (dynsecret.Lease, error)
}

type boundDynamicLeaseRevoker interface {
	RevokeBound(context.Context, string, string, string) (dynsecret.Lease, error)
}

// mutateSealedDynamicLease is the AN-5 recorder for the one credential-bearing
// response. The generic mutation recorder persists response JSON verbatim; this
// variant envelope-seals it first, so idempotent replay still returns the original
// credential without placing plaintext in idempotency_keys.result.
func (a *API) mutateSealedDynamicLease(w http.ResponseWriter, r *http.Request, idempotencyKey, binding string, fn func(context.Context, string) (int, any, error)) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	if a.secrets == nil || a.secrets.be.KEK == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "dynamic secret lease response sealing is not configured"))
		return
	}
	aad := []byte(tenantID + "/dynamic-secret-lease/idempotency/" + idempotencyKey)
	sealedResult, err := a.idem.DoDurableEffectBound(r.Context(), tenantID, idempotencyKey, binding, func(ctx context.Context) ([]byte, error) {
		status, body, callErr := fn(ctx, tenantID)
		if callErr != nil {
			return nil, callErr
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			if response, ok := body.(secretResponse); ok {
				defer response.wipeSecrets()
			}
			encoded, marshalErr := json.Marshal(body)
			if marshalErr != nil {
				return nil, marshalErr
			}
			defer secret.Wipe(encoded)
			bodyJSON = encoded
		}
		plaintext, marshalErr := json.Marshal(cachedResponse{Status: status, Body: bodyJSON, Binding: binding})
		if marshalErr != nil {
			return nil, marshalErr
		}
		defer secret.Wipe(plaintext)
		return a.secrets.seal(ctx, tenantID, plaintext, aad)
	})
	if err != nil {
		if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
			err = errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
		}
		a.writeError(w, err)
		return
	}
	plaintext, err := a.secrets.open(r.Context(), tenantID, sealedResult, aad)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(plaintext)
	var cached cachedResponse
	if err := json.Unmarshal(plaintext, &cached); err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(cached.Body)
	if !crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(binding)) {
		a.writeError(w, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request"))
		return
	}
	if cached.Status == http.StatusNoContent {
		w.WriteHeader(cached.Status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(cached.Status)
	_, _ = w.Write(cached.Body)
}

func dynamicLeaseIssueBinding(principal string, req dynamicLeaseIssueRequest) (string, error) {
	canonical := struct {
		Operation  string `json:"operation"`
		Principal  string `json:"principal"`
		Provider   string `json:"provider"`
		Role       string `json:"role"`
		TTLSeconds int    `json:"ttl_seconds"`
	}{Operation: "dynamic-secret.issue", Principal: principal, Provider: req.Provider, Role: req.Role, TTLSeconds: req.TTLSeconds}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func (a *API) getDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	lease, err := getDynamicLeaseContext(r.Context(), engine, r.PathValue("lease_id"))
	if err != nil {
		a.writeError(w, dynamicLeaseError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, toDynamicLeaseResponse(lease, nil))
}

//trstctl:mutation
func (a *API) renewDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	leaseID := r.PathValue("lease_id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req dynamicLeaseRenewRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.ExtendSeconds <= 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "extend_seconds must be positive"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := dynamicLeaseMutationBinding("renew", principal, leaseID, req.ExtendSeconds)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		var lease dynsecret.Lease
		if renewer, ok := engine.(boundDynamicLeaseRenewer); ok {
			lease, err = renewer.RenewBound(ctx, leaseID, time.Duration(req.ExtendSeconds)*time.Second, idempotencyKey, binding)
		} else {
			lease, err = engine.Renew(ctx, leaseID, time.Duration(req.ExtendSeconds)*time.Second)
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		return http.StatusOK, toDynamicLeaseResponse(lease, nil), nil
	})
}

//trstctl:mutation
func (a *API) revokeDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	leaseID := r.PathValue("lease_id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := dynamicLeaseMutationBinding("revoke", principal, leaseID, 0)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		var lease dynsecret.Lease
		if revoker, ok := engine.(boundDynamicLeaseRevoker); ok {
			lease, err = revoker.RevokeBound(ctx, leaseID, idempotencyKey, binding)
		} else {
			if err = engine.Revoke(ctx, leaseID); err == nil {
				lease, err = getDynamicLeaseContext(ctx, engine, leaseID)
			}
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		return http.StatusOK, toDynamicLeaseResponse(lease, nil), nil
	})
}

func dynamicLeaseMutationBinding(operation, principal, leaseID string, extendSeconds int) (string, error) {
	canonical := struct {
		Operation     string `json:"operation"`
		Principal     string `json:"principal"`
		LeaseID       string `json:"lease_id"`
		ExtendSeconds int    `json:"extend_seconds,omitempty"`
	}{Operation: "dynamic-secret." + operation, Principal: principal, LeaseID: leaseID, ExtendSeconds: extendSeconds}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

type contextDynamicLeaseReader interface {
	GetLeaseContext(context.Context, string) (dynsecret.Lease, error)
}

func getDynamicLeaseContext(ctx context.Context, lifecycle dynsecret.Lifecycle, leaseID string) (dynsecret.Lease, error) {
	if reader, ok := lifecycle.(contextDynamicLeaseReader); ok {
		return reader.GetLeaseContext(ctx, leaseID)
	}
	return lifecycle.GetLease(leaseID)
}

func toDynamicLeaseResponse(l dynsecret.Lease, credential []byte) dynamicLeaseResponse {
	var hardExpiresAt *time.Time
	if !l.HardExpiresAt.IsZero() {
		hardExpiresAt = &l.HardExpiresAt
	}
	return dynamicLeaseResponse{
		ID: l.ID, Provider: l.Provider, Role: l.Role, State: string(l.State),
		Credential: secretJSONBytes(credential), IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt,
		HardExpiresAt: hardExpiresAt, RevocationStatus: l.RevocationStatus,
		RevokedAt: l.RevokedAt, RevocationCompletedAt: l.RevocationCompletedAt,
	}
}

func dynamicLeaseError(err error) error {
	switch {
	case errors.Is(err, dynsecret.ErrUnknownProvider):
		return errStatus(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, dynsecret.ErrLeaseNotFound):
		return errStatus(http.StatusNotFound, "no such dynamic secret lease")
	case errors.Is(err, dynsecret.ErrLeaseNotActive):
		return errStatus(http.StatusConflict, "dynamic secret lease is not active")
	case errors.Is(err, dynsecret.ErrLeaseHardExpiry):
		return errStatus(http.StatusUnprocessableEntity, "renewal cannot pass the provider's original hard expiry; revoke this lease and create a new credential")
	case errors.Is(err, store.ErrIdempotencyConflict):
		return errStatus(http.StatusConflict, "Idempotency-Key was already used for a different dynamic secret request")
	case errors.Is(err, context.DeadlineExceeded):
		return errStatus(http.StatusGatewayTimeout, "dynamic secret issuance is still pending; retry with the same Idempotency-Key")
	default:
		return err
	}
}

func (s *secretsService) dynamicLeaseEngine(tenantID string) (dynsecret.Lifecycle, error) {
	providers := s.dynamicProviders(tenantID)
	if len(providers) == 0 && s.be.DynamicLifecycleForTenant == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "dynamic secret lease providers are not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if engine, ok := s.leases[tenantID]; ok {
		return engine, nil
	}
	if s.be.DynamicLifecycleForTenant != nil {
		lifecycle, err := s.be.DynamicLifecycleForTenant(tenantID)
		if err != nil {
			return nil, err
		}
		if lifecycle == nil {
			return nil, errStatus(http.StatusServiceUnavailable, "dynamic secret lease lifecycle is not configured")
		}
		s.leases[tenantID] = lifecycle
		return lifecycle, nil
	}
	queue := dynsecret.RevokeQueue(dynsecret.NewMemoryQueue())
	if s.be.DynamicRevokeQueue != nil {
		queue = s.be.DynamicRevokeQueue(tenantID)
	}
	engine, err := dynsecret.New(dynsecret.Config{
		TenantID: tenantID, Providers: providers, Queue: queue, Audit: s.be.Audit,
	})
	if err != nil {
		return nil, err
	}
	s.leases[tenantID] = engine
	return engine, nil
}

func (s *secretsService) dynamicLeaseEngines() []dynsecret.Lifecycle {
	s.mu.Lock()
	defer s.mu.Unlock()
	engines := make([]dynsecret.Lifecycle, 0, len(s.leases))
	for _, engine := range s.leases {
		engines = append(engines, engine)
	}
	return engines
}

func (s *secretsService) ensureDynamicLifecycleTenants() {
	if s.be.DynamicLifecycleTenantIDs == nil {
		return
	}
	for _, tenantID := range s.be.DynamicLifecycleTenantIDs() {
		_, _ = s.dynamicLeaseEngine(tenantID)
	}
}

func (s *secretsService) tickDynamicLeases(ctx context.Context) {
	s.ensureDynamicLifecycleTenants()
	for _, engine := range s.dynamicLeaseEngines() {
		worker := leaseworker.New(engine, s.be.DynamicLeaseWorkerInterval)
		_, _, _ = worker.Tick(ctx)
	}
}
