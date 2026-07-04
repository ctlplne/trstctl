// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/leaseworker"
)

type dynamicLeaseIssueRequest struct {
	Provider   string `json:"provider"`
	Role       string `json:"role"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type dynamicLeaseRenewRequest struct {
	ExtendSeconds int `json:"extend_seconds"`
}

type dynamicLeaseResponse struct {
	ID         string          `json:"id"`
	Provider   string          `json:"provider"`
	Role       string          `json:"role"`
	State      string          `json:"state"`
	Credential secretJSONBytes `json:"credential,omitempty"`
	IssuedAt   time.Time       `json:"issued_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req dynamicLeaseIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Provider == "" || req.Role == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider and role are required")
		}
		if req.TTLSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "ttl_seconds must be positive")
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		lease, credential, err := engine.Issue(ctx, req.Provider, req.Role, time.Duration(req.TTLSeconds)*time.Second, idempotencyKey)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		resp := toDynamicLeaseResponse(lease, credential)
		secret.Wipe(credential)
		return http.StatusCreated, resp, nil
	})
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
	lease, err := engine.GetLease(r.PathValue("lease_id"))
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req dynamicLeaseRenewRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.ExtendSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "extend_seconds must be positive")
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		lease, err := engine.Renew(ctx, leaseID, time.Duration(req.ExtendSeconds)*time.Second)
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		if err := engine.Revoke(ctx, leaseID); err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		lease, err := engine.GetLease(leaseID)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		_, _ = engine.RunRevocations(ctx)
		return http.StatusOK, toDynamicLeaseResponse(lease, nil), nil
	})
}

func toDynamicLeaseResponse(l dynsecret.Lease, credential []byte) dynamicLeaseResponse {
	return dynamicLeaseResponse{
		ID: l.ID, Provider: l.Provider, Role: l.Role, State: string(l.State),
		Credential: secretJSONBytes(credential), IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt,
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
	default:
		return err
	}
}

func (s *secretsService) dynamicLeaseEngine(tenantID string) (*dynsecret.Engine, error) {
	if len(s.be.DynamicProviders) == 0 {
		return nil, errStatus(http.StatusServiceUnavailable, "dynamic secret lease providers are not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if engine, ok := s.leases[tenantID]; ok {
		return engine, nil
	}
	queue := dynsecret.RevokeQueue(dynsecret.NewMemoryQueue())
	if s.be.DynamicRevokeQueue != nil {
		queue = s.be.DynamicRevokeQueue(tenantID)
	}
	engine, err := dynsecret.New(dynsecret.Config{
		TenantID: tenantID, Providers: s.be.DynamicProviders, Queue: queue, Audit: s.be.Audit,
	})
	if err != nil {
		return nil, err
	}
	s.leases[tenantID] = engine
	return engine, nil
}

func (s *secretsService) dynamicLeaseEngines() []*dynsecret.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	engines := make([]*dynsecret.Engine, 0, len(s.leases))
	for _, engine := range s.leases {
		engines = append(engines, engine)
	}
	return engines
}

func (s *secretsService) tickDynamicLeases(ctx context.Context) {
	for _, engine := range s.dynamicLeaseEngines() {
		worker := leaseworker.New(engine, s.be.DynamicLeaseWorkerInterval)
		_, _, _ = worker.Tick(ctx)
	}
}
