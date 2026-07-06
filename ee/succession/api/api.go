// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package api is the external PCAS surface (claims 6, 9): request a succession
// (idempotent, AN-5), fetch an identity's succession chain (a response a relying
// party verifies offline with PCAS-07), and record a signed relying-party
// capability acknowledgement (an nhi.rp.ack the PCAS-10 quorum counts). It attaches
// through the feature-neutral api.Option route seam (the ee/pqcmigration precedent);
// no PCAS route, handler, or DTO lives in MPL core. Every mutation flows through the
// shared idempotency path (api.Mutate), so a replayed Idempotency-Key returns the
// original result (claim 6).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
)

// plannableCredentialTypes is the claim-9 identity/credential genus the API accepts,
// mirroring ee/pqcmigration's plannable genus (X.509, SSH, workload-identity SVID,
// API token, secret). Kept local so the API surface does not pull the planner's
// dependency graph into the request path.
var plannableCredentialTypes = map[string]bool{
	"x509": true, "ssh": true, "workload-svid": true, "api-token": true, "secret": true,
}

// RequestSuccessionRequest asks to advance an identity to a new algorithm-epoch.
type RequestSuccessionRequest struct {
	IdentityID      string `json:"identity_id"`
	CredentialType  string `json:"credential_type"`
	TargetAlgorithm string `json:"target_algorithm"`
	PolicyRef       string `json:"policy_ref"`
	DeploymentScope string `json:"deployment_scope"`
}

// RequestSuccessionResponse acknowledges an accepted (idempotent) succession request.
type RequestSuccessionResponse struct {
	RequestID       string    `json:"request_id"`
	IdentityID      string    `json:"identity_id"`
	CredentialType  string    `json:"credential_type"`
	TargetAlgorithm string    `json:"target_algorithm"`
	Status          string    `json:"status"`
	QueuedAt        time.Time `json:"queued_at"`
}

// ChainResponse is an identity's succession chain: the ordered, gapless list of
// opaque encoded dual-signed records (PCAS-04), which a relying party verifies
// offline with PCAS-07.
type ChainResponse struct {
	IdentityID string   `json:"identity_id"`
	Records    [][]byte `json:"records"`
	Count      int      `json:"count"`
}

// AckRequest is a relying party's signed post-quantum-capability acknowledgement.
type AckRequest struct {
	IdentityID   string `json:"identity_id"`
	Epoch        uint64 `json:"epoch"`
	RelyingParty string `json:"relying_party"`
	Signature    []byte `json:"signature"`
}

// AckResponse acknowledges a recorded ack event.
type AckResponse struct {
	AckID        string    `json:"ack_id"`
	IdentityID   string    `json:"identity_id"`
	Epoch        uint64    `json:"epoch"`
	RelyingParty string    `json:"relying_party"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// Service is the PCAS API backend. The concrete implementation is store/log/outbox
// backed (see service.go); handlers depend only on this interface.
type Service interface {
	RequestSuccession(ctx context.Context, tenantID string, req RequestSuccessionRequest) (RequestSuccessionResponse, error)
	FetchChain(ctx context.Context, tenantID, identityID string) (ChainResponse, error)
	RecordAck(ctx context.Context, tenantID string, req AckRequest) (AckResponse, error)
}

// NewAPIOptionsFactory returns the licensed-route factory that attaches the PCAS API
// under the FeaturePCAS block (ee_attach). The concrete service is built from the
// server-provided store, event log, and outbox.
func NewAPIOptionsFactory() editionseam.LicensedAPIOptionsFactory {
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		svc := NewService(d.Store, d.Log, d.Outbox)
		return []api.Option{
			api.WithLicensedRoutes(Routes(svc)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}

// Routes declares the PCAS REST surface. Mutating routes set Mutation:true and read
// Idempotency-Key (AN-5); the shared machinery enforces idempotent replay and folds
// the routes into the served OpenAPI 3.1 document. It is exported so tests can drive
// the exact served routes against a test Service.
func Routes(svc Service) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method: "POST", Path: "/api/v1/pcas/successions", OperationID: "requestSuccession",
			Summary:       "Request an algorithm succession for an identity (idempotent)",
			Handler:       func(a *api.API) http.HandlerFunc { return requestSuccessionHandler(a, svc) },
			RequestSchema: "PCASSuccessionRequest", ResponseSchema: "PCASSuccessionAck",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/chain", OperationID: "getSuccessionChain",
			Summary: "Fetch an identity's succession chain for offline relying-party verification",
			Handler: func(a *api.API) http.HandlerFunc { return chainHandler(a, svc) },
			// identity_id is a query parameter, not a path segment, because stable
			// identity identifiers (e.g. SPIFFE IDs) contain '/' and must not be split
			// across path segments.
			Query:          []api.RouteParam{{Name: "identity_id", Type: "string", Description: "stable identity identifier"}},
			ResponseSchema: "PCASSuccessionChain", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/acks", OperationID: "recordRPAck",
			Summary:       "Record a signed relying-party post-quantum capability acknowledgement",
			Handler:       func(a *api.API) http.HandlerFunc { return ackHandler(a, svc) },
			RequestSchema: "PCASAckRequest", ResponseSchema: "PCASAck",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsWrite,
		},
	}
}

func requestSuccessionHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var req RequestSuccessionRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if req.IdentityID == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id is required")
			}
			if !plannableCredentialTypes[req.CredentialType] {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "credential_type must be one of the claim-9 genus: x509, ssh, workload-svid, api-token, secret")
			}
			if req.TargetAlgorithm == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "target_algorithm is required")
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("pcas_succession", "request", start, opErr) }()
			resp, err := svc.RequestSuccession(ctx, tenantID, req)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, resp, nil
		})
	}
}

func chainHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		identityID := r.URL.Query().Get("identity_id")
		if identityID == "" {
			writeProblem(w, http.StatusBadRequest, "identity_id query parameter is required")
			return
		}
		start := time.Now()
		resp, err := svc.FetchChain(r.Context(), tenantID, identityID)
		a.ObserveFeature("pcas_succession", "chain", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch succession chain")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func ackHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var req AckRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if req.IdentityID == "" || req.RelyingParty == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id and relying_party are required")
			}
			// The signature is the whole point of an acknowledgement: reject a stripped
			// ack at ingestion so an unsigned ack can never reach the quorum (claim 3).
			if len(req.Signature) == 0 {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "signature is required; an unsigned acknowledgement is not accepted")
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("pcas_succession", "ack", start, opErr) }()
			resp, err := svc.RecordAck(ctx, tenantID, req)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, resp, nil
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": detail})
}

func schemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"PCASSuccessionRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":      api.StringSchema(),
			"credential_type":  api.StringSchema(),
			"target_algorithm": api.StringSchema(),
			"policy_ref":       api.StringSchema(),
			"deployment_scope": api.StringSchema(),
		}, "identity_id", "credential_type", "target_algorithm"),
		"PCASSuccessionAck": api.ObjectSchema(map[string]*api.Schema{
			"request_id":       api.StringSchema(),
			"identity_id":      api.StringSchema(),
			"credential_type":  api.StringSchema(),
			"target_algorithm": api.StringSchema(),
			"status":           api.StringSchema(),
			"queued_at":        api.TimestampSchema(),
		}, "request_id", "identity_id", "status"),
		"PCASSuccessionChain": api.ObjectSchema(map[string]*api.Schema{
			"identity_id": api.StringSchema(),
			"records":     api.ArraySchema(api.StringSchema()), // base64-encoded opaque records
			"count":       api.IntegerSchema(),
		}, "identity_id", "records", "count"),
		"PCASAckRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":   api.StringSchema(),
			"epoch":         api.IntegerSchema(),
			"relying_party": api.StringSchema(),
			"signature":     api.StringSchema(), // base64-encoded RP signature
		}, "identity_id", "epoch", "relying_party", "signature"),
		"PCASAck": api.ObjectSchema(map[string]*api.Schema{
			"ack_id":        api.StringSchema(),
			"identity_id":   api.StringSchema(),
			"epoch":         api.IntegerSchema(),
			"relying_party": api.StringSchema(),
			"recorded_at":   api.TimestampSchema(),
		}, "ack_id", "identity_id", "epoch", "relying_party"),
	}
}
