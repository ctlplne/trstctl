// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package api is the external AGID (Agent Identity Lifecycle Enforcement) surface: it
// is the production caller that DRIVES the two AGID user journeys the mechanisms were
// built for but nothing yet invoked from cmd/trstctl.
//
//  1. Chain-bound agent-credential issuance (the paid "chains of authority" feature):
//     a POST accepts a delegation chain + agent-stack representation + attestation
//     (+ optional task envelope) + validity, enqueues an agentid.issue-chain-bound
//     outbox message, and returns an issuance id. The orchestrator (ee/agentid/
//     orchestrator) drains that message, computes the reachability verdict with
//     reach.NewEngine, drives broker.IssueChainBound (which consults the AGID-04
//     in-signer gate via the precondition), and records the result.
//  2. Cascaded revocation (the "verifiable kill"): a POST accepts a subject + reason
//     class, enqueues an agentid.revoke-directive message, and returns a directive id.
//     The orchestrator drains it and drives revoke.NewCascade -> revoke.NewExecutor ->
//     revoke.NewTerminalTransition.
//
// It mirrors ee/succession/api (the PCAS precedent): it attaches through the feature-
// neutral api.Option route seam (WithLicensedRoutes/WithLicensedSchemas), no AGID
// route/handler/DTO lives in MPL core, and every mutation flows through the shared
// idempotency path (api.Mutate) so a replayed Idempotency-Key returns the original
// result (AN-5).
//
// This package holds NO issuance or revocation key: it only stages requests onto the
// AN-6 outbox and serves read models. The mechanisms it drives (verify-before-keygen,
// the cascade, the terminal transition) run in the orchestrator worker, exactly as the
// PCAS API only enqueues and the PCAS orchestrator mints.
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

// IssueChainBoundRequest asks to issue a chain-bound agent credential. The delegation
// chain, agent-stack representation, attestation, and optional task envelope are opaque
// encoded bodies (the same JSON the AGID-02 ledger and the AGID-04a seam carry); the API
// does not parse them — the orchestrator hands them to the mechanisms, which re-verify
// everything cryptographically (INV-A1). AgentID/Method/TrustAnchorRef are the public
// scalars the broker's generic issuance view carries.
type IssueChainBoundRequest struct {
	// AgentID is the requested agent identity's identifier (the broker subject).
	AgentID string `json:"agent_id"`
	// TrustAnchorRef is the asserted trust-anchor reference (a subject handle) forwarded
	// to the in-signer gate for refusal attribution.
	TrustAnchorRef string `json:"trust_anchor_ref"`
	// DesignatedClass names the authority class the chain head is designated as, keying
	// the min-attestation-class policy (claim 10) and the reachability requester class.
	DesignatedClass string `json:"designated_class"`
	// Chain is the opaque encoded delegation chain (root-first RecordEnvelopes) the
	// orchestrator decodes and the gate verifies hop-by-hop.
	Chain []byte `json:"chain"`
	// AgentStackRepr is the opaque encoded agent-stack representation to bind (AGID-03).
	AgentStackRepr []byte `json:"agent_stack_repr"`
	// Attestation is the opaque attestation-evidence body (type + payload).
	Attestation []byte `json:"attestation"`
	// AttestationMethod names the method that produced Attestation.
	AttestationMethod string `json:"attestation_method"`
	// TaskEnvelope is the optional opaque encoded task envelope (AGID-05).
	TaskEnvelope []byte `json:"task_envelope,omitempty"`
	// Scopes are the requested authority scopes (forwarded to the policy gate).
	Scopes []string `json:"scopes,omitempty"`
	// ResourceValues are the resource-selector values of the final record's authority,
	// which the reachability engine resolves to graph start nodes (AGID-06).
	ResourceValues []string `json:"resource_values,omitempty"`
	// TTLSeconds is the caller-requested credential lifetime. The precondition clamps it
	// strictly sub-hour and refuses an over-long request (INV-A7). Zero means "derive
	// from the chain".
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// IssueChainBoundResponse acknowledges an accepted (idempotent) chain-bound issuance.
type IssueChainBoundResponse struct {
	IssuanceID     string    `json:"issuance_id"`
	AgentID        string    `json:"agent_id"`
	TrustAnchorRef string    `json:"trust_anchor_ref"`
	Status         string    `json:"status"`
	QueuedAt       time.Time `json:"queued_at"`
}

// RevokeRequest asks to revoke a subject (a delegation record, agent identity, or
// credential — an opaque subject id) with a reason class (claim 17). The cascade
// determines the descendant set for the subject and drives the verifiable kill.
type RevokeRequest struct {
	// Subject is the opaque subject id to revoke.
	Subject string `json:"subject"`
	// Reason is the directive reason class (compromise, task-completion, policy-change,
	// root-principal-request). An unrecognized class is rejected at ingestion.
	Reason string `json:"reason"`
	// PublishDownstream marks that every descendant job should also publish a downstream
	// trust-plane revocation entry (KRL/CRL) through the outbox (claim 19).
	PublishDownstream bool `json:"publish_downstream,omitempty"`
}

// RevokeResponse acknowledges an accepted (idempotent) revocation directive.
type RevokeResponse struct {
	DirectiveID string    `json:"directive_id"`
	Subject     string    `json:"subject"`
	Reason      string    `json:"reason"`
	Status      string    `json:"status"`
	QueuedAt    time.Time `json:"queued_at"`
}

// ChainResponse is an issued agent credential's delegation chain: the ordered opaque
// delegation records the AGID-09 relying-party verifier re-verifies offline.
type ChainResponse struct {
	CredentialID string   `json:"credential_id"`
	Records      [][]byte `json:"records"`
	Count        int      `json:"count"`
}

// IncompleteJob is one still-open descendant job of a directive (AGID-11 IncompleteJobs):
// its credential id and whether it is a follow-on job. An operator polls this to watch a
// verifiable kill drain to completion.
type IncompleteJob struct {
	CredentialID string `json:"credential_id"`
	FollowOn     bool   `json:"follow_on"`
}

// IncompleteJobsResponse is the incomplete-jobs query result for a directive (AGID-11).
type IncompleteJobsResponse struct {
	DirectiveID string          `json:"directive_id"`
	Jobs        []IncompleteJob `json:"jobs"`
	Count       int             `json:"count"`
}

// RevocationEvidenceResponse is the aggregate revocation-evidence artifact for a directive
// (AGID-11 aggregate.go): the signed, offline-verifiable proof that every enqueued and
// follow-on job completed, plus whether the directive has reached the terminal
// revoked-with-evidence state. Terminal=false with the artifact absent means the directive
// is still draining. The Artifact is the encoded AggregateEvidence a relying party verifies
// offline with VerifyAggregateOffline.
type RevocationEvidenceResponse struct {
	DirectiveID     string   `json:"directive_id"`
	Terminal        bool     `json:"terminal"`
	JobCount        int      `json:"job_count"`
	Missing         []string `json:"missing,omitempty"`
	EvidenceDigests [][]byte `json:"evidence_digests,omitempty"`
	Artifact        []byte   `json:"artifact,omitempty"`
}

// Service is the AGID API backend. The concrete implementation is store/log/outbox
// backed (service.go); handlers depend only on this interface (the PCAS pattern).
type Service interface {
	// IssueChainBound stages a chain-bound issuance as an idempotent outbox job
	// (agentid.issue-chain-bound) for the orchestrator to drive.
	IssueChainBound(ctx context.Context, tenantID string, req IssueChainBoundRequest) (IssueChainBoundResponse, error)
	// Revoke stages a revocation directive as an idempotent outbox job
	// (agentid.revoke-directive) for the orchestrator's cascade to drive.
	Revoke(ctx context.Context, tenantID string, req RevokeRequest) (RevokeResponse, error)
	// FetchChain returns an issued credential's delegation chain (offline-verifiable).
	FetchChain(ctx context.Context, tenantID, credentialID string) (ChainResponse, error)
	// IncompleteJobs returns a directive's still-open descendant jobs (AGID-11).
	IncompleteJobs(ctx context.Context, tenantID, directiveID string) (IncompleteJobsResponse, error)
	// RevocationEvidence returns a directive's aggregate revocation-evidence artifact and
	// terminal verdict (AGID-11).
	RevocationEvidence(ctx context.Context, tenantID, directiveID string) (RevocationEvidenceResponse, error)
}

// NewAPIOptionsFactory returns the licensed-route factory that attaches the AGID API
// under the FeatureAgentDelegation block (ee_attach). The concrete service is built from
// the server-provided store, event log, and outbox — exactly like PCAS
// NewAPIOptionsFactory.
func NewAPIOptionsFactory() editionseam.LicensedAPIOptionsFactory {
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		svc := NewService(d.Store, d.Log, d.Outbox)
		return []api.Option{
			api.WithLicensedRoutes(Routes(svc)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}

// Routes declares the AGID REST surface. Mutating routes set Mutation:true and read the
// Idempotency-Key (AN-5); the shared machinery enforces idempotent replay and folds the
// routes into the served OpenAPI 3.1 document. It is exported so tests can drive the exact
// served routes against a test Service (the PCAS pattern).
func Routes(svc Service) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method: "POST", Path: "/api/v1/agent-delegation/issuances", OperationID: "issueChainBoundCredential",
			Summary:       "Issue a chain-bound agent credential (idempotent)",
			Handler:       func(a *api.API) http.HandlerFunc { return issueHandler(a, svc) },
			RequestSchema: "AGIDIssuanceRequest", ResponseSchema: "AGIDIssuanceAck",
			SuccessCode: "202", Mutation: true, Permission: authz.AgentsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/agent-delegation/revocations", OperationID: "revokeAgentDelegation",
			Summary:       "Revoke a subject and cascade the verifiable kill (idempotent)",
			Handler:       func(a *api.API) http.HandlerFunc { return revokeHandler(a, svc) },
			RequestSchema: "AGIDRevocationRequest", ResponseSchema: "AGIDRevocationAck",
			SuccessCode: "202", Mutation: true, Permission: authz.AgentsWrite,
		},
		{
			Method: "GET", Path: "/api/v1/agent-delegation/chain", OperationID: "getAgentDelegationChain",
			Summary: "Fetch an issued agent credential's delegation chain for offline relying-party verification",
			// credential_id is a query parameter because stable credential identifiers may
			// contain '/' and must not be split across path segments (the PCAS chain rule).
			Handler:        func(a *api.API) http.HandlerFunc { return chainHandler(a, svc) },
			Query:          []api.RouteParam{{Name: "credential_id", Type: "string", Description: "stable issued-credential identifier"}},
			ResponseSchema: "AGIDDelegationChain", SuccessCode: "200", Permission: authz.AgentsRead,
		},
		{
			Method: "GET", Path: "/api/v1/agent-delegation/revocations/incomplete-jobs", OperationID: "getRevocationIncompleteJobs",
			Summary:        "Fetch a revocation directive's still-open descendant jobs (AGID-11 incomplete-jobs query)",
			Handler:        func(a *api.API) http.HandlerFunc { return incompleteJobsHandler(a, svc) },
			Query:          []api.RouteParam{{Name: "directive_id", Type: "string", Description: "revocation directive id"}},
			ResponseSchema: "AGIDIncompleteJobs", SuccessCode: "200", Permission: authz.AgentsRead,
		},
		{
			Method: "GET", Path: "/api/v1/agent-delegation/revocations/evidence", OperationID: "getRevocationEvidence",
			Summary:        "Fetch a revocation directive's aggregate evidence artifact and terminal verdict (AGID-11)",
			Handler:        func(a *api.API) http.HandlerFunc { return evidenceHandler(a, svc) },
			Query:          []api.RouteParam{{Name: "directive_id", Type: "string", Description: "revocation directive id"}},
			ResponseSchema: "AGIDRevocationEvidence", SuccessCode: "200", Permission: authz.AgentsRead,
		},
	}
}

// issueHandler stages a chain-bound issuance idempotently (the PCAS requestSuccessionHandler
// shape): decode, validate the public scalars, then enqueue via the service under the
// Idempotency-Key.
func issueHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var req IssueChainBoundRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if req.AgentID == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "agent_id is required")
			}
			if len(req.Chain) == 0 && len(req.Attestation) == 0 {
				// A chain-bound issuance needs at least a chain or (in the attestation-gated
				// fallback) an attestation; a request carrying neither can never verify, so
				// reject it at ingestion rather than staging a job that will always refuse.
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "at least one of chain or attestation is required for a chain-bound issuance")
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("agentid", "issue-chain-bound", start, opErr) }()
			resp, err := svc.IssueChainBound(ctx, tenantID, req)
			if err != nil {
				opErr = err
				return 0, nil, err
			}
			return http.StatusAccepted, resp, nil
		})
	}
}

// revokeHandler stages a revocation directive idempotently. The reason class is validated
// at ingestion so a malformed reason never reaches the ledger (claim 17).
func revokeHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var req RevokeRequest
			if err := api.DecodeJSON(r, &req); err != nil {
				return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
			}
			if req.Subject == "" {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "subject is required")
			}
			if !validReason(req.Reason) {
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "reason must be one of: compromise, task-completion, policy-change, root-principal-request")
			}
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature("agentid", "revoke-directive", start, opErr) }()
			resp, err := svc.Revoke(ctx, tenantID, req)
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
		credentialID := r.URL.Query().Get("credential_id")
		if credentialID == "" {
			writeProblem(w, http.StatusBadRequest, "credential_id query parameter is required")
			return
		}
		start := time.Now()
		resp, err := svc.FetchChain(r.Context(), tenantID, credentialID)
		a.ObserveFeature("agentid", "chain", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch delegation chain")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func incompleteJobsHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		directiveID := r.URL.Query().Get("directive_id")
		if directiveID == "" {
			writeProblem(w, http.StatusBadRequest, "directive_id query parameter is required")
			return
		}
		start := time.Now()
		resp, err := svc.IncompleteJobs(r.Context(), tenantID, directiveID)
		a.ObserveFeature("agentid", "incomplete-jobs", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch incomplete jobs")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func evidenceHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		directiveID := r.URL.Query().Get("directive_id")
		if directiveID == "" {
			writeProblem(w, http.StatusBadRequest, "directive_id query parameter is required")
			return
		}
		start := time.Now()
		resp, err := svc.RevocationEvidence(r.Context(), tenantID, directiveID)
		a.ObserveFeature("agentid", "revocation-evidence", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch revocation evidence")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// validReason mirrors revoke.ReasonClass.Valid without importing the control-plane revoke
// package into the request path (the PCAS plannableCredentialTypes pattern of keeping the
// accepted genus local to the API surface).
func validReason(r string) bool {
	switch r {
	case "compromise", "task-completion", "policy-change", "root-principal-request":
		return true
	default:
		return false
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
		"AGIDIssuanceRequest": api.ObjectSchema(map[string]*api.Schema{
			"agent_id":           api.StringSchema(),
			"trust_anchor_ref":   api.StringSchema(),
			"designated_class":   api.StringSchema(),
			"chain":              api.StringSchema(), // base64-encoded opaque delegation chain
			"agent_stack_repr":   api.StringSchema(), // base64-encoded opaque agent-stack representation
			"attestation":        api.StringSchema(), // base64-encoded opaque attestation body
			"attestation_method": api.StringSchema(),
			"task_envelope":      api.StringSchema(), // base64-encoded opaque task envelope
			"scopes":             api.ArraySchema(api.StringSchema()),
			"resource_values":    api.ArraySchema(api.StringSchema()),
			"ttl_seconds":        api.IntegerSchema(),
		}, "agent_id"),
		"AGIDIssuanceAck": api.ObjectSchema(map[string]*api.Schema{
			"issuance_id":      api.StringSchema(),
			"agent_id":         api.StringSchema(),
			"trust_anchor_ref": api.StringSchema(),
			"status":           api.StringSchema(),
			"queued_at":        api.TimestampSchema(),
		}, "issuance_id", "agent_id", "status"),
		"AGIDRevocationRequest": api.ObjectSchema(map[string]*api.Schema{
			"subject":            api.StringSchema(),
			"reason":             api.StringSchema(),
			"publish_downstream": api.BooleanSchema(),
		}, "subject", "reason"),
		"AGIDRevocationAck": api.ObjectSchema(map[string]*api.Schema{
			"directive_id": api.StringSchema(),
			"subject":      api.StringSchema(),
			"reason":       api.StringSchema(),
			"status":       api.StringSchema(),
			"queued_at":    api.TimestampSchema(),
		}, "directive_id", "subject", "status"),
		"AGIDDelegationChain": api.ObjectSchema(map[string]*api.Schema{
			"credential_id": api.StringSchema(),
			"records":       api.ArraySchema(api.StringSchema()), // base64-encoded opaque records
			"count":         api.IntegerSchema(),
		}, "credential_id", "records", "count"),
		"AGIDIncompleteJobs": api.ObjectSchema(map[string]*api.Schema{
			"directive_id": api.StringSchema(),
			"jobs": api.ArraySchema(api.ObjectSchema(map[string]*api.Schema{
				"credential_id": api.StringSchema(),
				"follow_on":     api.BooleanSchema(),
			}, "credential_id")),
			"count": api.IntegerSchema(),
		}, "directive_id", "jobs", "count"),
		"AGIDRevocationEvidence": api.ObjectSchema(map[string]*api.Schema{
			"directive_id":     api.StringSchema(),
			"terminal":         api.BooleanSchema(),
			"job_count":        api.IntegerSchema(),
			"missing":          api.ArraySchema(api.StringSchema()),
			"evidence_digests": api.ArraySchema(api.StringSchema()),
			"artifact":         api.StringSchema(), // base64-encoded aggregate evidence artifact
		}, "directive_id", "terminal"),
	}
}
