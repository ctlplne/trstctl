// SPDX-License-Identifier: BUSL-1.1

// Package api is the external PCAS surface (PCAS-claims-6, 9): request a succession
// (idempotent, AN-5), fetch an identity's succession chain (a response a relying
// party verifies offline with PCAS-07), and record a signed relying-party
// capability acknowledgement (an nhi.rp.ack the PCAS-10 quorum counts). It attaches
// through the feature-neutral api.Option route seam (the internal/pqcmigration precedent);
// no PCAS route, handler, or DTO lives in the static API package. Every mutation flows through the
// shared idempotency path (api.Mutate), so a replayed Idempotency-Key returns the
// original result (PCAS-claim-6).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
)

// plannableCredentialTypes is the PCAS-claim-9 identity/credential genus the API accepts,
// mirroring internal/pqcmigration's plannable genus (X.509, SSH, workload-identity SVID,
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
	DelegationScope string `json:"delegation_scope,omitempty"`
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

type DelegationScopeRequest struct {
	ScopeID       string `json:"scope_id"`
	ParentScopeID string `json:"parent_scope_id,omitempty"`
	EpochFloor    uint64 `json:"epoch_floor"`
}

type DelegationScopeResponse struct {
	ScopeID       string    `json:"scope_id"`
	ParentScopeID string    `json:"parent_scope_id,omitempty"`
	EpochFloor    uint64    `json:"epoch_floor"`
	Status        string    `json:"status"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DelegationFloorRequest struct {
	ScopeID    string `json:"scope_id"`
	EpochFloor uint64 `json:"epoch_floor"`
}

type RecoveryPolicyRequest struct {
	IdentityID   string          `json:"identity_id"`
	Threshold    int             `json:"threshold"`
	Roster       json.RawMessage `json:"roster"`
	TrustRootDER []byte          `json:"trust_root_der,omitempty"`
}

type RecoveryPolicyResponse struct {
	IdentityID string    `json:"identity_id"`
	Status     string    `json:"status"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type RecoveryRequest struct {
	IdentityID           string          `json:"identity_id"`
	DeploymentScope      string          `json:"deployment_scope,omitempty"`
	TargetAlgorithm      string          `json:"target_algorithm"`
	SuccessorHandle      string          `json:"successor_handle"`
	PredecessorEpoch     uint64          `json:"predecessor_epoch"`
	Epoch                uint64          `json:"epoch"`
	PredecessorAlgorithm string          `json:"predecessor_algorithm"`
	PredecessorPublicDER []byte          `json:"predecessor_public_der"`
	TrustRootDER         []byte          `json:"trust_root_der"`
	Authorization        json.RawMessage `json:"authorization"`
}

type AsyncRequestResponse struct {
	RequestID  string    `json:"request_id"`
	Status     string    `json:"status"`
	QueuedAt   time.Time `json:"queued_at"`
	Target     string    `json:"target,omitempty"`
	IdentityID string    `json:"identity_id,omitempty"`
}

type FederationImportRequest struct {
	ForeignDeploymentID  string            `json:"foreign_deployment_id"`
	LocalDeploymentID    string            `json:"local_deployment_id"`
	LocalAuthorityHandle string            `json:"local_authority_handle"`
	IdentityID           string            `json:"identity_id"`
	ForeignTrustRootDER  []byte            `json:"foreign_trust_root_der"`
	LocalBaseEpoch       uint64            `json:"local_base_epoch"`
	ForeignGenesis       json.RawMessage   `json:"foreign_genesis"`
	ForeignChain         []json.RawMessage `json:"foreign_chain,omitempty"`
}

type KEMRewrapRequest struct {
	IdentityID          string   `json:"identity_id"`
	PredecessorHandle   string   `json:"predecessor_handle"`
	PredecessorEpoch    uint64   `json:"predecessor_epoch"`
	SuccessorSignHandle string   `json:"successor_sign_handle"`
	SuccessorKEMHandle  string   `json:"successor_kem_handle"`
	SigningAlgorithm    string   `json:"signing_algorithm"`
	KEMAlgorithm        string   `json:"kem_algorithm"`
	Stages              []string `json:"stages,omitempty"`
}

type IssuerAuthorityRequest struct {
	IssuerID     string `json:"issuer_id"`
	IdentityID   string `json:"identity_id"`
	CurrentEpoch uint64 `json:"current_epoch"`
	CAKeyHandle  string `json:"ca_key_handle"`
	CACertDER    []byte `json:"ca_cert_der,omitempty"`
}

type IssuerAuthorityResponse struct {
	IssuerID     string    `json:"issuer_id"`
	IdentityID   string    `json:"identity_id"`
	CurrentEpoch uint64    `json:"current_epoch"`
	CAKeyHandle  string    `json:"ca_key_handle,omitempty"`
	Status       string    `json:"status"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type IssueLeafRequest struct {
	IssuerID        string `json:"issuer_id"`
	CSRDER          []byte `json:"csr_der"`
	RotationVersion uint64 `json:"rotation_version"`
	TTLSeconds      int64  `json:"ttl_seconds"`
}

type IssueLeafResponse struct {
	IssuerID        string    `json:"issuer_id"`
	IdentityID      string    `json:"identity_id"`
	Epoch           uint64    `json:"epoch"`
	RotationVersion uint64    `json:"rotation_version,omitempty"`
	CertDER         []byte    `json:"cert_der"`
	IssuedAt        time.Time `json:"issued_at"`
}

type IssueStapledLeafRequest struct {
	IssuerID             string `json:"issuer_id"`
	CSRDER               []byte `json:"csr_der"`
	CheckpointIdentityID string `json:"checkpoint_identity_id,omitempty"`
	TTLSeconds           int64  `json:"ttl_seconds"`
}

type RewrapStatusResponse struct {
	IdentityID       string           `json:"identity_id"`
	PredecessorEpoch uint64           `json:"predecessor_epoch,omitempty"`
	Jobs             []RewrapJobState `json:"jobs"`
	Complete         bool             `json:"complete"`
	CheckedAt        time.Time        `json:"checked_at"`
}

type RewrapJobState struct {
	JobID           string    `json:"job_id"`
	Stage           string    `json:"stage"`
	TotalStages     int       `json:"total_stages"`
	CompletedStages int       `json:"completed_stages"`
	Status          string    `json:"status"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RetirementPolicyRequest struct {
	IdentityID            string          `json:"identity_id"`
	PredecessorEpoch      uint64          `json:"predecessor_epoch"`
	Threshold             int             `json:"threshold"`
	Roster                json.RawMessage `json:"roster"`
	ValidityWindowSeconds uint64          `json:"validity_window_seconds,omitempty"`
	PredecessorHandle     string          `json:"predecessor_handle,omitempty"`
}

type RetirementPolicyResponse struct {
	IdentityID            string          `json:"identity_id"`
	PredecessorEpoch      uint64          `json:"predecessor_epoch"`
	Threshold             int             `json:"threshold"`
	Roster                json.RawMessage `json:"roster"`
	ValidityWindowSeconds uint64          `json:"validity_window_seconds"`
	PredecessorHandle     string          `json:"predecessor_handle,omitempty"`
	Status                string          `json:"status"`
	UpdatedAt             time.Time       `json:"updated_at"`
	RewrapComplete        bool            `json:"rewrap_complete"`
}

type PostureReportResponse struct {
	IdentityID              string    `json:"identity_id"`
	TenantID                string    `json:"tenant_id"`
	Algorithm               string    `json:"algorithm"`
	Epoch                   uint64    `json:"epoch"`
	IntroducingRecordDigest []byte    `json:"introducing_record_digest"`
	Signature               []byte    `json:"signature"`
	ReporterPublicDER       []byte    `json:"reporter_public_der"`
	IssuedAt                time.Time `json:"issued_at"`
}

type CheckpointResponse struct {
	IdentityID     string          `json:"identity_id"`
	Epoch          uint64          `json:"epoch"`
	LogTreeSize    uint64          `json:"log_tree_size"`
	LogRoot        []byte          `json:"log_root"`
	Signature      []byte          `json:"signature"`
	CheckpointJSON json.RawMessage `json:"checkpoint"`
	IssuedAt       time.Time       `json:"issued_at"`
}

// FederationBridgeResponse is one imported federation bridge: which foreign
// deployment it trusts, for which identity, and the digest of the imported
// trust root — the digest rather than the DER, so an operator can compare
// against the foreign deployment's published root without this route becoming a
// trust-material export.
type FederationBridgeResponse struct {
	ForeignDeploymentID string    `json:"foreign_deployment_id"`
	IdentityID          string    `json:"identity_id"`
	LocalBaseEpoch      uint64    `json:"local_base_epoch"`
	TrustRootSHA256     string    `json:"trust_root_sha256"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// FederationBridgeListResponse is the served answer to "which bridges have been
// imported" (AUD-9: the table was write-only — POST recorded it and nothing
// could ever read it back).
type FederationBridgeListResponse struct {
	Bridges []FederationBridgeResponse `json:"bridges"`
	Count   int                        `json:"count"`
}

type MisissuanceListResponse struct {
	Findings []MisissuanceResponse `json:"findings"`
	Count    int                   `json:"count"`
}

type MisissuanceResponse struct {
	IdentityID    string          `json:"identity_id"`
	Epoch         uint64          `json:"epoch"`
	RecordADigest []byte          `json:"record_a_digest"`
	RecordBDigest []byte          `json:"record_b_digest"`
	SignerA       string          `json:"signer_a"`
	SignerB       string          `json:"signer_b"`
	ProofJSON     json.RawMessage `json:"proof"`
	DetectedAt    time.Time       `json:"detected_at"`
}

// Service is the PCAS API backend. The concrete implementation is store/log/outbox
// backed (see service.go); handlers depend only on this interface.
type Service interface {
	RequestSuccession(ctx context.Context, tenantID string, req RequestSuccessionRequest) (RequestSuccessionResponse, error)
	FetchChain(ctx context.Context, tenantID, identityID string) (ChainResponse, error)
	RecordAck(ctx context.Context, tenantID string, req AckRequest) (AckResponse, error)
	ConfigureDelegationScope(ctx context.Context, tenantID string, req DelegationScopeRequest) (DelegationScopeResponse, error)
	RaiseDelegationFloor(ctx context.Context, tenantID string, req DelegationFloorRequest) (DelegationScopeResponse, error)
	ConfigureRecoveryPolicy(ctx context.Context, tenantID string, req RecoveryPolicyRequest) (RecoveryPolicyResponse, error)
	RequestRecovery(ctx context.Context, tenantID string, req RecoveryRequest) (AsyncRequestResponse, error)
	RequestFederationImport(ctx context.Context, tenantID string, req FederationImportRequest) (AsyncRequestResponse, error)
	RequestKEMRewrap(ctx context.Context, tenantID string, req KEMRewrapRequest) (AsyncRequestResponse, error)
	RegisterIssuerAuthority(ctx context.Context, tenantID string, req IssuerAuthorityRequest) (IssuerAuthorityResponse, error)
	IssueIssuerLeaf(ctx context.Context, tenantID string, req IssueLeafRequest) (IssueLeafResponse, error)
	IssueStapledLeaf(ctx context.Context, tenantID string, req IssueStapledLeafRequest) (IssueLeafResponse, error)
	RewrapStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RewrapStatusResponse, error)
	ConfigureRetirementPolicy(ctx context.Context, tenantID string, req RetirementPolicyRequest) (RetirementPolicyResponse, error)
	RetirementStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RetirementPolicyResponse, bool, error)
	LatestCheckpoint(ctx context.Context, tenantID, identityID string) (CheckpointResponse, bool, error)
	PostureReport(ctx context.Context, tenantID, identityID string) (PostureReportResponse, bool, error)
	ListMisissuance(ctx context.Context, tenantID string) (MisissuanceListResponse, error)
	ListFederationBridges(ctx context.Context, tenantID string) (FederationBridgeListResponse, error)
}

// NewAPIOptionsFactory returns the licensed-route factory that attaches the PCAS API
// under the FeaturePCAS block (ee_attach). The concrete service is built from the
// server-provided store, event log, and outbox.
func NewAPIOptionsFactory(opts ...ServiceOption) editionseam.LicensedAPIOptionsFactory {
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		serviceOpts := append([]ServiceOption{WithSignerStoreDir(d.SignerKeyStoreDir), WithKEMCustody(d.KEMCustody)}, opts...)
		svc := NewService(d.Store, d.Log, d.Outbox, serviceOpts...)
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
		{
			Method: "POST", Path: "/api/v1/pcas/delegation/scopes", OperationID: "configurePCASDelegationScope",
			Summary:       "Configure a signer-enforced PCAS delegation scope",
			Handler:       func(a *api.API) http.HandlerFunc { return delegationScopeHandler(a, svc) },
			RequestSchema: "PCASDelegationScopeRequest", ResponseSchema: "PCASDelegationScope",
			SuccessCode: "200", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/delegation/floors", OperationID: "raisePCASDelegationFloor",
			Summary:       "Raise a signer-enforced PCAS delegation epoch floor",
			Handler:       func(a *api.API) http.HandlerFunc { return delegationFloorHandler(a, svc) },
			RequestSchema: "PCASDelegationFloorRequest", ResponseSchema: "PCASDelegationScope",
			SuccessCode: "200", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/recovery/policies", OperationID: "configurePCASRecoveryPolicy",
			Summary:       "Configure a threshold recovery policy for an identity",
			Handler:       func(a *api.API) http.HandlerFunc { return recoveryPolicyHandler(a, svc) },
			RequestSchema: "PCASRecoveryPolicyRequest", ResponseSchema: "PCASRecoveryPolicy",
			SuccessCode: "200", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/recovery/requests", OperationID: "requestPCASRecovery",
			Summary:       "Queue a threshold-authenticated PCAS recovery mint",
			Handler:       func(a *api.API) http.HandlerFunc { return recoveryRequestHandler(a, svc) },
			RequestSchema: "PCASRecoveryRequest", ResponseSchema: "PCASAsyncRequest",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/federation/bridges", OperationID: "listPCASFederationBridges",
			Summary:        "List imported PCAS federation bridges with their trust-root digests",
			Handler:        func(a *api.API) http.HandlerFunc { return federationBridgesHandler(a, svc) },
			ResponseSchema: "PCASFederationBridgeList", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/federation/imports", OperationID: "requestPCASFederationImport",
			Summary:       "Queue a PCAS federation bridge import",
			Handler:       func(a *api.API) http.HandlerFunc { return federationImportHandler(a, svc) },
			RequestSchema: "PCASFederationImportRequest", ResponseSchema: "PCASAsyncRequest",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/kem/rewraps", OperationID: "requestPCASKEMRewrap",
			Summary:       "Queue a signer-custodied PCAS KEM re-wrap",
			Handler:       func(a *api.API) http.HandlerFunc { return kemRewrapHandler(a, svc) },
			RequestSchema: "PCASKEMRewrapRequest", ResponseSchema: "PCASAsyncRequest",
			SuccessCode: "202", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/issuers", OperationID: "registerPCASIssuerAuthority",
			Summary:       "Register an issuer authority's current PCAS epoch",
			Handler:       func(a *api.API) http.HandlerFunc { return issuerAuthorityHandler(a, svc) },
			RequestSchema: "PCASIssuerAuthorityRequest", ResponseSchema: "PCASIssuerAuthority",
			SuccessCode: "200", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/issuers/leaf", OperationID: "issuePCASIssuerLeaf",
			Summary:       "Issue a real X.509 leaf carrying the issuer PCAS epoch tuple",
			Handler:       func(a *api.API) http.HandlerFunc { return issueLeafHandler(a, svc) },
			RequestSchema: "PCASIssueLeafRequest", ResponseSchema: "PCASIssuedLeaf",
			SuccessCode: "201", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/staple/leaf", OperationID: "issuePCASStapledLeaf",
			Summary:       "Issue a real X.509 leaf carrying a PCAS succession attachment",
			Handler:       func(a *api.API) http.HandlerFunc { return issueStapledLeafHandler(a, svc) },
			RequestSchema: "PCASIssueStapledLeafRequest", ResponseSchema: "PCASIssuedLeaf",
			SuccessCode: "201", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/rewrap", OperationID: "getPCASRewrapStatus",
			Summary: "Fetch PCAS KEM re-wrap status for an identity",
			Handler: func(a *api.API) http.HandlerFunc { return rewrapStatusHandler(a, svc) },
			Query: []api.RouteParam{
				{Name: "identity_id", Type: "string", Description: "stable identity identifier"},
				{Name: "predecessor_epoch", Type: "integer", Description: "predecessor epoch; 0 returns all stages"},
			},
			ResponseSchema: "PCASRewrapStatus", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "POST", Path: "/api/v1/pcas/retirement/policies", OperationID: "configurePCASRetirementPolicy",
			Summary:       "Configure the RP acknowledgement quorum for PCAS retirement",
			Handler:       func(a *api.API) http.HandlerFunc { return retirementPolicyHandler(a, svc) },
			RequestSchema: "PCASRetirementPolicyRequest", ResponseSchema: "PCASRetirementPolicy",
			SuccessCode: "200", Mutation: true, Permission: authz.CertsWrite,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/retirement", OperationID: "getPCASRetirementStatus",
			Summary: "Fetch PCAS retirement status for an identity epoch",
			Handler: func(a *api.API) http.HandlerFunc { return retirementStatusHandler(a, svc) },
			Query: []api.RouteParam{
				{Name: "identity_id", Type: "string", Description: "stable identity identifier"},
				{Name: "predecessor_epoch", Type: "integer", Description: "predecessor epoch being retired"},
			},
			ResponseSchema: "PCASRetirementPolicy", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/checkpoints", OperationID: "getPCASCheckpoint",
			Summary:        "Fetch the latest signed PCAS epoch checkpoint for an identity",
			Handler:        func(a *api.API) http.HandlerFunc { return checkpointHandler(a, svc) },
			Query:          []api.RouteParam{{Name: "identity_id", Type: "string", Description: "stable identity identifier"}},
			ResponseSchema: "PCASCheckpoint", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/posture", OperationID: "getPCASPostureReport",
			Summary:        "Fetch a signed standalone PCAS posture report for an identity",
			Handler:        func(a *api.API) http.HandlerFunc { return postureHandler(a, svc) },
			Query:          []api.RouteParam{{Name: "identity_id", Type: "string", Description: "stable identity identifier"}},
			ResponseSchema: "PCASPostureReport", SuccessCode: "200", Permission: authz.CertsRead,
		},
		{
			Method: "GET", Path: "/api/v1/pcas/misissuance", OperationID: "listPCASMisissuance",
			Summary:        "List signer-detected PCAS misissuance findings",
			Handler:        func(a *api.API) http.HandlerFunc { return misissuanceHandler(a, svc) },
			ResponseSchema: "PCASMisissuanceList", SuccessCode: "200", Permission: authz.CertsRead,
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
				return 0, nil, api.ErrStatus(http.StatusBadRequest, "credential_type must be one of the PCAS-claim-9 genus: x509, ssh, workload-svid, api-token, secret")
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
			// ack at ingestion so an unsigned ack can never reach the quorum (PCAS-claim-3).
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

func delegationScopeHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_delegation", "scope", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req DelegationScopeRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.ScopeID == "" {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "scope_id is required")
		}
		resp, err := svc.ConfigureDelegationScope(ctx, tenantID, req)
		return http.StatusOK, resp, err
	})
}

func delegationFloorHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_delegation", "floor", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req DelegationFloorRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.ScopeID == "" {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "scope_id is required")
		}
		resp, err := svc.RaiseDelegationFloor(ctx, tenantID, req)
		return http.StatusOK, resp, err
	})
}

func recoveryPolicyHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_recovery", "policy", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req RecoveryPolicyRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IdentityID == "" || req.Threshold <= 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id and positive threshold are required")
		}
		resp, err := svc.ConfigureRecoveryPolicy(ctx, tenantID, req)
		return http.StatusOK, resp, err
	})
}

func recoveryRequestHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_recovery", "request", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req RecoveryRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IdentityID == "" || req.TargetAlgorithm == "" || req.SuccessorHandle == "" || req.Epoch == 0 || len(req.Authorization) == 0 || len(req.TrustRootDER) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id, target_algorithm, successor_handle, epoch, trust_root_der, and authorization are required")
		}
		resp, err := svc.RequestRecovery(ctx, tenantID, req)
		return http.StatusAccepted, resp, err
	})
}

func federationImportHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_federation", "import", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req FederationImportRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.ForeignDeploymentID == "" || req.LocalDeploymentID == "" || req.LocalAuthorityHandle == "" || req.IdentityID == "" || len(req.ForeignTrustRootDER) == 0 || len(req.ForeignGenesis) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "foreign_deployment_id, local_deployment_id, local_authority_handle, identity_id, foreign_trust_root_der, and foreign_genesis are required")
		}
		resp, err := svc.RequestFederationImport(ctx, tenantID, req)
		return http.StatusAccepted, resp, err
	})
}

func kemRewrapHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_kem", "rewrap", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req KEMRewrapRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IdentityID == "" || req.PredecessorHandle == "" || req.SuccessorSignHandle == "" || req.SuccessorKEMHandle == "" || req.SigningAlgorithm == "" || req.KEMAlgorithm == "" {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id, predecessor_handle, successor handles, signing_algorithm, and kem_algorithm are required")
		}
		resp, err := svc.RequestKEMRewrap(ctx, tenantID, req)
		return http.StatusAccepted, resp, err
	})
}

func issuerAuthorityHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_issuer", "register", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req IssuerAuthorityRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IssuerID == "" || req.IdentityID == "" || req.CAKeyHandle == "" || len(req.CACertDER) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "issuer_id, identity_id, ca_key_handle, and ca_cert_der are required")
		}
		resp, err := svc.RegisterIssuerAuthority(ctx, tenantID, req)
		return http.StatusOK, resp, err
	})
}

func issueLeafHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_issuer", "issue_leaf", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req IssueLeafRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IssuerID == "" || len(req.CSRDER) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "issuer_id and csr_der are required")
		}
		resp, err := svc.IssueIssuerLeaf(ctx, tenantID, req)
		return mapPCASServiceError(http.StatusCreated, resp, err)
	})
}

func issueStapledLeafHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_staple", "issue_leaf", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req IssueStapledLeafRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IssuerID == "" || len(req.CSRDER) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "issuer_id and csr_der are required")
		}
		resp, err := svc.IssueStapledLeaf(ctx, tenantID, req)
		return mapPCASServiceError(http.StatusCreated, resp, err)
	})
}

func rewrapStatusHandler(a *api.API, svc Service) http.HandlerFunc {
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
		epoch, err := parseOptionalUint(r.URL.Query().Get("predecessor_epoch"))
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "predecessor_epoch must be an unsigned integer")
			return
		}
		start := time.Now()
		resp, err := svc.RewrapStatus(r.Context(), tenantID, identityID, epoch)
		a.ObserveFeature("pcas_kem", "rewrap_status", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch PCAS rewrap status")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func retirementPolicyHandler(a *api.API, svc Service) http.HandlerFunc {
	return mutationHandler(a, "pcas_retirement", "policy", func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req RetirementPolicyRequest
		if err := api.DecodeJSON(r, &req); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if req.IdentityID == "" || req.Threshold <= 0 || len(req.Roster) == 0 {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "identity_id, positive threshold, and roster are required")
		}
		resp, err := svc.ConfigureRetirementPolicy(ctx, tenantID, req)
		return http.StatusOK, resp, err
	})
}

func retirementStatusHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		identityID := r.URL.Query().Get("identity_id")
		epoch, err := parseOptionalUint(r.URL.Query().Get("predecessor_epoch"))
		if identityID == "" || err != nil {
			writeProblem(w, http.StatusBadRequest, "identity_id and numeric predecessor_epoch are required")
			return
		}
		start := time.Now()
		resp, found, err := svc.RetirementStatus(r.Context(), tenantID, identityID, epoch)
		a.ObserveFeature("pcas_retirement", "status", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch PCAS retirement status")
			return
		}
		if !found {
			writeProblem(w, http.StatusNotFound, "PCAS retirement policy not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func checkpointHandler(a *api.API, svc Service) http.HandlerFunc {
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
		resp, found, err := svc.LatestCheckpoint(r.Context(), tenantID, identityID)
		a.ObserveFeature("pcas_checkpoint", "get", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to fetch PCAS checkpoint")
			return
		}
		if !found {
			writeProblem(w, http.StatusNotFound, "PCAS checkpoint not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func postureHandler(a *api.API, svc Service) http.HandlerFunc {
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
		resp, found, err := svc.PostureReport(r.Context(), tenantID, identityID)
		a.ObserveFeature("pcas_posture", "get", start, err)
		if err != nil {
			if errors.Is(err, ErrSignerUnavailable) {
				writeProblem(w, http.StatusServiceUnavailable, "PCAS signer is unavailable")
				return
			}
			writeProblem(w, http.StatusInternalServerError, "failed to build PCAS posture report")
			return
		}
		if !found {
			writeProblem(w, http.StatusNotFound, "PCAS posture not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func federationBridgesHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		start := time.Now()
		resp, err := svc.ListFederationBridges(r.Context(), tenantID)
		a.ObserveFeature("pcas_federation", "list_bridges", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to list PCAS federation bridges")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func misissuanceHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		start := time.Now()
		resp, err := svc.ListMisissuance(r.Context(), tenantID)
		a.ObserveFeature("pcas_monitor", "misissuance", start, err)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "failed to list PCAS misissuance findings")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func parseOptionalUint(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	return strconv.ParseUint(raw, 10, 64)
}

func mapPCASServiceError(okStatus int, resp any, err error) (int, any, error) {
	if err == nil {
		return okStatus, resp, nil
	}
	switch {
	case errors.Is(err, ErrIssuerNotFound), errors.Is(err, ErrCheckpointNotFound):
		return 0, nil, api.ErrWithStatus(http.StatusNotFound, err)
	case errors.Is(err, ErrSignerUnavailable):
		return 0, nil, api.ErrWithStatus(http.StatusServiceUnavailable, err)
	default:
		return 0, nil, err
	}
}

func mutationHandler(a *api.API, feature, action string, fn func(context.Context, string, *http.Request) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.Mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			start := time.Now()
			var opErr error
			defer func() { a.ObserveFeature(feature, action, start, opErr) }()
			status, resp, err := fn(ctx, tenantID, r)
			if err != nil {
				opErr = err
			}
			return status, resp, err
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
			"delegation_scope": api.StringSchema(),
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
		"PCASDelegationScopeRequest": api.ObjectSchema(map[string]*api.Schema{
			"scope_id":        api.StringSchema(),
			"parent_scope_id": api.StringSchema(),
			"epoch_floor":     api.IntegerSchema(),
		}, "scope_id"),
		"PCASDelegationFloorRequest": api.ObjectSchema(map[string]*api.Schema{
			"scope_id":    api.StringSchema(),
			"epoch_floor": api.IntegerSchema(),
		}, "scope_id", "epoch_floor"),
		"PCASDelegationScope": api.ObjectSchema(map[string]*api.Schema{
			"scope_id":        api.StringSchema(),
			"parent_scope_id": api.StringSchema(),
			"epoch_floor":     api.IntegerSchema(),
			"status":          api.StringSchema(),
			"updated_at":      api.TimestampSchema(),
		}, "scope_id", "epoch_floor", "status"),
		"PCASRecoveryPolicyRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":    api.StringSchema(),
			"threshold":      api.IntegerSchema(),
			"roster":         api.StringSchema(),
			"trust_root_der": api.StringSchema(),
		}, "identity_id", "threshold", "roster"),
		"PCASRecoveryPolicy": api.ObjectSchema(map[string]*api.Schema{
			"identity_id": api.StringSchema(),
			"status":      api.StringSchema(),
			"updated_at":  api.TimestampSchema(),
		}, "identity_id", "status"),
		"PCASRecoveryRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":            api.StringSchema(),
			"deployment_scope":       api.StringSchema(),
			"target_algorithm":       api.StringSchema(),
			"successor_handle":       api.StringSchema(),
			"predecessor_epoch":      api.IntegerSchema(),
			"epoch":                  api.IntegerSchema(),
			"predecessor_algorithm":  api.StringSchema(),
			"predecessor_public_der": api.StringSchema(),
			"trust_root_der":         api.StringSchema(),
			"authorization":          api.StringSchema(),
		}, "identity_id", "target_algorithm", "successor_handle", "epoch", "trust_root_der", "authorization"),
		"PCASAsyncRequest": api.ObjectSchema(map[string]*api.Schema{
			"request_id":  api.StringSchema(),
			"status":      api.StringSchema(),
			"queued_at":   api.TimestampSchema(),
			"target":      api.StringSchema(),
			"identity_id": api.StringSchema(),
		}, "request_id", "status", "queued_at"),
		"PCASFederationImportRequest": api.ObjectSchema(map[string]*api.Schema{
			"foreign_deployment_id":  api.StringSchema(),
			"local_deployment_id":    api.StringSchema(),
			"local_authority_handle": api.StringSchema(),
			"identity_id":            api.StringSchema(),
			"foreign_trust_root_der": api.StringSchema(),
			"local_base_epoch":       api.IntegerSchema(),
			"foreign_genesis":        api.StringSchema(),
			"foreign_chain":          api.ArraySchema(api.StringSchema()),
		}, "foreign_deployment_id", "local_deployment_id", "local_authority_handle", "identity_id", "foreign_trust_root_der", "foreign_genesis"),
		"PCASKEMRewrapRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":           api.StringSchema(),
			"predecessor_handle":    api.StringSchema(),
			"predecessor_epoch":     api.IntegerSchema(),
			"successor_sign_handle": api.StringSchema(),
			"successor_kem_handle":  api.StringSchema(),
			"signing_algorithm":     api.StringSchema(),
			"kem_algorithm":         api.StringSchema(),
			"stages":                api.ArraySchema(api.StringSchema()),
		}, "identity_id", "predecessor_handle", "successor_sign_handle", "successor_kem_handle", "signing_algorithm", "kem_algorithm"),
		"PCASIssuerAuthorityRequest": api.ObjectSchema(map[string]*api.Schema{
			"issuer_id":     api.StringSchema(),
			"identity_id":   api.StringSchema(),
			"current_epoch": api.IntegerSchema(),
			"ca_key_handle": api.StringSchema(),
			"ca_cert_der":   api.StringSchema(),
		}, "issuer_id", "identity_id", "ca_key_handle", "ca_cert_der"),
		"PCASIssuerAuthority": api.ObjectSchema(map[string]*api.Schema{
			"issuer_id":     api.StringSchema(),
			"identity_id":   api.StringSchema(),
			"current_epoch": api.IntegerSchema(),
			"ca_key_handle": api.StringSchema(),
			"status":        api.StringSchema(),
			"updated_at":    api.TimestampSchema(),
		}, "issuer_id", "identity_id", "status"),
		"PCASIssueLeafRequest": api.ObjectSchema(map[string]*api.Schema{
			"issuer_id":        api.StringSchema(),
			"csr_der":          api.StringSchema(),
			"rotation_version": api.IntegerSchema(),
			"ttl_seconds":      api.IntegerSchema(),
		}, "issuer_id", "csr_der"),
		"PCASIssueStapledLeafRequest": api.ObjectSchema(map[string]*api.Schema{
			"issuer_id":              api.StringSchema(),
			"csr_der":                api.StringSchema(),
			"checkpoint_identity_id": api.StringSchema(),
			"ttl_seconds":            api.IntegerSchema(),
		}, "issuer_id", "csr_der"),
		"PCASIssuedLeaf": api.ObjectSchema(map[string]*api.Schema{
			"issuer_id":        api.StringSchema(),
			"identity_id":      api.StringSchema(),
			"epoch":            api.IntegerSchema(),
			"rotation_version": api.IntegerSchema(),
			"cert_der":         api.StringSchema(),
			"issued_at":        api.TimestampSchema(),
		}, "issuer_id", "identity_id", "epoch", "cert_der", "issued_at"),
		"PCASRewrapStatus": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":       api.StringSchema(),
			"predecessor_epoch": api.IntegerSchema(),
			"jobs": api.ArraySchema(api.ObjectSchema(map[string]*api.Schema{
				"job_id":           api.StringSchema(),
				"stage":            api.StringSchema(),
				"total_stages":     api.IntegerSchema(),
				"completed_stages": api.IntegerSchema(),
				"status":           api.StringSchema(),
				"updated_at":       api.TimestampSchema(),
			}, "job_id", "stage", "status")),
			"complete":   api.BooleanSchema(),
			"checked_at": api.TimestampSchema(),
		}, "identity_id", "jobs", "complete", "checked_at"),
		"PCASRetirementPolicyRequest": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":             api.StringSchema(),
			"predecessor_epoch":       api.IntegerSchema(),
			"threshold":               api.IntegerSchema(),
			"roster":                  api.StringSchema(),
			"validity_window_seconds": api.IntegerSchema(),
			"predecessor_handle":      api.StringSchema(),
		}, "identity_id", "predecessor_epoch", "threshold", "roster"),
		"PCASRetirementPolicy": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":             api.StringSchema(),
			"predecessor_epoch":       api.IntegerSchema(),
			"threshold":               api.IntegerSchema(),
			"roster":                  api.StringSchema(),
			"validity_window_seconds": api.IntegerSchema(),
			"predecessor_handle":      api.StringSchema(),
			"status":                  api.StringSchema(),
			"updated_at":              api.TimestampSchema(),
			"rewrap_complete":         api.BooleanSchema(),
		}, "identity_id", "predecessor_epoch", "threshold", "status"),
		"PCASCheckpoint": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":   api.StringSchema(),
			"epoch":         api.IntegerSchema(),
			"log_tree_size": api.IntegerSchema(),
			"log_root":      api.StringSchema(),
			"signature":     api.StringSchema(),
			"checkpoint":    api.StringSchema(),
			"issued_at":     api.TimestampSchema(),
		}, "identity_id", "epoch", "signature"),
		"PCASPostureReport": api.ObjectSchema(map[string]*api.Schema{
			"identity_id":               api.StringSchema(),
			"tenant_id":                 api.StringSchema(),
			"algorithm":                 api.StringSchema(),
			"epoch":                     api.IntegerSchema(),
			"introducing_record_digest": api.StringSchema(),
			"signature":                 api.StringSchema(),
			"reporter_public_der":       api.StringSchema(),
			"issued_at":                 api.TimestampSchema(),
		}, "identity_id", "tenant_id", "algorithm", "epoch", "signature"),
		"PCASFederationBridge": api.ObjectSchema(map[string]*api.Schema{
			"foreign_deployment_id": api.StringSchema(),
			"identity_id":           api.StringSchema(),
			"local_base_epoch":      api.IntegerSchema(),
			"trust_root_sha256":     api.StringSchema(),
			"updated_at":            api.TimestampSchema(),
		}, "foreign_deployment_id", "identity_id", "local_base_epoch", "trust_root_sha256"),
		"PCASFederationBridgeList": api.ObjectSchema(map[string]*api.Schema{
			"bridges": api.ArraySchema(api.SchemaRef("PCASFederationBridge")),
			"count":   api.IntegerSchema(),
		}, "bridges", "count"),
		"PCASMisissuanceList": api.ObjectSchema(map[string]*api.Schema{
			"findings": api.ArraySchema(api.ObjectSchema(map[string]*api.Schema{
				"identity_id":     api.StringSchema(),
				"epoch":           api.IntegerSchema(),
				"record_a_digest": api.StringSchema(),
				"record_b_digest": api.StringSchema(),
				"signer_a":        api.StringSchema(),
				"signer_b":        api.StringSchema(),
				"proof":           api.StringSchema(),
				"detected_at":     api.TimestampSchema(),
			}, "identity_id", "epoch", "record_a_digest", "record_b_digest")),
			"count": api.IntegerSchema(),
		}, "findings", "count"),
	}
}
