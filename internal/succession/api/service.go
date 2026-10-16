// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	pcasdelegation "trstctl.com/trstctl/internal/succession/delegation"
	pcasissuer "trstctl.com/trstctl/internal/succession/issuer"
	pcasrecovery "trstctl.com/trstctl/internal/succession/recovery"
	pcasstaple "trstctl.com/trstctl/internal/succession/staple"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// SuccessionRequestDestination is the outbox destination for an accepted succession
// request. The signer-side orchestrator (PCAS-08) consumes it and mints the
// successor; the IdempotencyKey renders redeliveries exactly-once (AN-5 ↔ AN-6).
const (
	GenesisRequestDestination    = "pcas.genesis-request"
	SuccessionRequestDestination = "pcas.succession-request"
	RecoveryRequestDestination   = "pcas.recovery-request"
	FederationImportDestination  = "pcas.federation-import"
	KEMRewrapDestination         = "pcas.kem-rewrap"
	DelegationScopeDestination   = "pcas.delegation-scope"
	DelegationFloorDestination   = "pcas.delegation-floor"
)

// service is the store/log/outbox-backed PCAS API Service. Request-succession
// enqueues an idempotent job through the core outbox; chain-fetch reads the
// RLS-scoped succession store; ack-record appends a signed nhi.rp.ack to the AN-2
// ledger. HTTP-level idempotency (api.Mutate) makes a replayed Idempotency-Key
// return the original result without re-invoking these methods (PCAS-claim-6).
type service struct {
	store  *corestore.Store
	repo   *pcasstore.Repo
	log    *events.Log
	outbox *orchestrator.Outbox
	kem    editionseam.KEMCustody
	// Breadth outbox topics, resolved from pcas.{recovery,federation,kem}.
	// outbox_topic (AUD-7: the config was validated and never read — an operator
	// who re-pointed a topic still enqueued to the hardcoded constant). Empty
	// falls back to the canonical constants; the dispatch side resolves the SAME
	// configuration, so both ends of the outbox always agree.
	recoveryTopic   string
	federationTopic string
	kemTopic        string
}

type ServiceOption func(*service)

func WithKEMCustody(kem editionseam.KEMCustody) ServiceOption {
	return func(s *service) { s.kem = kem }
}

// WithOutboxTopics resolves the breadth destinations from operator
// configuration (pcas.recovery/federation/kem.outbox_topic). Blank values keep
// the canonical defaults, so an unset config changes nothing.
func WithOutboxTopics(recovery, federation, kem string) ServiceOption {
	return func(s *service) {
		s.recoveryTopic = strings.TrimSpace(recovery)
		s.federationTopic = strings.TrimSpace(federation)
		s.kemTopic = strings.TrimSpace(kem)
	}
}

// topicOr returns configured when non-empty, else the canonical fallback.
func topicOr(configured, fallback string) string {
	if configured != "" {
		return configured
	}
	return fallback
}

var (
	ErrIssuerNotFound     = errors.New("pcas api: issuer authority not found")
	ErrSignerUnavailable  = errors.New("pcas api: signer custody unavailable")
	ErrCheckpointNotFound = errors.New("pcas api: checkpoint not found")
)

const defaultReporterHandle = "pcas-checkpoint-signer"

// NewService builds the store/log/outbox-backed PCAS API Service. It is exported so
// the attach seam and integration tests construct the concrete service directly.
func NewService(store *corestore.Store, log *events.Log, outbox *orchestrator.Outbox, opts ...ServiceOption) Service {
	s := &service{store: store, log: log, outbox: outbox}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if store != nil {
		s.repo = pcasstore.New(store)
	}
	return s
}

var _ Service = (*service)(nil)

// RegisterGenesis queues first-use signer custody and a trust-root-attested
// public anchor. No key generation occurs inside the API request process.
func (s *service) RegisterGenesis(ctx context.Context, tenantID string, req GenesisRegistrationRequest) (AsyncRequestResponse, error) {
	if s.store == nil || s.outbox == nil {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS genesis outbox is unavailable")
	}
	if _, err := succession.GenesisDigest(succession.GenesisRecord{Algorithm: crypto.Algorithm(req.Algorithm)}); err != nil {
		return AsyncRequestResponse{}, api.ErrWithStatus(http.StatusBadRequest, fmt.Errorf("unsupported PCAS genesis algorithm: %w", err))
	}
	if s.repo != nil {
		if _, found, err := s.repo.GetGenesis(ctx, tenantID, req.IdentityID); err != nil {
			return AsyncRequestResponse{}, err
		} else if found {
			return AsyncRequestResponse{}, api.ErrStatus(http.StatusConflict,
				"PCAS identity already has an immutable genesis; read its signed chain before requesting a new epoch")
		}
	}
	requestID := events.NewID()
	queuedAt := time.Now().UTC()
	var actor *events.Actor
	if attributed, ok := events.ActorFromContext(ctx); ok {
		actor = &attributed
	}
	payload, err := json.Marshal(struct {
		RequestID string                     `json:"request_id"`
		QueuedAt  time.Time                  `json:"queued_at"`
		Request   GenesisRegistrationRequest `json:"request"`
		Actor     *events.Actor              `json:"actor,omitempty"`
	}{RequestID: requestID, QueuedAt: queuedAt, Request: req, Actor: actor})
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: GenesisRequestDestination, IdempotencyKey: requestID, Payload: payload,
		})
		return err
	}); err != nil {
		return AsyncRequestResponse{}, fmt.Errorf("pcas api: enqueue genesis: %w", err)
	}
	return AsyncRequestResponse{RequestID: requestID, IdentityID: req.IdentityID, Status: "queued",
		QueuedAt: queuedAt, StatusURL: "/api/v1/pcas/requests/" + requestID}, nil
}

// GetRequestStatus reads only this tenant's PCAS outbox destinations, including
// configured breadth topics and canonical rows left by an earlier config.
// Raw worker errors stay in the operator outbox ledger, outside this public
// response, because they may include upstream data.
func (s *service) GetRequestStatus(ctx context.Context, tenantID, requestID string) (RequestStatus, bool, error) {
	if s.store == nil {
		return RequestStatus{}, false, nil
	}
	var result RequestStatus
	var found bool
	recoveryTopic := topicOr(s.recoveryTopic, RecoveryRequestDestination)
	federationTopic := topicOr(s.federationTopic, FederationImportDestination)
	kemTopic := topicOr(s.kemTopic, KEMRewrapDestination)
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var destination string
		err := tx.QueryRow(ctx, `SELECT destination, status, attempts, created_at, delivered_at FROM outbox
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND idempotency_key = $1
			AND destination IN ($2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			requestID, GenesisRequestDestination, SuccessionRequestDestination,
			DelegationScopeDestination, DelegationFloorDestination,
			RecoveryRequestDestination, FederationImportDestination, KEMRewrapDestination,
			recoveryTopic, federationTopic, kemTopic).
			Scan(&destination, &result.Status, &result.Attempts, &result.CreatedAt, &result.DeliveredAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		result.RequestID = requestID
		switch destination {
		case GenesisRequestDestination:
			result.Kind = "genesis"
		case SuccessionRequestDestination:
			result.Kind = "succession"
		case DelegationScopeDestination:
			result.Kind = "delegation_scope"
		case DelegationFloorDestination:
			result.Kind = "delegation_floor"
		case recoveryTopic, RecoveryRequestDestination:
			result.Kind = "recovery"
		case federationTopic, FederationImportDestination:
			result.Kind = "federation_import"
		case kemTopic, KEMRewrapDestination:
			result.Kind = "kem_rewrap"
		}
		return nil
	})
	return result, found, err
}

// RequestSuccession records an accepted succession request as an idempotent outbox
// job for the signer to mint (AN-4/AN-5/AN-6). It returns a request acknowledgment;
// the actual dual-signed record is produced asynchronously by the signer-side
// orchestrator.
func (s *service) RequestSuccession(ctx context.Context, tenantID string, req RequestSuccessionRequest) (RequestSuccessionResponse, error) {
	if s.repo != nil {
		anchor, found, err := s.repo.GetGenesis(ctx, tenantID, req.IdentityID)
		if err != nil {
			return RequestSuccessionResponse{}, err
		}
		if !found {
			return RequestSuccessionResponse{}, api.ErrStatus(http.StatusConflict,
				"PCAS identity has no registered genesis; register it at POST /api/v1/pcas/genesis and wait for delivery before requesting succession")
		}
		if anchor.Genesis.DeploymentScope != req.DeploymentScope {
			return RequestSuccessionResponse{}, api.ErrStatus(http.StatusConflict, "deployment_scope differs from the registered PCAS genesis")
		}
		if err := succession.VerifyGenesis(anchor.TrustRootPublicDER, anchor.Genesis); err != nil {
			return RequestSuccessionResponse{}, fmt.Errorf("pcas api: stored genesis verification failed: %w", err)
		}
	}
	requestID := events.NewID()
	payload, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		RequestSuccessionRequest
	}{RequestID: requestID, RequestSuccessionRequest: req})
	if err != nil {
		return RequestSuccessionResponse{}, err
	}
	if s.store != nil && s.outbox != nil {
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: SuccessionRequestDestination,
				IdempotencyKey: requestID, Payload: payload,
			})
			return err
		}); err != nil {
			return RequestSuccessionResponse{}, fmt.Errorf("pcas api: enqueue succession request: %w", err)
		}
	}
	return RequestSuccessionResponse{
		RequestID:       requestID,
		IdentityID:      req.IdentityID,
		CredentialType:  req.CredentialType,
		TargetAlgorithm: req.TargetAlgorithm,
		Status:          "queued",
		QueuedAt:        time.Now().UTC(),
		StatusURL:       "/api/v1/pcas/requests/" + requestID,
	}, nil
}

func (s *service) ConfigureDelegationScope(ctx context.Context, tenantID string, req DelegationScopeRequest) (DelegationScopeResponse, error) {
	return s.enqueueDelegation(ctx, tenantID, DelegationScopeDestination, pcasdelegation.Command{
		Kind: "scope", ScopeID: req.ScopeID, ParentScopeID: req.ParentScopeID, EpochFloor: req.EpochFloor,
	})
}

func (s *service) RaiseDelegationFloor(ctx context.Context, tenantID string, req DelegationFloorRequest) (DelegationScopeResponse, error) {
	return s.enqueueDelegation(ctx, tenantID, DelegationFloorDestination, pcasdelegation.Command{
		Kind: "floor", ScopeID: req.ScopeID, EpochFloor: req.EpochFloor,
	})
}

func (s *service) enqueueDelegation(ctx context.Context, tenantID, destination string, cmd pcasdelegation.Command) (DelegationScopeResponse, error) {
	if s.store == nil || s.outbox == nil || s.kem == nil {
		return DelegationScopeResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "isolated PCAS signer outbox is unavailable")
	}
	if _, ok := s.kem.(interface {
		ApplyDelegation(context.Context, pcasdelegation.Command) (pcasdelegation.Receipt, error)
	}); !ok {
		return DelegationScopeResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "isolated PCAS delegation custody is unavailable")
	}
	if cmd.ScopeID == "" || cmd.ScopeID == cmd.ParentScopeID {
		return DelegationScopeResponse{}, api.ErrStatus(http.StatusBadRequest, "delegation scope and parent must differ")
	}
	cmd.TenantID, cmd.OperationID = tenantID, events.NewID()
	queuedAt := time.Now().UTC()
	var actor *events.Actor
	if attributed, ok := events.ActorFromContext(ctx); ok {
		actor = &attributed
	}
	payload, err := json.Marshal(struct {
		Command  pcasdelegation.Command `json:"command"`
		QueuedAt time.Time              `json:"queued_at"`
		Actor    *events.Actor          `json:"actor,omitempty"`
	}{Command: cmd, QueuedAt: queuedAt, Actor: actor})
	if err != nil {
		return DelegationScopeResponse{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: destination, IdempotencyKey: cmd.OperationID, Payload: payload,
		})
		return err
	}); err != nil {
		return DelegationScopeResponse{}, err
	}
	return DelegationScopeResponse{RequestID: cmd.OperationID, ScopeID: cmd.ScopeID,
		ParentScopeID: cmd.ParentScopeID, EpochFloor: cmd.EpochFloor, Status: "queued",
		UpdatedAt: queuedAt, StatusURL: "/api/v1/pcas/requests/" + cmd.OperationID}, nil
}

func (s *service) ListDelegationScopes(ctx context.Context, tenantID string) (DelegationListResponse, error) {
	if s.repo == nil {
		return DelegationListResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS delegation store unavailable")
	}
	rows, err := s.repo.ListDelegationScopes(ctx, tenantID)
	if err != nil {
		return DelegationListResponse{}, err
	}
	resp := DelegationListResponse{Scopes: make([]DelegationScopeState, 0, len(rows)), Count: len(rows)}
	for _, row := range rows {
		state := DelegationScopeState{ScopeID: row.ScopeID, ParentScopeID: row.ParentScopeID,
			EpochFloor: row.EpochFloor, UpdatedAt: row.UpdatedAt}
		if len(row.SignerReceiptJSON) > 0 {
			var receipt pcasdelegation.Receipt
			if err := json.Unmarshal(row.SignerReceiptJSON, &receipt); err != nil {
				return DelegationListResponse{}, err
			}
			if receipt.TenantID != tenantID || receipt.ScopeID != row.ScopeID ||
				receipt.AppliedParentScopeID != row.ParentScopeID || receipt.AppliedFloor != row.EpochFloor {
				return DelegationListResponse{}, errors.New("pcas api: stored delegation receipt does not bind serving row")
			}
			if err := receipt.Verify(); err != nil {
				return DelegationListResponse{}, err
			}
			state.SignerConfirmed = true
			state.SignerReceipt = append(json.RawMessage(nil), row.SignerReceiptJSON...)
		}
		resp.Scopes = append(resp.Scopes, state)
	}
	return resp, nil
}

func (s *service) ConfigureRecoveryPolicy(ctx context.Context, tenantID string, req RecoveryPolicyRequest) (RecoveryPolicyResponse, error) {
	if err := validateRecoveryPolicyRequest(req); err != nil {
		return RecoveryPolicyResponse{}, err
	}
	if s.repo == nil || s.log == nil {
		return RecoveryPolicyResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS recovery policy event log or store unavailable")
	}
	encoded, err := succession.Encode(succession.RecoveryPolicyConfiguredV1{
		TenantID: tenantID, IdentityID: req.IdentityID, Threshold: req.Threshold,
		Roster: req.Roster, TrustRootDER: req.TrustRootDER,
	})
	if err != nil {
		return RecoveryPolicyResponse{}, err
	}
	if req.OperationID != "" {
		encoded.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("pcas.recovery.policy.v1\x00"+tenantID+"\x00"+req.OperationID)).String()
		if prior, found, err := s.log.EventByID(ctx, encoded.ID); err != nil {
			return RecoveryPolicyResponse{}, err
		} else if found {
			if prior.TenantID != tenantID || prior.Type != encoded.Type ||
				prior.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(prior.Data, encoded.Data) {
				return RecoveryPolicyResponse{}, api.ErrStatus(http.StatusConflict, "idempotency key belongs to another recovery policy command")
			}
			if err := s.repo.ApplyRecoveryPolicyEvent(ctx, prior); err != nil {
				return RecoveryPolicyResponse{}, err
			}
			return RecoveryPolicyResponse{IdentityID: req.IdentityID, Status: "configured", UpdatedAt: prior.Time}, nil
		}
	}
	recorded, err := s.log.Append(ctx, encoded)
	if err != nil {
		return RecoveryPolicyResponse{}, err
	}
	if recorded.TenantID != tenantID || recorded.Type != encoded.Type ||
		recorded.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(recorded.Data, encoded.Data) {
		return RecoveryPolicyResponse{}, api.ErrStatus(http.StatusConflict, "idempotency key belongs to another recovery policy event")
	}
	if err := s.repo.ApplyRecoveryPolicyEvent(ctx, recorded); err != nil {
		return RecoveryPolicyResponse{}, err
	}
	return RecoveryPolicyResponse{IdentityID: req.IdentityID, Status: "configured", UpdatedAt: recorded.Time}, nil
}

func validateRecoveryPolicyRequest(req RecoveryPolicyRequest) error {
	if strings.TrimSpace(req.IdentityID) == "" || req.Threshold < 1 {
		return api.ErrStatus(http.StatusBadRequest, "identity_id and positive threshold are required")
	}
	var roster []pcasrecovery.Approver
	if err := json.Unmarshal(req.Roster, &roster); err != nil || len(roster) == 0 {
		return api.ErrStatus(http.StatusBadRequest, "roster must be a nonempty array of approvers")
	}
	if err := pcasrecovery.ValidatePolicy(pcasrecovery.Policy{
		TrustRootDER: req.TrustRootDER, Threshold: req.Threshold, Roster: roster,
	}); err != nil {
		return api.ErrWithStatus(http.StatusBadRequest, err)
	}
	return nil
}

func (s *service) RequestRecovery(ctx context.Context, tenantID string, req RecoveryRequest) (AsyncRequestResponse, error) {
	if s.repo == nil {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS recovery policy store unavailable")
	}
	policy, found, err := s.repo.GetRecoveryPolicy(ctx, tenantID, req.IdentityID)
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if !found {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusConflict, "recovery policy is not configured for this identity")
	}
	if err := validateRecoveryRequestPolicy(tenantID, req, policy); err != nil {
		return AsyncRequestResponse{}, err
	}
	return s.enqueue(ctx, tenantID, topicOr(s.recoveryTopic, RecoveryRequestDestination), req.IdentityID, req)
}

func validateRecoveryRequestPolicy(tenantID string, req RecoveryRequest, policy pcasstore.RecoveryPolicy) error {
	var configured []pcasrecovery.Approver
	if err := json.Unmarshal(policy.RosterJSON, &configured); err != nil {
		return fmt.Errorf("pcas recovery: decode configured roster: %w", err)
	}
	var auth pcasrecovery.RecoveryAuthorization
	if err := json.Unmarshal(req.Authorization, &auth); err != nil {
		return api.ErrStatus(http.StatusBadRequest, "recovery authorization must be valid JSON")
	}
	expected := pcasrecovery.Expected{IdentityID: req.IdentityID, TenantID: tenantID,
		Epoch: req.Epoch, SuccessorAlg: req.TargetAlgorithm, SuccessorPub: auth.Statement.SuccessorPub}
	err := pcasrecovery.VerifyConfiguredPolicy(pcasrecovery.Policy{
		TrustRootDER: policy.TrustRootDER, Threshold: policy.Threshold, Roster: configured,
	}, req.TrustRootDER, auth, expected, req.DeploymentScope)
	switch {
	case errors.Is(err, pcasrecovery.ErrPolicyRootMismatch):
		return api.ErrStatus(http.StatusConflict, "recovery request trust root does not match the configured policy")
	case errors.Is(err, pcasrecovery.ErrPolicyQuorumMismatch):
		return api.ErrStatus(http.StatusConflict, "recovery authorization does not match the configured quorum")
	case errors.Is(err, pcasrecovery.ErrPolicyRosterMismatch):
		return api.ErrStatus(http.StatusConflict, "recovery authorization does not match the configured roster")
	case errors.Is(err, pcasrecovery.ErrStatementMismatch):
		return api.ErrStatus(http.StatusBadRequest, "recovery authorization statement does not match the request")
	case err != nil:
		return api.ErrStatus(http.StatusBadRequest, "recovery authorization signatures are invalid for the configured policy")
	}
	return nil
}

func (s *service) RequestFederationImport(ctx context.Context, tenantID string, req FederationImportRequest) (AsyncRequestResponse, error) {
	if s.store == nil || s.outbox == nil || s.repo == nil {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS federation outbox is unavailable")
	}
	// Validate the foreign trust root BEFORE persisting it. The HTTP handler
	// checks that the field is non-empty; nothing checked that the bytes are a
	// certificate. This value is a TRUST ANCHOR — a bridge row records what a
	// foreign deployment's succession chain will later be verified against — so
	// persisting arbitrary bytes under that name means the failure surfaces in a
	// worker, long after the request that caused it, against a row that already
	// looks authoritative. Checked here rather than in the handler so no caller
	// path can reach the persist without it.
	if err := validateForeignTrustRoot(req.ForeignTrustRootDER); err != nil {
		return AsyncRequestResponse{}, err
	}
	localGenesis, found, err := s.repo.GetGenesis(ctx, tenantID, req.LocalDeploymentID)
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if !found || localGenesis.Genesis.TenantID != tenantID ||
		localGenesis.Genesis.IdentityID != req.LocalDeploymentID {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusConflict, "local federation authority has no tenant-bound PCAS genesis")
	}
	if err := succession.VerifyGenesis(localGenesis.TrustRootPublicDER, localGenesis.Genesis); err != nil {
		return AsyncRequestResponse{}, fmt.Errorf("pcas federation: local authority genesis is invalid: %w", err)
	}
	expectedHandle := succession.TenantKeyHandle(tenantID, req.LocalDeploymentID, 0)
	if req.LocalAuthorityHandle == "" {
		req.LocalAuthorityHandle = expectedHandle
	}
	if req.LocalAuthorityHandle != expectedHandle {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusConflict, "local_authority_handle does not name this tenant's registered federation authority")
	}
	// A queued command has not verified the foreign chain. Only the worker may
	// publish a bridge after it has produced a signed import proof.
	return s.enqueue(ctx, tenantID, topicOr(s.federationTopic, FederationImportDestination), req.ForeignDeploymentID, req)
}

// validateForeignTrustRoot rejects bytes that cannot serve as a federation trust
// anchor.
//
// Despite the "DER" in its name this is a PKIX SubjectPublicKeyInfo, not a
// certificate — VerifyGenesis hands it straight to crypto.VerifyMessage. Checking
// it here means an unusable anchor is refused at the request that supplies it,
// rather than surfacing much later in a worker as a verification failure against
// a stored bridge row that already looks authoritative.
func validateForeignTrustRoot(der []byte) error {
	if len(der) == 0 {
		return api.ErrStatus(http.StatusBadRequest, "succession: federation import requires a foreign trust root")
	}
	if err := crypto.ValidatePublicKeyDER(der); err != nil {
		// 400, not 500: the caller supplied these bytes, so this is a bad request,
		// not a server fault.
		return api.ErrWithStatus(http.StatusBadRequest,
			fmt.Errorf("succession: foreign trust root is not a usable public key: %w", err))
	}
	return nil
}

func (s *service) RequestKEMRewrap(ctx context.Context, tenantID string, req KEMRewrapRequest) (AsyncRequestResponse, error) {
	if len(req.Stages) == 0 {
		req.Stages = []string{"default"}
	}
	resp, err := s.enqueue(ctx, tenantID, topicOr(s.kemTopic, KEMRewrapDestination), req.IdentityID, req)
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if s.repo != nil {
		total := len(req.Stages)
		for _, stage := range req.Stages {
			if err := s.repo.UpsertRewrapJob(ctx, tenantID, pcasstore.RewrapJob{
				JobID: resp.RequestID, IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch,
				Stage: stage, TotalStages: total, Status: "queued",
			}); err != nil {
				return AsyncRequestResponse{}, err
			}
		}
	}
	return resp, nil
}

func (s *service) RegisterIssuerAuthority(ctx context.Context, tenantID string, req IssuerAuthorityRequest) (IssuerAuthorityResponse, error) {
	if s.store == nil || s.repo == nil || s.kem == nil || s.log == nil {
		return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS issuer store, event log or isolated signer is unavailable")
	}
	if strings.TrimSpace(req.CAKeyHandle) == "" {
		return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusBadRequest, "ca_key_handle is required")
	}
	if err := s.verifyIssuerEpoch(ctx, tenantID, req.IdentityID, req.CurrentEpoch); err != nil {
		return IssuerAuthorityResponse{}, err
	}
	if err := s.requireManagedIssuerCA(ctx, tenantID, req.CAKeyHandle, req.CACertDER); err != nil {
		return IssuerAuthorityResponse{}, err
	}
	ca, err := s.caSigner(ctx, req.CAKeyHandle)
	if status.Code(err) == codes.NotFound {
		return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusConflict, "managed CA key is absent from isolated signer custody")
	}
	if status.Code(err) == codes.Unavailable {
		return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "isolated CA signer is unavailable")
	}
	if err != nil {
		return IssuerAuthorityResponse{}, err
	}
	if err := crypto.VerifyCertificateSigner(req.CACertDER, ca.Public()); err != nil {
		return IssuerAuthorityResponse{}, api.ErrWithStatus(http.StatusConflict, fmt.Errorf("issuer certificate and signer custody mismatch: %w", err))
	}
	encoded, err := succession.Encode(succession.IssuerAuthorityRegisteredV1{
		TenantID: tenantID, IssuerID: req.IssuerID, IdentityID: req.IdentityID,
		CurrentEpoch: req.CurrentEpoch, CAKeyHandle: req.CAKeyHandle, CACertDER: req.CACertDER,
	})
	if err != nil {
		return IssuerAuthorityResponse{}, err
	}
	if req.OperationID != "" {
		encoded.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("pcas.issuer.authority.v1\x00"+tenantID+"\x00"+req.OperationID)).String()
		if prior, found, err := s.log.EventByID(ctx, encoded.ID); err != nil {
			return IssuerAuthorityResponse{}, err
		} else if found {
			if prior.TenantID != tenantID || prior.Type != encoded.Type ||
				prior.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(prior.Data, encoded.Data) {
				return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusConflict, "idempotency key belongs to another issuer authority command")
			}
			if err := s.repo.ApplyIssuerAuthorityEvent(ctx, prior); err != nil {
				return IssuerAuthorityResponse{}, err
			}
			return IssuerAuthorityResponse{IssuerID: req.IssuerID, IdentityID: req.IdentityID,
				CurrentEpoch: req.CurrentEpoch, CAKeyHandle: req.CAKeyHandle,
				Status: "registered", UpdatedAt: prior.Time}, nil
		}
	}
	recorded, err := s.log.Append(ctx, encoded)
	if err != nil {
		return IssuerAuthorityResponse{}, err
	}
	if recorded.TenantID != tenantID || recorded.Type != encoded.Type ||
		recorded.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(recorded.Data, encoded.Data) {
		return IssuerAuthorityResponse{}, api.ErrStatus(http.StatusConflict, "idempotency key belongs to another issuer authority event")
	}
	if err := s.repo.ApplyIssuerAuthorityEvent(ctx, recorded); err != nil {
		return IssuerAuthorityResponse{}, err
	}
	return IssuerAuthorityResponse{
		IssuerID: req.IssuerID, IdentityID: req.IdentityID, CurrentEpoch: req.CurrentEpoch,
		CAKeyHandle: req.CAKeyHandle, Status: "registered", UpdatedAt: recorded.Time,
	}, nil
}

func (s *service) verifyIssuerEpoch(ctx context.Context, tenantID, identityID string, epoch uint64) error {
	genesis, found, err := s.repo.GetGenesis(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	if !found || genesis.Genesis.TenantID != tenantID || genesis.Genesis.IdentityID != identityID {
		return api.ErrStatus(http.StatusConflict, "PCAS issuer identity has no tenant-bound genesis")
	}
	if err := succession.VerifyGenesis(genesis.TrustRootPublicDER, genesis.Genesis); err != nil {
		return fmt.Errorf("pcas issuer: stored genesis is invalid: %w", err)
	}
	observedEpoch, hasEpoch, err := s.repo.GetHighWater(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	if (hasEpoch && observedEpoch != epoch) || (!hasEpoch && epoch != 0) {
		return api.ErrStatus(http.StatusConflict, "issuer epoch does not match this identity's recorded PCAS epoch")
	}
	return nil
}

func (s *service) requireManagedIssuerCA(ctx context.Context, tenantID, handle string, certDER []byte) error {
	managedCA, err := s.store.GetCAAuthorityBySignerHandle(ctx, tenantID, handle)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ErrStatus(http.StatusConflict, "CA key handle is not a managed authority in this tenant")
	}
	if err != nil {
		return err
	}
	if managedCA.Status != "active" {
		return api.ErrStatus(http.StatusConflict, "CA authority is not active for issuer use")
	}
	// Managed authorities may retain a leaf-first public PEM chain. Parse the
	// whole bounded public-only envelope and require its first certificate to
	// match the exact requested CA DER; never select a later block as authority.
	if _, err := certinfo.ParsePublicPEMChain([]byte(managedCA.CertificatePEM), certDER); err != nil {
		return api.ErrStatus(http.StatusConflict, "issuer certificate does not match this tenant's managed CA public chain")
	}
	return nil
}

func (s *service) IssueIssuerLeaf(ctx context.Context, tenantID string, req IssueLeafRequest) (IssueLeafResponse, error) {
	authority, err := s.issuerAuthority(ctx, tenantID, req.IssuerID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	ca, err := s.caSigner(ctx, authority.CAKeyHandle)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	ttl := leafTTL(req.TTLSeconds)
	rotation := req.RotationVersion
	if rotation == 0 {
		rotation = 1
	}
	certDER, err := pcasissuer.IssueLeafCertificate(authority.CACertDER, ca, req.CSRDER, pcasissuer.IssuerPosture{
		IssuerID:  authority.IssuerID,
		Epoch:     authority.CurrentEpoch,
		Algorithm: string(ca.Algorithm()),
		PublicDER: ca.Public().DER,
	}, rotation, ttl)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	return IssueLeafResponse{
		IssuerID: authority.IssuerID, IdentityID: authority.IdentityID, Epoch: authority.CurrentEpoch,
		RotationVersion: rotation, CertDER: certDER, IssuedAt: time.Now().UTC(),
	}, nil
}

func (s *service) IssueStapledLeaf(ctx context.Context, tenantID string, req IssueStapledLeafRequest) (IssueLeafResponse, error) {
	authority, err := s.issuerAuthority(ctx, tenantID, req.IssuerID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	identityID := req.CheckpointIdentityID
	if identityID == "" {
		identityID = authority.IdentityID
	}
	cp, found, err := s.LatestCheckpoint(ctx, tenantID, identityID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	if !found {
		return IssueLeafResponse{}, ErrCheckpointNotFound
	}
	var signed succession.SignedEpochCheckpoint
	if len(cp.CheckpointJSON) > 0 {
		if err := json.Unmarshal(cp.CheckpointJSON, &signed); err != nil {
			return IssueLeafResponse{}, err
		}
	} else {
		signed = succession.SignedEpochCheckpoint{
			IdentityID: cp.IdentityID, TenantID: tenantID, Epoch: cp.Epoch, LogTreeSize: cp.LogTreeSize,
			LogRootHash: cp.LogRoot, Signature: cp.Signature,
		}
	}
	ca, err := s.caSigner(ctx, authority.CAKeyHandle)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	certDER, err := pcasstaple.IssueStapledLeaf(authority.CACertDER, ca, req.CSRDER, pcasstaple.Attachment{Checkpoint: &signed}, leafTTL(req.TTLSeconds))
	if err != nil {
		return IssueLeafResponse{}, err
	}
	return IssueLeafResponse{
		IssuerID: authority.IssuerID, IdentityID: authority.IdentityID, Epoch: authority.CurrentEpoch,
		CertDER: certDER, IssuedAt: time.Now().UTC(),
	}, nil
}

func (s *service) RewrapStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RewrapStatusResponse, error) {
	resp := RewrapStatusResponse{IdentityID: identityID, PredecessorEpoch: predecessorEpoch, Jobs: []RewrapJobState{}, CheckedAt: time.Now().UTC()}
	if s.repo == nil {
		return resp, nil
	}
	jobs, err := s.repo.ListRewrapJobs(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil {
		return RewrapStatusResponse{}, err
	}
	for _, job := range jobs {
		resp.Jobs = append(resp.Jobs, RewrapJobState{
			JobID: job.JobID, Stage: job.Stage, TotalStages: job.TotalStages,
			CompletedStages: job.CompletedStages, Status: job.Status, UpdatedAt: job.UpdatedAt,
		})
	}
	if predecessorEpoch != 0 {
		resp.Complete, err = s.repo.RewrapComplete(ctx, tenantID, identityID, predecessorEpoch)
		if err != nil {
			return RewrapStatusResponse{}, err
		}
	} else {
		resp.Complete = len(resp.Jobs) > 0
		for _, job := range resp.Jobs {
			resp.Complete = resp.Complete && job.Status == "complete"
		}
	}
	return resp, nil
}

func (s *service) ConfigureRetirementPolicy(ctx context.Context, tenantID string, req RetirementPolicyRequest) (RetirementPolicyResponse, error) {
	if err := validateRetirementPolicyRequest(req); err != nil {
		return RetirementPolicyResponse{}, err
	}
	// Operator-registered PCAS keys live under a tenant-bound signer handle.
	// Never let a caller redirect a valid RP quorum to another key, and never
	// leave an empty handle for the worker to interpret as a legacy key.
	boundHandle := succession.TenantKeyHandle(tenantID, req.IdentityID, req.PredecessorEpoch)
	if req.PredecessorHandle != "" && req.PredecessorHandle != boundHandle {
		return RetirementPolicyResponse{}, fmt.Errorf("%w: predecessor_handle does not match the tenant-bound identity epoch", errInvalidRetirementPolicy)
	}
	req.PredecessorHandle = boundHandle
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.UpsertRetirementPolicy(ctx, tenantID, pcasstore.RetirementPolicy{
			IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch, Threshold: req.Threshold,
			RosterJSON: req.Roster, ValidityWindowSeconds: req.ValidityWindowSeconds,
			PredecessorHandle: req.PredecessorHandle, Status: "active",
		}); err != nil {
			return RetirementPolicyResponse{}, err
		}
	}
	complete := false
	if s.repo != nil {
		var err error
		complete, err = s.repo.RewrapComplete(ctx, tenantID, req.IdentityID, req.PredecessorEpoch)
		if err != nil {
			return RetirementPolicyResponse{}, err
		}
	}
	return RetirementPolicyResponse{
		IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch, Threshold: req.Threshold,
		Roster: req.Roster, ValidityWindowSeconds: req.ValidityWindowSeconds,
		PredecessorHandle: req.PredecessorHandle, Status: "active", UpdatedAt: updated, RewrapComplete: complete,
	}, nil
}

var errInvalidRetirementPolicy = errors.New("pcas retirement: invalid policy")

func validateRetirementPolicyRequest(req RetirementPolicyRequest) error {
	if strings.TrimSpace(req.IdentityID) == "" || req.Threshold <= 0 {
		return fmt.Errorf("%w: identity_id and positive threshold are required", errInvalidRetirementPolicy)
	}
	// The worker converts seconds to time.Duration. Reject overflow before a policy
	// can be saved as active, or every later evaluation would fail permanently.
	if req.ValidityWindowSeconds > uint64(math.MaxInt64/int64(time.Second)) {
		return fmt.Errorf("%w: validity window exceeds the representable duration", errInvalidRetirementPolicy)
	}
	var roster []struct {
		RelyingParty string `json:"relying_party"`
		PublicDER    []byte `json:"public_der"`
	}
	if err := json.Unmarshal(req.Roster, &roster); err != nil || len(roster) == 0 {
		return fmt.Errorf("%w: roster must be a nonempty array of relying-party public keys", errInvalidRetirementPolicy)
	}
	seen := make(map[string]struct{}, len(roster))
	for _, member := range roster {
		if member.RelyingParty == "" || strings.TrimSpace(member.RelyingParty) != member.RelyingParty {
			return fmt.Errorf("%w: each relying party needs a nonblank, trimmed name", errInvalidRetirementPolicy)
		}
		if _, duplicate := seen[member.RelyingParty]; duplicate {
			return fmt.Errorf("%w: duplicate relying party %q", errInvalidRetirementPolicy, member.RelyingParty)
		}
		seen[member.RelyingParty] = struct{}{}
		if err := crypto.ValidatePublicKeyDER(member.PublicDER); err != nil {
			return fmt.Errorf("%w: relying party %q has an unusable public key: %v", errInvalidRetirementPolicy, member.RelyingParty, err)
		}
	}
	if req.Threshold > len(seen) {
		return fmt.Errorf("%w: threshold %d exceeds the %d distinct relying parties", errInvalidRetirementPolicy, req.Threshold, len(seen))
	}
	return nil
}

func (s *service) RetirementStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RetirementPolicyResponse, bool, error) {
	if s.repo == nil {
		return RetirementPolicyResponse{}, false, nil
	}
	policy, found, err := s.repo.GetRetirementPolicy(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil || !found {
		return RetirementPolicyResponse{}, found, err
	}
	complete, err := s.repo.RewrapComplete(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil {
		return RetirementPolicyResponse{}, false, err
	}
	return retirementPolicyResponse(policy, complete), true, nil
}

func (s *service) LatestCheckpoint(ctx context.Context, tenantID, identityID string) (CheckpointResponse, bool, error) {
	if s.repo == nil {
		return CheckpointResponse{}, false, nil
	}
	cp, found, err := s.repo.LatestCheckpoint(ctx, tenantID, identityID)
	if err != nil || !found {
		return CheckpointResponse{}, found, err
	}
	resp, err := checkpointResponse(cp)
	return resp, err == nil, err
}

func checkpointResponse(cp pcasstore.EpochCheckpoint) (CheckpointResponse, error) {
	var signed succession.SignedEpochCheckpoint
	if err := json.Unmarshal(cp.CheckpointJSON, &signed); err != nil {
		return CheckpointResponse{}, fmt.Errorf("decode stored PCAS checkpoint: %w", err)
	}
	if signed.IdentityID != cp.IdentityID || signed.Epoch != cp.Epoch ||
		signed.LogTreeSize != cp.LogTreeSize ||
		!bytes.Equal(signed.LogRootHash, cp.LogRoot) ||
		!bytes.Equal(signed.Signature, cp.Signature) {
		return CheckpointResponse{}, errors.New("stored PCAS checkpoint disagrees with its read model")
	}
	return CheckpointResponse{
		IdentityID: cp.IdentityID, Epoch: cp.Epoch, LogTreeSize: cp.LogTreeSize, LogRoot: cp.LogRoot,
		Signature: cp.Signature, SignerPublicDER: signed.SignerPublicDER,
		CheckpointJSON: cp.CheckpointJSON, IssuedAt: cp.IssuedAt,
	}, nil
}

func (s *service) PostureReport(ctx context.Context, tenantID, identityID string) (PostureReportResponse, bool, error) {
	if s.repo == nil {
		return PostureReportResponse{}, false, nil
	}
	rec, found, err := s.repo.LatestRecord(ctx, tenantID, identityID)
	if err != nil || !found {
		return PostureReportResponse{}, found, err
	}
	reporter, err := s.reporterSigner(ctx)
	if err != nil {
		return PostureReportResponse{}, false, err
	}
	digest := crypto.SHA256Sum(rec.Encoded)
	report := succession.BuildPostureReport(succession.IdentityPosture{
		IdentityID:       rec.IdentityID,
		TenantID:         tenantID,
		CurrentEpoch:     rec.Epoch,
		CurrentAlgorithm: rec.SuccessorAlg,
		CurrentPublicDER: rec.SuccessorPub,
		State:            succession.StateActive,
	}, digest)
	signed, err := succession.SignPostureReport(crypto.SignerFromDigestSigner(reporter), report)
	if err != nil {
		return PostureReportResponse{}, false, err
	}
	return PostureReportResponse{
		IdentityID: signed.IdentityID, TenantID: signed.TenantID, Algorithm: string(signed.Algorithm),
		Epoch: signed.Epoch, IntroducingRecordDigest: signed.IntroducingRecordDigest,
		Signature: signed.Signature, ReporterPublicDER: reporter.Public().DER, IssuedAt: time.Now().UTC(),
	}, true, nil
}

func (s *service) ListMisissuance(ctx context.Context, tenantID string) (MisissuanceListResponse, error) {
	resp := MisissuanceListResponse{Findings: []MisissuanceResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	findings, err := s.repo.ListMisissuance(ctx, tenantID)
	if err != nil {
		return MisissuanceListResponse{}, err
	}
	for _, m := range findings {
		resp.Findings = append(resp.Findings, MisissuanceResponse{
			IdentityID: m.IdentityID, Epoch: m.Epoch, RecordADigest: m.RecordADigest, RecordBDigest: m.RecordBDigest,
			SignerA: m.SignerA, SignerB: m.SignerB, ProofJSON: m.ProofJSON, DetectedAt: m.DetectedAt,
		})
	}
	resp.Count = len(resp.Findings)
	return resp, nil
}

// ListFederationBridges serves the imported bridges with trust-root digests
// (AUD-9's missing read path). No repo means no bridges — an empty truthful
// answer, not an error.
func (s *service) ListFederationBridges(ctx context.Context, tenantID string) (FederationBridgeListResponse, error) {
	resp := FederationBridgeListResponse{Bridges: []FederationBridgeResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	bridges, err := s.repo.ListFederationBridges(ctx, tenantID)
	if err != nil {
		return FederationBridgeListResponse{}, err
	}
	for _, b := range bridges {
		digest := ""
		if len(b.ForeignTrustRootDER) > 0 {
			digest = hex.EncodeToString(crypto.SHA256Sum(b.ForeignTrustRootDER))
		}
		resp.Bridges = append(resp.Bridges, FederationBridgeResponse{
			ForeignDeploymentID: b.ForeignDeploymentID,
			IdentityID:          b.IdentityID,
			LocalBaseEpoch:      b.LocalBaseEpoch,
			TrustRootSHA256:     digest,
			UpdatedAt:           b.UpdatedAt,
		})
	}
	resp.Count = len(resp.Bridges)
	return resp, nil
}

func (s *service) enqueue(ctx context.Context, tenantID, destination, target string, req any) (AsyncRequestResponse, error) {
	if s.store == nil || s.outbox == nil {
		return AsyncRequestResponse{}, api.ErrStatus(http.StatusServiceUnavailable, "PCAS outbox is unavailable")
	}
	requestID := events.NewID()
	payload, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		Request   any    `json:"request"`
	}{RequestID: requestID, Request: req})
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: destination, IdempotencyKey: requestID, Payload: payload,
		})
		return err
	}); err != nil {
		return AsyncRequestResponse{}, fmt.Errorf("pcas api: enqueue %s: %w", destination, err)
	}
	return AsyncRequestResponse{RequestID: requestID, Status: "queued", QueuedAt: time.Now().UTC(),
		Target: target, StatusURL: "/api/v1/pcas/requests/" + requestID}, nil
}

func (s *service) issuerAuthority(ctx context.Context, tenantID, issuerID string) (pcasstore.IssuerAuthority, error) {
	if s.repo == nil || s.store == nil {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	authority, found, err := s.repo.GetIssuerAuthority(ctx, tenantID, issuerID)
	if err != nil {
		return pcasstore.IssuerAuthority{}, err
	}
	if !found {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	if authority.CAKeyHandle == "" || len(authority.CACertDER) == 0 {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	if err := s.requireManagedIssuerCA(ctx, tenantID, authority.CAKeyHandle, authority.CACertDER); err != nil {
		return pcasstore.IssuerAuthority{}, err
	}
	if err := s.verifyIssuerEpoch(ctx, tenantID, authority.IdentityID, authority.CurrentEpoch); err != nil {
		return pcasstore.IssuerAuthority{}, err
	}
	return authority, nil
}

func (s *service) caSigner(ctx context.Context, handle string) (*signing.RemoteSigner, error) {
	if s.kem == nil {
		return nil, ErrSignerUnavailable
	}
	return s.kem.SignerForHandleWithPurpose(ctx, handle, signing.PurposeCASign)
}

func (s *service) reporterSigner(ctx context.Context) (*signing.RemoteSigner, error) {
	if s.kem == nil {
		return nil, ErrSignerUnavailable
	}
	rs, err := s.kem.SignerForHandleWithPurpose(ctx, defaultReporterHandle, signing.PurposeGeneric)
	if err == nil {
		return rs, nil
	}
	rs, err = s.kem.GenerateKeyHandle(ctx, crypto.ECDSAP256, defaultReporterHandle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
	}
	return rs, nil
}

func leafTTL(seconds int64) time.Duration {
	if seconds <= 0 {
		return time.Hour
	}
	return time.Duration(seconds) * time.Second
}

func retirementPolicyResponse(policy pcasstore.RetirementPolicy, rewrapComplete bool) RetirementPolicyResponse {
	return RetirementPolicyResponse{
		IdentityID: policy.IdentityID, PredecessorEpoch: policy.PredecessorEpoch,
		Threshold: policy.Threshold, Roster: policy.RosterJSON,
		ValidityWindowSeconds: policy.ValidityWindowSeconds,
		PredecessorHandle:     policy.PredecessorHandle, Status: policy.Status,
		UpdatedAt: policy.UpdatedAt, RewrapComplete: rewrapComplete,
	}
}

// FetchChain returns identityID's ordered, gapless succession records (opaque
// encoded, PCAS-04), RLS-scoped to tenantID. The response verifies offline with
// PCAS-07.
func (s *service) FetchChain(ctx context.Context, tenantID, identityID string) (ChainResponse, error) {
	resp := ChainResponse{IdentityID: identityID, Records: [][]byte{}}
	if s.repo == nil {
		return resp, nil
	}
	if anchor, found, err := s.repo.GetGenesis(ctx, tenantID, identityID); err != nil {
		return ChainResponse{}, err
	} else if found {
		if anchor.Genesis.TenantID != tenantID || anchor.Genesis.IdentityID != identityID {
			return ChainResponse{}, errors.New("pcas api: genesis scope does not match request")
		}
		if err := succession.VerifyGenesis(anchor.TrustRootPublicDER, anchor.Genesis); err != nil {
			return ChainResponse{}, fmt.Errorf("pcas api: stored genesis verification failed: %w", err)
		}
		resp.Genesis = &anchor.Genesis
		resp.TrustRootPublicDER = anchor.TrustRootPublicDER
	}
	recs, err := s.repo.FetchChain(ctx, tenantID, identityID)
	if err != nil {
		return ChainResponse{}, err
	}
	for _, r := range recs {
		resp.Records = append(resp.Records, r.Encoded)
	}
	resp.Count = len(resp.Records)
	return resp, nil
}

// RecordAck appends the relying party's signed acknowledgment as an nhi.rp.ack
// event on the AN-2 ledger, preserving the signature and identity/epoch binding so
// the PCAS-10 quorum can count it. The ledger stamps the recorded time (the quorum
// validity-window anchor).
func (s *service) RecordAck(ctx context.Context, tenantID string, req AckRequest) (AckResponse, error) {
	ev, err := succession.Encode(succession.RPAckV1{
		IdentityID:   req.IdentityID,
		TenantID:     tenantID,
		Epoch:        req.Epoch,
		RelyingParty: req.RelyingParty,
		AckSignature: req.Signature,
	})
	if err != nil {
		return AckResponse{}, err
	}
	recorded := ev
	if s.log != nil {
		recorded, err = s.log.Append(ctx, ev)
		if err != nil {
			return AckResponse{}, fmt.Errorf("pcas api: record ack: %w", err)
		}
	} else {
		recorded.ID = events.NewID()
		recorded.Time = time.Now().UTC()
	}
	return AckResponse{
		AckID:        recorded.ID,
		IdentityID:   req.IdentityID,
		Epoch:        req.Epoch,
		RelyingParty: req.RelyingParty,
		RecordedAt:   recorded.Time,
	}, nil
}
