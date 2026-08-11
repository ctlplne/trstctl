// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	defaultRekorDestination = "transparency.rekor"
	codeSigningPollInterval = 25 * time.Millisecond
	codeSigningWaitLimit    = 30 * time.Second
)

var codeSigningEventNamespace = uuid.MustParse("046f42f9-87a1-5f88-a8e1-f3804ea19091")

// CodeSigningConfig wires the served CLM-06 code-signing surface. Keys is a
// compile-time Go interface boundary: production passes signer-backed handles;
// no private key or identity proof is persisted in plaintext.
type CodeSigningConfig struct {
	Keys codesign.KeyResolver
	Gate codesign.Gate

	Attestors          []attest.Attestor
	AttestorsForTenant func(tenantID string) []attest.Attestor
	EphemeralAlgorithm crypto.Algorithm

	// NewEphemeralSigner binds or creates the deterministic, operation-scoped
	// handle inside the isolated signer. Replaying operationID must return the same
	// handle and public key. DestroyEphemeralSigner is invoked only by the durable
	// cleanup outbox command after completion has been projected.
	NewEphemeralSigner     func(context.Context, string, crypto.Algorithm) (crypto.DigestSigner, string, error)
	DestroyEphemeralSigner func(context.Context, string) error

	RekorDestination    string
	TransparencyHandler orchestrator.Handler
}

func (c CodeSigningConfig) enabled() bool {
	return c.Keys != nil || len(c.Attestors) > 0 || c.AttestorsForTenant != nil
}

type servedCodeSigningService struct {
	cfg    CodeSigningConfig
	store  *store.Store
	log    *events.Log
	kek    seal.KeyWrapper
	crypto tenantseal.Access
	outbox *orchestrator.Outbox
	wake   func()

	// Test-only crash seam: it fires after the signer returned but before the
	// completion event. A redelivery must obtain the signer journal's exact result.
	afterSign func(context.Context, api.CodeSigningResponse) error

	// These narrow test seams model a real wall clock and process death after a
	// successful broker ACK but before the relational projector commits.
	now                func() time.Time
	afterCommandAppend func(events.Event) error
}

type codeSigningExactApprovalGate interface {
	api.ExactApprovalChecker
	CodeSigningApprovalRequired() bool
}

var errCodeSigningTerminalDomain = errors.New("codesign: terminal domain failure")

type codeSigningTerminalDomainError struct{ cause error }

func (e *codeSigningTerminalDomainError) Error() string { return e.cause.Error() }
func (e *codeSigningTerminalDomainError) Unwrap() error { return e.cause }
func (e *codeSigningTerminalDomainError) Is(target error) bool {
	return target == errCodeSigningTerminalDomain || errors.Is(e.cause, target)
}

func terminalCodeSigningDomainError(err error) error {
	if err == nil || codeSigningInfrastructureRetryable(err) {
		return err
	}
	return &codeSigningTerminalDomainError{cause: err}
}

// codeSigningInfrastructureRetryable is a closed transport classification. ELI5:
// a busy, restarting, or temporarily unreachable signer is a broken road, not a
// bad signing request. The outbox keeps the command queued and retries that road.
func codeSigningInfrastructureRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Aborted, codes.Internal, codes.Unavailable, codes.DataLoss:
		return true
	default:
		return false
	}
}

// codeSigningExecutionIsTerminal separates immutable request/domain failures from
// retryable infrastructure failures without parsing error strings. Unknown errors
// stay retryable and eventually pass through the outbox's terminal callback; this
// avoids turning one transient provider message into a permanent user-visible deny.
func codeSigningExecutionIsTerminal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCodeSigningTerminalDomain) {
		return true
	}
	// Transport identity wins over the broader domain class. A key resolver may
	// report ErrKeyUnavailable because the signer socket is restarting; the nested
	// gRPC Unavailable still describes a retryable road, not a permanently absent
	// key. Closed invalid/policy/not-found errors carry no retryable transport code.
	if codeSigningInfrastructureRetryable(err) {
		return false
	}
	if errors.Is(err, codesign.ErrInvalidRequest) ||
		errors.Is(err, codesign.ErrPolicyDenied) ||
		errors.Is(err, codesign.ErrKeyUnavailable) {
		return true
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
		codes.OutOfRange, codes.Unimplemented:
		return true
	default:
		return false
	}
}

func newServedCodeSigningService(cfg CodeSigningConfig, st *store.Store, log *events.Log, kek seal.KeyWrapper, outbox *orchestrator.Outbox, wake func(), tenantCrypto ...tenantseal.Access) (*servedCodeSigningService, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	if st == nil || log == nil || kek == nil || outbox == nil || wake == nil {
		return nil, errors.New("server: code-signing requires store, event log, KEK, outbox, and dispatcher wake")
	}
	if cfg.Keys == nil {
		cfg.Keys = emptyCodeSigningKeys{}
	}
	if cfg.EphemeralAlgorithm == "" {
		cfg.EphemeralAlgorithm = crypto.ECDSAP256
	}
	if len(cfg.Attestors) > 0 || cfg.AttestorsForTenant != nil {
		if cfg.NewEphemeralSigner == nil || cfg.DestroyEphemeralSigner == nil {
			return nil, errors.New("server: keyless code-signing requires deterministic signer create/bind and destroy functions")
		}
	}
	if cfg.RekorDestination == "" {
		cfg.RekorDestination = defaultRekorDestination
	}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	return &servedCodeSigningService{cfg: cfg, store: st, log: log, kek: kek, crypto: access, outbox: outbox, wake: wake}, nil
}

type codeSigningCommand struct {
	Mode            string `json:"mode"`
	Principal       string `json:"principal"`
	KeyID           string `json:"key_id,omitempty"`
	ArtifactType    string `json:"artifact_type"`
	Digest          []byte `json:"digest"`
	IdentityMethod  string `json:"identity_method,omitempty"`
	IdentityPayload []byte `json:"identity_payload,omitempty"`
	FulcioSAN       string `json:"fulcio_san,omitempty"`
	FulcioIssuer    string `json:"fulcio_issuer,omitempty"`
}

func (s *servedCodeSigningService) SignCode(ctx context.Context, tenantID, idempotencyKey string, req api.CodeSigningRequest) (api.CodeSigningResponse, error) {
	return s.submitAndWait(ctx, tenantID, idempotencyKey, codeSigningCommand{
		Mode: "key", Principal: req.Principal, KeyID: req.KeyID,
		ArtifactType: req.ArtifactType, Digest: req.Digest,
	})
}

func (s *servedCodeSigningService) SignKeylessCode(ctx context.Context, tenantID, idempotencyKey string, req api.CodeSigningKeylessRequest) (api.CodeSigningResponse, error) {
	return s.submitAndWait(ctx, tenantID, idempotencyKey, codeSigningCommand{
		Mode: "keyless", Principal: req.Principal, ArtifactType: req.ArtifactType,
		Digest: req.Digest, IdentityMethod: req.IdentityMethod,
		IdentityPayload: req.IdentityPayload, FulcioSAN: req.FulcioSAN,
		FulcioIssuer: req.FulcioIssuer,
	})
}

func (s *servedCodeSigningService) submitAndWait(ctx context.Context, tenantID, idempotencyKey string, command codeSigningCommand) (api.CodeSigningResponse, error) {
	var response api.CodeSigningResponse
	err := withTenantCipher(ctx, s.crypto, s.kek, tenantID, func(scoped context.Context, _ tenantseal.Cipher) (err error) {
		response, err = s.submitAndWaitFenced(scoped, tenantID, idempotencyKey, command)
		return err
	})
	return response, err
}

func (s *servedCodeSigningService) submitAndWaitFenced(ctx context.Context, tenantID, idempotencyKey string, command codeSigningCommand) (api.CodeSigningResponse, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return api.CodeSigningResponse{}, errors.New("codesign: tenant and idempotency key are required")
	}
	plain, err := json.Marshal(command)
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	defer secret.Wipe(plain)
	requestHash := crypto.SHA256Hex(plain)
	operationID := codeSigningOperationID(tenantID, idempotencyKey)
	legacyOperationID := projections.LegacyCodeSigningOperationID(tenantID, idempotencyKey)

	op, found, err := s.store.CodeSigningOperationByIdempotency(ctx, tenantID, idempotencyKey)
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	if !found {
		recovered, recoverErr := s.projectRetainedCodeSigningCommand(
			ctx, tenantID, operationID, legacyOperationID,
			idempotencyKey, command.Mode, requestHash,
		)
		if recoverErr != nil {
			return api.CodeSigningResponse{}, recoverErr
		}
		if recovered {
			op, found, err = s.store.CodeSigningOperationByIdempotency(ctx, tenantID, idempotencyKey)
			if err != nil {
				return api.CodeSigningResponse{}, err
			}
		}
	}
	if !found {
		requestBinding := projections.CodeSigningRequestBinding(requestHash, idempotencyKey)
		fence, fenceErr := s.store.GetApprovedTargetFence(ctx, tenantID,
			store.ApprovedTargetCodeSigningCommand, operationID)
		if store.IsNotFound(fenceErr) {
			// A v2 first command may have survived an older process. Its operation
			// identity used the raw-key derivation; recover that exact fence instead
			// of creating a parallel v3 command for the same API mutation key.
			fence, fenceErr = s.store.GetApprovedTargetFence(ctx, tenantID,
				store.ApprovedTargetCodeSigningCommand, legacyOperationID)
		}
		switch {
		case fenceErr == nil:
			if fence.RequestBinding != requestBinding {
				return api.CodeSigningResponse{}, fmt.Errorf("%w: code-signing idempotency key belongs to a different command", store.ErrIdempotencyConflict)
			}
			if err := s.projectCodeSigningFence(ctx, tenantID, fence); err != nil {
				return api.CodeSigningResponse{}, err
			}
		case store.IsNotFound(fenceErr):
			approval, approvalErr := s.authorizeCodeSigningCommand(ctx, tenantID, idempotencyKey, requestHash, command)
			if approvalErr != nil {
				return api.CodeSigningResponse{}, approvalErr
			}
			eventTime := s.codeSigningCommandEventTime()
			sealed, sealErr := sealTenantValue(ctx, s.crypto, s.kek, tenantID, plain, codeSigningCommandAAD(tenantID, operationID, command.Mode, requestHash))
			if sealErr != nil {
				return api.CodeSigningResponse{}, fmt.Errorf("codesign: seal command: %w", sealErr)
			}
			defer secret.Wipe(sealed)
			keyRef := store.CodeSigningIdempotencyKeyRef(idempotencyKey)
			commanded := projections.CodeSigningCommanded{
				OperationID: operationID, IdempotencyKeyRef: keyRef,
				RequestBinding: requestBinding, Mode: command.Mode,
				RequestHash: requestHash, SealedCommand: sealed, Approval: approval,
			}
			if err := s.appendCodeSigningCommand(ctx, tenantID, operationID, eventTime, commanded); err != nil {
				return api.CodeSigningResponse{}, err
			}
		default:
			return api.CodeSigningResponse{}, fenceErr
		}
		op, found, err = s.store.CodeSigningOperationByIdempotency(ctx, tenantID, idempotencyKey)
		if err != nil {
			return api.CodeSigningResponse{}, err
		}
	}
	if !found {
		return api.CodeSigningResponse{}, errors.New("codesign: command projection is missing")
	}
	if (op.OperationID != operationID && op.OperationID != legacyOperationID) ||
		op.Mode != command.Mode || op.RequestHash != requestHash {
		return api.CodeSigningResponse{}, errors.New("codesign: idempotency key was already used for a different signing request")
	}
	operationID = op.OperationID
	if response, done, err := codeSigningTerminalResponse(op); done {
		return response, err
	}

	// Only the normal bounded dispatcher performs signer/attestor/Rekor work. The
	// API goroutine wakes it and polls this exact operation outside any SQL tx.
	s.wake()
	return s.waitForResult(ctx, tenantID, operationID)
}

// projectRetainedCodeSigningCommand closes the approval-disabled crash window
// where a deterministic command reached JetStream but its SQL projection did
// not commit. Retry checks both current and historical identities before doing
// authorization or randomized sealing. Exactly one closed envelope may exist;
// the canonical retained ciphertext is reprojected and no provider/outbox work
// is duplicated even after broker duplicate memory expires.
func (s *servedCodeSigningService) projectRetainedCodeSigningCommand(
	ctx context.Context,
	tenantID, operationID, legacyOperationID, idempotencyKey, mode, requestHash string,
) (bool, error) {
	type candidate struct {
		event     events.Event
		found     bool
		isLegacy  bool
		approved  bool
		operation string
	}
	candidates := []candidate{
		{operation: operationID},
		{operation: legacyOperationID, isLegacy: true},
		{operation: operationID, approved: true},
		{operation: legacyOperationID, isLegacy: true, approved: true},
	}
	for i := range candidates {
		eventID := codeSigningEventID(tenantID, projections.EventCodeSigningCommanded, candidates[i].operation)
		if candidates[i].approved {
			eventID = codeSigningApprovedEventID(tenantID, candidates[i].operation)
		}
		retained, found, err := s.log.EventByID(ctx, eventID)
		if err != nil {
			return false, err
		}
		candidates[i].event = retained
		candidates[i].found = found
	}
	var retained candidate
	retainedCount := 0
	for _, candidate := range candidates {
		if candidate.found {
			retained = candidate
			retainedCount++
		}
	}
	if retainedCount > 1 {
		return false, fmt.Errorf("%w: multiple current/legacy code-signing command identities exist", store.ErrIdempotencyConflict)
	}
	if retainedCount == 0 {
		return false, nil
	}
	if err := s.validateRetainedCodeSigningCommand(
		ctx, retained.event, tenantID, operationID, legacyOperationID,
		idempotencyKey, mode, requestHash, retained.isLegacy, retained.approved,
	); err != nil {
		return false, err
	}
	if err := projections.New(s.store).Apply(ctx, retained.event); err != nil {
		return false, err
	}
	return true, nil
}

func (s *servedCodeSigningService) validateRetainedCodeSigningCommand(
	ctx context.Context,
	retained events.Event,
	tenantID, operationID, legacyOperationID, idempotencyKey, mode, requestHash string,
	legacy, approved bool,
) error {
	expectedOperationID := operationID
	expectedVersion := projections.CodeSigningPrivacySafeEventSchemaVersion
	if legacy {
		expectedOperationID = legacyOperationID
		expectedVersion = 1
	}
	eventID := codeSigningEventID(tenantID, projections.EventCodeSigningCommanded, expectedOperationID)
	if approved {
		eventID = codeSigningApprovedEventID(tenantID, expectedOperationID)
		if legacy {
			expectedVersion = projections.CodeSigningApprovalEventSchemaVersion
		}
	}
	version := retained.SchemaVersion
	if version == 0 {
		version = 1
	}
	if retained.ID != eventID || retained.Type != projections.EventCodeSigningCommanded ||
		retained.TenantID != tenantID || version != expectedVersion || retained.Time.IsZero() {
		return fmt.Errorf("%w: retained code-signing envelope differs", store.ErrIdempotencyConflict)
	}
	if !legacy && !retained.Time.Equal(retained.Time.UTC().Truncate(time.Microsecond)) {
		return fmt.Errorf("%w: retained privacy-safe code-signing timestamp is not PostgreSQL-exact", store.ErrIdempotencyConflict)
	}
	var payload projections.CodeSigningCommanded
	if err := json.Unmarshal(retained.Data, &payload); err != nil {
		return fmt.Errorf("codesign: decode retained command: %w", err)
	}
	if payload.OperationID != expectedOperationID || (payload.Approval != nil) != approved ||
		payload.Mode != mode || payload.RequestHash != requestHash || len(payload.SealedCommand) == 0 {
		return fmt.Errorf("%w: retained code-signing command differs", store.ErrIdempotencyConflict)
	}
	if legacy {
		validKey := payload.IdempotencyKey == idempotencyKey ||
			store.IsLegacyCodeSigningStorageKey(payload.IdempotencyKey, legacyOperationID)
		if !validKey || payload.IdempotencyKeyRef != "" || payload.RequestBinding != "" {
			return fmt.Errorf("%w: retained legacy code-signing key identity differs", store.ErrIdempotencyConflict)
		}
	} else {
		keyRef := store.CodeSigningIdempotencyKeyRef(idempotencyKey)
		requestBinding := projections.CodeSigningRequestBinding(requestHash, idempotencyKey)
		if payload.IdempotencyKey != "" || payload.IdempotencyKeyRef != keyRef ||
			payload.RequestBinding != requestBinding {
			return fmt.Errorf("%w: retained privacy-safe code-signing request binding differs", store.ErrIdempotencyConflict)
		}
	}
	if _, err := projections.CodeSigningCommandSemanticDigest(retained, payload); err != nil {
		return fmt.Errorf("%w: retained code-signing semantic basis is invalid: %v", store.ErrIdempotencyConflict, err)
	}
	if approved {
		if err := s.validateRetainedCodeSigningApproval(ctx, retained, payload, idempotencyKey); err != nil {
			return err
		}
	}
	return nil
}

func (s *servedCodeSigningService) validateRetainedCodeSigningApproval(
	ctx context.Context,
	retained events.Event,
	payload projections.CodeSigningCommanded,
	idempotencyKey string,
) error {
	use := payload.Approval
	if use == nil || use.RequestID == "" || use.IntentDigest == "" || use.Requester == "" ||
		use.RequiredApprovals <= 0 || use.FromState != "" || use.ToState != "" || use.TargetVersion != 0 ||
		use.Issuance != nil || use.ResourceKind != "code_signing" || use.Action != "sign" ||
		use.ResourceID != store.CodeSigningApprovalResourceID(payload.RequestHash, idempotencyKey) {
		return fmt.Errorf("%w: retained code-signing capability identity differs", store.ErrApprovalDrifted)
	}
	request, err := s.store.GetOperationApproval(ctx, retained.TenantID, use.RequestID)
	if err != nil {
		return err
	}
	if request.Status != store.ApprovalStatusConsumed || request.ConsumedEventID != retained.ID ||
		request.IntentDigest != use.IntentDigest || request.Requester != use.Requester ||
		request.ResourceKind != use.ResourceKind || request.ResourceID != use.ResourceID ||
		request.Action != use.Action || request.FromState != use.FromState ||
		request.ToState != use.ToState || request.TargetVersion != use.TargetVersion ||
		request.RequiredApprovals != use.RequiredApprovals || request.Reason != use.Reason ||
		!reflect.DeepEqual(request.EvidenceRefs, use.EvidenceRefs) {
		return fmt.Errorf("%w: retained code-signing capability was not consumed by this event", store.ErrApprovalDrifted)
	}
	return nil
}

func (s *servedCodeSigningService) authorizeCodeSigningCommand(
	ctx context.Context,
	tenantID, idempotencyKey, requestHash string,
	command codeSigningCommand,
) (*store.OperationApprovalUse, error) {
	gate, ok := s.cfg.Gate.(codeSigningExactApprovalGate)
	if !ok || !gate.CodeSigningApprovalRequired() {
		return nil, nil
	}
	resourceID := store.CodeSigningApprovalResourceID(requestHash, idempotencyKey)
	resourceName := command.KeyID
	if resourceName == "" {
		resourceName = "keyless " + command.ArtifactType
	}
	keyDigest := store.CodeSigningIdempotencyKeyDigest(idempotencyKey)
	intent := api.ApprovalIntent{
		TenantID: tenantID, ResourceKind: "code_signing", ResourceID: resourceID,
		ResourceName: resourceName, Action: codeSigningApprovalAction, Requester: command.Principal,
		Reason: "authorize one exact code-signing command",
		EvidenceRefs: []string{
			"request-sha256:" + requestHash,
			"idempotency-key-sha256:" + keyDigest,
			"artifact-sha256:" + fmt.Sprintf("%x", command.Digest),
			"artifact-type:" + command.ArtifactType,
			"mode:" + command.Mode,
		},
	}
	authority, approved, reason := gate.AuthorizeApproval(ctx, intent)
	if !approved {
		if reason == "" {
			reason = "the exact code-signing command awaits distinct approval"
		}
		return nil, fmt.Errorf("codesign: approval_required:%s request_id=%s intent_digest=%s: %s",
			resourceID, authority.RequestID, authority.IntentDigest, reason)
	}
	if authority.RequestID == "" || authority.IntentDigest == "" ||
		authority.Requester != command.Principal || authority.ResourceKind != intent.ResourceKind ||
		authority.ResourceID != resourceID || authority.Action != codeSigningApprovalAction ||
		authority.FromState != intent.FromState || authority.ToState != intent.ToState ||
		authority.TargetVersion != intent.TargetVersion || authority.RequiredApprovals <= 0 {
		return nil, store.ErrApprovalDrifted
	}
	return &store.OperationApprovalUse{
		RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
		Requester: authority.Requester, ResourceKind: authority.ResourceKind,
		ResourceID: authority.ResourceID, Action: authority.Action,
		FromState: authority.FromState, ToState: authority.ToState,
		TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
		Reason: authority.Reason, EvidenceRefs: append([]string(nil), authority.EvidenceRefs...),
		Issuance: authority.Issuance,
	}, nil
}

func (s *servedCodeSigningService) appendCodeSigningCommand(
	ctx context.Context,
	tenantID, operationID string,
	eventTime time.Time,
	payload projections.CodeSigningCommanded,
) error {
	if eventTime.IsZero() || !eventTime.Equal(eventTime.UTC().Truncate(time.Microsecond)) {
		return errors.New("codesign: command event time must be UTC PostgreSQL microsecond precision")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := codeSigningEventID(tenantID, projections.EventCodeSigningCommanded, operationID)
	if payload.Approval != nil {
		eventID = codeSigningApprovedEventID(tenantID, operationID)
	}
	candidate := events.Event{
		ID: eventID, Type: projections.EventCodeSigningCommanded,
		TenantID: tenantID, Time: eventTime,
		SchemaVersion: projections.CodeSigningPrivacySafeEventSchemaVersion,
		Data:          raw,
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		candidate.Actor = &actor
	}
	semanticDigest, err := projections.CodeSigningCommandSemanticDigest(candidate, payload)
	if err != nil {
		return err
	}
	if payload.Approval == nil {
		event, err := s.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if s.afterCommandAppend != nil {
			if err := s.afterCommandAppend(event); err != nil {
				return err
			}
		}
		return projections.New(s.store).Apply(ctx, event)
	}
	fence, _, err := s.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantID, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey:     operationID,
		RequestBinding: payload.RequestBinding,
		EventID:        eventID, EventType: projections.EventCodeSigningCommanded,
		SchemaVersion: projections.CodeSigningPrivacySafeEventSchemaVersion,
		EventTime:     eventTime, Actor: candidate.Actor, Payload: raw, SemanticDigest: semanticDigest,
	}, *payload.Approval)
	if err != nil {
		return err
	}
	return s.projectCodeSigningFence(ctx, tenantID, fence)
}

func (s *servedCodeSigningService) codeSigningCommandEventTime() time.Time {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	return now.UTC().Truncate(time.Microsecond)
}

// projectCodeSigningFence heals the exact crash window between a successful
// broker Append and a rolled-back SQL projection. The grant and randomized
// ciphertext already live in PostgreSQL, so this path never authorizes again and
// never reseals the plaintext command. It scans retained history before Append;
// broker duplicate-memory expiry therefore cannot create a second command.
func (s *servedCodeSigningService) projectCodeSigningFence(ctx context.Context, tenantID string, fence store.ApprovedTargetFence) error {
	return s.store.WithPrivacyRecoveryBarrier(ctx, tenantID,
		"approved-code-signing recovery privacy barrier", func(barrierCtx context.Context) error {
			latest, err := s.store.GetApprovedTargetFence(barrierCtx, tenantID,
				store.ApprovedTargetCodeSigningCommand, fence.CommandKey)
			if err != nil {
				return err
			}
			if latest.EventID != fence.EventID || latest.RequestBinding != fence.RequestBinding {
				return fmt.Errorf("%w: approved code-signing fence changed across privacy barrier", store.ErrIdempotencyConflict)
			}
			return s.projectCodeSigningFenceUnbarriered(barrierCtx, tenantID, latest)
		})
}

func (s *servedCodeSigningService) projectCodeSigningFenceUnbarriered(
	ctx context.Context,
	tenantID string,
	fence store.ApprovedTargetFence,
) error {
	if fence.TenantID != tenantID || fence.TargetKind != store.ApprovedTargetCodeSigningCommand {
		return fmt.Errorf("%w: approved code-signing fence scope differs", store.ErrIdempotencyConflict)
	}
	retained, retainedFound, err := s.log.EventByID(ctx, fence.EventID)
	if err != nil {
		return err
	}
	projector := projections.New(s.store)
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		locked, use, privacyRewritten, err := s.store.LockApprovedTargetFenceTx(ctx, tx, tenantID,
			store.ApprovedTargetCodeSigningCommand, fence.CommandKey)
		if err != nil {
			return err
		}
		var payload projections.CodeSigningCommanded
		if err := json.Unmarshal(locked.Payload, &payload); err != nil {
			return fmt.Errorf("codesign: decode durable approved command: %w", err)
		}
		originalApproval := payload.Approval
		payload.Approval = &use
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		candidate := events.Event{
			ID: locked.EventID, Type: locked.EventType, TenantID: tenantID,
			Time: locked.EventTime, SchemaVersion: locked.SchemaVersion, Actor: locked.Actor, Data: data,
		}
		wantSemantic, err := projections.CodeSigningCommandSemanticDigest(candidate, payload)
		if err != nil {
			return err
		}
		if wantSemantic != locked.SemanticDigest {
			if locked.SchemaVersion != projections.CodeSigningApprovalEventSchemaVersion {
				return fmt.Errorf("%w: approved code-signing fence semantic digest differs", store.ErrIdempotencyConflict)
			}
			// A schema-v2 fence may have committed the historical nanosecond digest
			// before PostgreSQL rounded EventTime. If JetStream retained the event,
			// prove that exact predecessor. If Append never happened, the historical
			// SHA leaves only the 1,000 nanosecond remainders inside the stored
			// microsecond. Exhausting that bounded set recovers the exact original
			// timestamp and rejects a corrupted digest instead of guessing.
			if retainedFound {
				if !codeSigningFenceTimesMatch(retained.Time, locked.EventTime, locked.SchemaVersion) {
					return fmt.Errorf("%w: retained legacy code-signing fence time differs", store.ErrIdempotencyConflict)
				}
				var retainedPayload projections.CodeSigningCommanded
				if err := json.Unmarshal(retained.Data, &retainedPayload); err != nil {
					return fmt.Errorf("codesign: decode retained legacy approved command: %w", err)
				}
				historical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(retained, retainedPayload)
				if err != nil || historical != locked.SemanticDigest {
					if err == nil {
						err = store.ErrIdempotencyConflict
					}
					return fmt.Errorf("%w: retained legacy code-signing fence semantic digest differs", err)
				}
			} else {
				matches := 0
				base := locked.EventTime.UTC().Truncate(time.Microsecond)
				for remainder := range 1_000 {
					probe := candidate
					probe.Time = base.Add(time.Duration(remainder) * time.Nanosecond)
					historical, probeErr := projections.LegacyCodeSigningHistoricalSemanticDigest(probe, payload)
					if probeErr != nil {
						return probeErr
					}
					if historical == locked.SemanticDigest {
						candidate.Time = probe.Time
						matches++
					}
				}
				if matches != 1 {
					return fmt.Errorf("%w: legacy code-signing fence timestamp proof matched %d nanosecond remainders",
						store.ErrIdempotencyConflict, matches)
				}
			}
		}
		event := retained
		if !retainedFound {
			event, err = s.log.Append(ctx, candidate)
			if err != nil {
				return err
			}
			if s.afterCommandAppend != nil {
				if err := s.afterCommandAppend(event); err != nil {
					return err
				}
			}
		}
		if event.ID != locked.EventID || event.Type != locked.EventType || event.TenantID != tenantID ||
			event.SchemaVersion != locked.SchemaVersion ||
			!codeSigningFenceTimesMatch(event.Time, locked.EventTime, locked.SchemaVersion) {
			return fmt.Errorf("%w: canonical approved code-signing event envelope differs", store.ErrIdempotencyConflict)
		}
		var canonical projections.CodeSigningCommanded
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return fmt.Errorf("codesign: decode canonical approved command: %w", err)
		}
		gotSemantic, err := projections.CodeSigningCommandSemanticDigest(event, canonical)
		if err != nil {
			return err
		}
		if gotSemantic != locked.SemanticDigest {
			compatible := false
			if locked.SchemaVersion == projections.CodeSigningApprovalEventSchemaVersion {
				historical, historicalErr := projections.LegacyCodeSigningHistoricalSemanticDigest(event, canonical)
				if historicalErr != nil {
					return historicalErr
				}
				compatible = historical == locked.SemanticDigest
			}
			if !compatible {
				return fmt.Errorf("%w: canonical approved code-signing command differs", store.ErrIdempotencyConflict)
			}
		}
		if canonical.Approval == nil || originalApproval == nil {
			return fmt.Errorf("%w: canonical approved code-signing command lacks approval", store.ErrIdempotencyConflict)
		}
		if privacyRewritten {
			if err := store.ValidateApprovedTargetActorPrivacyRewrite(tenantID,
				locked.Actor, use.Requester, event.Actor, originalApproval.Requester); err != nil {
				return fmt.Errorf("%w: canonical approved code-signing actor privacy rewrite differs", err)
			}
			if retainedFound {
				if err := store.ValidateApprovedTargetPrivacyRewrite(tenantID, *originalApproval, use, *canonical.Approval); err != nil {
					return fmt.Errorf("%w: canonical approved code-signing privacy rewrite differs", err)
				}
			}
			canonical.Approval = &use
			projectData, err := json.Marshal(canonical)
			if err != nil {
				return err
			}
			event.Data = projectData
		} else if !reflect.DeepEqual(event.Actor, locked.Actor) || !bytes.Equal(event.Data, locked.Payload) {
			return fmt.Errorf("%w: canonical approved code-signing bytes differ", store.ErrIdempotencyConflict)
		}
		return projector.ApplyTx(ctx, tx, event)
	})
}

func codeSigningFenceTimesMatch(eventTime, fenceTime time.Time, schemaVersion int) bool {
	if schemaVersion >= projections.CodeSigningPrivacySafeEventSchemaVersion {
		return eventTime.Equal(fenceTime.UTC())
	}
	// PostgreSQL stores timestamptz at microsecond precision. Historical v1/v2
	// events could retain nanoseconds in JetStream, so compare their exact SQL
	// round-trip value without changing the historical semantic digest.
	return eventTime.UTC().Truncate(time.Microsecond).Equal(fenceTime.UTC())
}

// reconcileApprovedTargetEventFences repairs commands whose independent SQL
// claim survived but whose target projection did not. It intentionally does not
// require the served feature to remain enabled: projecting the already-approved
// immutable command is recovery, not fresh authorization. Any resulting worker
// intent stays safely queued until its bounded dispatcher is configured.
func reconcileApprovedTargetEventFences(ctx context.Context, st *store.Store, log *events.Log, orch *orchestrator.Orchestrator) (int, error) {
	if st == nil || log == nil || orch == nil {
		return 0, errors.New("server: approved target reconciliation requires store, event log, and orchestrator")
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	codeSigningRecovery := &servedCodeSigningService{store: st, log: log}
	healed := 0
	for _, tenant := range tenants {
		if err := st.WithPrivacyRecoveryBarrier(ctx, tenant.TenantID,
			"approved-target reconciliation privacy barrier", func(context.Context) error { return nil }); err != nil {
			return healed, err
		}
		fences, err := st.ListApprovedTargetFences(ctx, tenant.TenantID)
		if err != nil {
			return healed, err
		}
		for _, fence := range fences {
			switch fence.TargetKind {
			case store.ApprovedTargetEphemeralCertificate:
				if _, err := orch.ProjectApprovedCertificateFence(ctx, tenant.TenantID, fence); err != nil {
					return healed, fmt.Errorf("server: reconcile approved certificate %s: %w", fence.EventID, err)
				}
			case store.ApprovedTargetCodeSigningCommand:
				if err := codeSigningRecovery.projectCodeSigningFence(ctx, tenant.TenantID, fence); err != nil {
					return healed, fmt.Errorf("server: reconcile approved code-signing command %s: %w", fence.EventID, err)
				}
			default:
				return healed, fmt.Errorf("server: reconcile unsupported approved target kind %q", fence.TargetKind)
			}
			healed++
		}
	}
	return healed, nil
}

func codeSigningCommandHash(command codeSigningCommand) (string, error) {
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(raw), nil
}

func (s *servedCodeSigningService) waitForResult(ctx context.Context, tenantID, operationID string) (api.CodeSigningResponse, error) {
	waitCtx, cancel := context.WithTimeout(ctx, codeSigningWaitLimit)
	defer cancel()
	ticker := time.NewTicker(codeSigningPollInterval)
	defer ticker.Stop()
	for {
		op, found, err := s.store.CodeSigningOperationByID(waitCtx, tenantID, operationID)
		if err != nil {
			return api.CodeSigningResponse{}, err
		}
		if !found {
			return api.CodeSigningResponse{}, errors.New("codesign: projected operation disappeared")
		}
		if response, done, terminalErr := codeSigningTerminalResponse(op); done {
			return response, terminalErr
		}
		if outboxRecord, getErr := s.outbox.Get(waitCtx, tenantID, op.CommandOutboxID); getErr != nil {
			return api.CodeSigningResponse{}, getErr
		} else if outboxRecord.Status == "failed" {
			failure := outboxRecord.LastError
			if failure == "" {
				failure = "signing worker exhausted its retry budget"
			}
			if err := s.recordTerminalFailure(waitCtx, op, errors.New(failure)); err != nil {
				return api.CodeSigningResponse{}, err
			}
			continue
		}
		select {
		case <-waitCtx.Done():
			return api.CodeSigningResponse{}, fmt.Errorf("codesign: signing remains pending: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func codeSigningTerminalResponse(op store.CodeSigningOperation) (api.CodeSigningResponse, bool, error) {
	switch op.Status {
	case "queued":
		return api.CodeSigningResponse{}, false, nil
	case "failed":
		return api.CodeSigningResponse{}, true, fmt.Errorf("codesign: prior signing command failed: %s", op.LastError)
	case "completed":
		var response api.CodeSigningResponse
		if err := json.Unmarshal(op.Response, &response); err != nil {
			return api.CodeSigningResponse{}, true, fmt.Errorf("codesign: decode persisted response: %w", err)
		}
		return response, true, nil
	default:
		return api.CodeSigningResponse{}, true, fmt.Errorf("codesign: unsupported projected status %q", op.Status)
	}
}

// Deliver owns the two first-party code-signing outbox destinations. A command
// failure is recorded as an immutable terminal event before the command row is
// acknowledged; infrastructure failures while recording remain retryable.
func (s *servedCodeSigningService) Deliver(ctx context.Context, message orchestrator.Message) (bool, error) {
	switch message.Destination {
	case store.CodeSigningCommandDestination:
		return true, s.deliverCommand(ctx, message)
	case store.CodeSigningCleanupDestination:
		return true, s.deliverCleanup(ctx, message)
	default:
		return false, nil
	}
}

// DeliverTerminalFailure projects a code-signing command's terminal state before
// the generic outbox marks the command dead-lettered. This callback is independent
// of the request goroutine: a caller may disconnect long before retries are
// exhausted, but the operation must still leave "queued" and keyless cleanup must
// still be scheduled.
func (s *servedCodeSigningService) DeliverTerminalFailure(ctx context.Context, message orchestrator.Message, cause error) (bool, error) {
	if message.Destination != store.CodeSigningCommandDestination {
		return false, nil
	}
	op, found, err := s.codeSigningCommandOperation(ctx, message)
	if err != nil {
		return true, err
	}
	if !found {
		return true, errors.New("codesign: terminal command has no projected operation")
	}
	if op.Status == "completed" || op.Status == "failed" {
		return true, nil
	}
	if op.Status != "queued" {
		return true, fmt.Errorf("codesign: terminal command has invalid projected status %q", op.Status)
	}
	return true, s.recordTerminalFailure(ctx, op, cause)
}

func (s *servedCodeSigningService) deliverCommand(ctx context.Context, message orchestrator.Message) error {
	op, found, err := s.codeSigningCommandOperation(ctx, message)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("codesign: command has no projected operation")
	}
	if op.Status == "completed" || op.Status == "failed" {
		return nil
	}
	plain, err := openTenantValue(ctx, s.crypto, s.kek, op.TenantID, op.SealedCommand,
		codeSigningCommandAAD(op.TenantID, op.OperationID, op.Mode, op.RequestHash))
	if err != nil {
		return s.recordTerminalFailure(ctx, op, fmt.Errorf("open sealed command: %w", err))
	}
	defer secret.Wipe(plain)
	var command codeSigningCommand
	if err := json.Unmarshal(plain, &command); err != nil {
		return s.recordTerminalFailure(ctx, op, fmt.Errorf("decode sealed command: %w", err))
	}
	defer secret.Wipe(command.Digest)
	defer secret.Wipe(command.IdentityPayload)
	if command.Mode != op.Mode || crypto.SHA256Hex(plain) != op.RequestHash {
		return s.recordTerminalFailure(ctx, op, errors.New("sealed command binding mismatch"))
	}
	response, transparency, ephemeralHandle, err := s.executeCommand(ctx, op, command)
	if err != nil {
		if codeSigningExecutionIsTerminal(err) {
			return s.recordTerminalFailure(ctx, op, err, ephemeralHandle)
		}
		// Infrastructure failures must consume the bounded outbox retry budget. The
		// operation stays queued; if retries exhaust, DeliverTerminalFailure projects
		// the closed failure code and schedules deterministic keyless cleanup.
		return err
	}
	if s.afterSign != nil {
		if err := s.afterSign(ctx, response); err != nil {
			return err // crash-equivalent: retry, do not create a false terminal event
		}
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return err
	}
	transparency.QueuedAt = time.Now().UTC()
	transparencyBytes, err := json.Marshal(transparency)
	if err != nil {
		return err
	}
	return s.appendAndProject(ctx, op.TenantID, projections.EventCodeSigningCompleted, op.OperationID, projections.CodeSigningCompleted{
		OperationID: op.OperationID, RequestHash: op.RequestHash,
		Response: responseBytes, RekorDestination: s.cfg.RekorDestination,
		RekorPayload: transparencyBytes, EphemeralHandle: ephemeralHandle,
	})
}

func (s *servedCodeSigningService) codeSigningCommandOperation(ctx context.Context, message orchestrator.Message) (store.CodeSigningOperation, bool, error) {
	var ref projections.CodeSigningCommandReference
	if err := json.Unmarshal(message.Payload, &ref); err != nil || ref.OperationID == "" {
		if err == nil {
			err = errors.New("operation_id is required")
		}
		return store.CodeSigningOperation{}, false, fmt.Errorf("codesign: decode command: %w", err)
	}
	expectedKey := "codesign.command:" + ref.OperationID
	if message.IdempotencyKey != expectedKey {
		return store.CodeSigningOperation{}, false, errors.New("codesign: command outbox identity is invalid")
	}
	op, found, err := s.store.CodeSigningOperationByID(ctx, message.TenantID, ref.OperationID)
	if err != nil || !found {
		return op, found, err
	}
	if op.CommandOutboxID != message.ID {
		return store.CodeSigningOperation{}, false, errors.New("codesign: command outbox does not match its durable operation")
	}
	return op, true, nil
}

func (s *servedCodeSigningService) executeCommand(ctx context.Context, op store.CodeSigningOperation, command codeSigningCommand) (api.CodeSigningResponse, codeSigningTransparencyPayload, string, error) {
	if op.ApprovalRequestID != "" {
		approval, err := s.store.GetOperationApproval(ctx, op.TenantID, op.ApprovalRequestID)
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", err
		}
		resourceID, err := store.CodeSigningApprovalResourceIDForOperation(
			op.TenantID, op.OperationID, op.RequestHash, op.IdempotencyKey, approval.ResourceID,
		)
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", err
		}
		if op.SourceEventID != codeSigningApprovedEventID(op.TenantID, op.OperationID) {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "",
				fmt.Errorf("%w: approved code-signing source event is invalid", codesign.ErrPolicyDenied)
		}
		consumed, err := s.store.CodeSigningApprovalConsumed(ctx, op.TenantID, resourceID,
			op.ApprovalRequestID, op.ApprovalIntentDigest, op.SourceEventID)
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", err
		}
		if !consumed {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "",
				fmt.Errorf("%w: exact code-signing approval was not consumed", codesign.ErrPolicyDenied)
		}
	} else if gate, ok := s.cfg.Gate.(codeSigningExactApprovalGate); ok && gate.CodeSigningApprovalRequired() {
		return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "",
			fmt.Errorf("%w: legacy code-signing command lacks approval authority", codesign.ErrPolicyDenied)
	}
	svc, err := codesign.New(codesign.Config{
		TenantID: op.TenantID, Keys: s.cfg.Keys, Gate: s.cfg.Gate,
		Audit: codeSigningEventAuditor{log: s.log},
	})
	if err != nil {
		return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", terminalCodeSigningDomainError(err)
	}
	switch command.Mode {
	case "key":
		sig, err := svc.Sign(ctx, codesign.SignRequest{
			OperationID: op.OperationID, Principal: command.Principal,
			KeyID: command.KeyID, ArtifactType: command.ArtifactType,
			Digest: command.Digest,
		})
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", err
		}
		return api.CodeSigningResponse{
				Algorithm: sig.Algorithm, KeyID: sig.KeyID, ArtifactType: sig.ArtifactType,
				Signature: sig.Value, PublicKeyDER: sig.PublicKeyDER,
				TransparencyDestination: s.cfg.RekorDestination,
			}, codeSigningTransparencyPayload{
				Mode: "key", Principal: command.Principal, KeyID: sig.KeyID,
				ArtifactType: sig.ArtifactType, DigestHex: fmt.Sprintf("%x", command.Digest),
				Algorithm: sig.Algorithm, Signature: sig.Value, PublicKeyDER: sig.PublicKeyDER,
			}, "", nil
	case "keyless":
		attestors := s.cfg.Attestors
		if s.cfg.AttestorsForTenant != nil {
			attestors = s.cfg.AttestorsForTenant(op.TenantID)
		}
		verifier, err := attest.NewVerifier(attest.Config{
			TenantID: op.TenantID, Attestors: attestors,
			Audit: codeSigningEventAuditor{log: s.log},
		})
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", terminalCodeSigningDomainError(err)
		}
		identity, err := verifier.Verify(ctx, command.IdentityMethod, command.IdentityPayload)
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", terminalCodeSigningDomainError(err)
		}
		ephemeral, handle, err := s.cfg.NewEphemeralSigner(ctx, op.OperationID, s.cfg.EphemeralAlgorithm)
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", err
		}
		if ephemeral == nil || handle == "" {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", terminalCodeSigningDomainError(errors.New("server: ephemeral signer factory returned an incomplete signer"))
		}
		sig, err := svc.SignKeyless(ctx, codesign.KeylessRequest{
			OperationID: op.OperationID, Principal: command.Principal, Identity: identity,
			FulcioSAN: command.FulcioSAN, FulcioIssuer: command.FulcioIssuer,
			Ephemeral: ephemeral, ArtifactType: command.ArtifactType, Digest: command.Digest,
		})
		if err != nil {
			return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, handle, err
		}
		return api.CodeSigningResponse{
				Algorithm: sig.Algorithm, ArtifactType: sig.ArtifactType,
				Signature: sig.Value, PublicKeyDER: sig.PublicKeyDER,
				FulcioSAN: sig.FulcioSAN, FulcioIssuer: sig.FulcioIssuer,
				TransparencyDestination: s.cfg.RekorDestination,
			}, codeSigningTransparencyPayload{
				Mode: "keyless", Principal: command.Principal, ArtifactType: sig.ArtifactType,
				DigestHex: fmt.Sprintf("%x", command.Digest), Algorithm: sig.Algorithm,
				Signature: sig.Value, PublicKeyDER: sig.PublicKeyDER,
				FulcioSAN: sig.FulcioSAN, FulcioIssuer: sig.FulcioIssuer,
			}, handle, nil
	default:
		return api.CodeSigningResponse{}, codeSigningTransparencyPayload{}, "", terminalCodeSigningDomainError(fmt.Errorf("codesign: unsupported command mode %q", command.Mode))
	}
}

func (s *servedCodeSigningService) recordTerminalFailure(ctx context.Context, op store.CodeSigningOperation, failure error, handles ...string) error {
	message := codeSigningFailureCode(failure)
	ephemeralHandle := ""
	if len(handles) > 0 {
		ephemeralHandle = handles[0]
	}
	// The production keyless handle is a pure function of operationID. Derive it
	// even when the process died after creating/signing with the key but before it
	// could return the handle to the completion projector. DestroyKey is idempotent,
	// so scheduling cleanup for a pre-key attestation failure is also safe.
	if op.Mode == "keyless" && ephemeralHandle == "" {
		ephemeralHandle = codeSigningEphemeralHandle(op.OperationID)
	}
	if err := s.appendAndProject(ctx, op.TenantID, projections.EventCodeSigningFailed, op.OperationID,
		projections.CodeSigningFailed{OperationID: op.OperationID, Error: message, EphemeralHandle: ephemeralHandle}); err != nil {
		return err
	}
	return nil
}

// codeSigningFailureCode is intentionally closed-form. Attestors and provider
// clients may echo attacker-controlled identity payloads in their errors; those
// strings must never enter the immutable event log or relational read model. The
// sole parameterized form is a validated, fixed-length approval-resource digest.
func codeSigningFailureCode(failure error) string {
	if failure == nil {
		return "command_failed"
	}
	text := strings.ToLower(failure.Error())
	if resource := codeSigningApprovalResourceFromFailure(text); resource != "" {
		return "approval_required:" + resource
	}
	switch {
	case strings.Contains(text, "sealed command"), strings.Contains(text, "binding mismatch"), strings.Contains(text, "decode sealed"):
		return "sealed_command_invalid"
	case strings.Contains(text, "attest"), strings.Contains(text, "verified identity"), strings.Contains(text, "fulcio"):
		return "identity_attestation_failed"
	case strings.Contains(text, "not permitted"), strings.Contains(text, "policy"):
		return "policy_denied"
	case strings.Contains(text, "no key"), strings.Contains(text, "resolve key"):
		return "signing_key_unavailable"
	case strings.Contains(text, "sign"), strings.Contains(text, "journal"):
		return "signer_operation_failed"
	default:
		return "command_failed"
	}
}

func codeSigningApprovalResourceFromFailure(text string) string {
	const marker = "approval resource "
	start := strings.Index(text, marker)
	if start < 0 {
		return ""
	}
	value := text[start+len(marker):]
	if end := strings.IndexAny(value, ",)"); end >= 0 {
		value = value[:end]
	}
	const prefix = "codesign:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return ""
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, prefix)); err != nil {
		return ""
	}
	return value
}

func (s *servedCodeSigningService) deliverCleanup(ctx context.Context, message orchestrator.Message) error {
	var ref projections.CodeSigningCommandReference
	if err := json.Unmarshal(message.Payload, &ref); err != nil || ref.OperationID == "" {
		if err == nil {
			err = errors.New("operation_id is required")
		}
		return fmt.Errorf("codesign: decode cleanup command: %w", err)
	}
	op, found, err := s.store.CodeSigningOperationByID(ctx, message.TenantID, ref.OperationID)
	if err != nil {
		return err
	}
	if !found || (op.Status != "completed" && op.Status != "failed") || op.Mode != "keyless" || op.EphemeralHandle == "" {
		return errors.New("codesign: cleanup command has no terminal keyless operation")
	}
	if message.IdempotencyKey != "codesign.cleanup:"+op.OperationID || message.ID != op.CleanupOutboxID {
		return errors.New("codesign: cleanup outbox does not match its durable operation")
	}
	if op.CleanupStatus == "completed" {
		return nil
	}
	if err := s.cfg.DestroyEphemeralSigner(ctx, op.EphemeralHandle); err != nil {
		return fmt.Errorf("codesign: destroy ephemeral signer handle: %w", err)
	}
	return s.appendAndProject(ctx, op.TenantID, projections.EventCodeSigningEphemeralDestroyed, op.OperationID,
		projections.CodeSigningCommandReference{OperationID: op.OperationID})
}

func (s *servedCodeSigningService) appendAndProject(ctx context.Context, tenantID, eventType, operationID string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event, err := s.log.Append(ctx, events.Event{
		ID:   codeSigningEventID(tenantID, eventType, operationID),
		Type: eventType, TenantID: tenantID, Data: data,
	})
	if err != nil {
		return err
	}
	return projections.New(s.store).Apply(ctx, event)
}

func codeSigningEventID(tenantID, eventType, operationID string) string {
	return "codesign-event-" + uuid.NewSHA1(codeSigningEventNamespace,
		[]byte(tenantID+"\x00"+eventType+"\x00"+operationID)).String()
}

// codeSigningApprovedEventID is the actual UUID event identity stored beside
// the consumed capability. Historical code-signing events keep their prefixed
// IDs; approval authority's consumed_event_id column is intentionally UUID-only.
func codeSigningApprovedEventID(tenantID, operationID string) string {
	return projections.CodeSigningApprovalEventID(tenantID, operationID)
}

func codeSigningOperationID(tenantID, idempotencyKey string) string {
	return projections.CodeSigningOperationID(tenantID, idempotencyKey)
}

func codeSigningEphemeralHandle(operationID string) string {
	return "codesign-ephemeral-" + crypto.SHA256Hex([]byte(operationID))[:32]
}

func codeSigningCommandAAD(tenantID, operationID, mode, requestHash string) []byte {
	return []byte("trstctl:codesign-command:v1\x00" + tenantID + "\x00" + operationID + "\x00" + mode + "\x00" + requestHash)
}

type codeSigningTransparencyPayload struct {
	Mode         string    `json:"mode"`
	Principal    string    `json:"principal"`
	KeyID        string    `json:"key_id,omitempty"`
	ArtifactType string    `json:"artifact_type"`
	DigestHex    string    `json:"digest_hex"`
	Algorithm    string    `json:"algorithm"`
	Signature    []byte    `json:"signature"`
	PublicKeyDER []byte    `json:"public_key_der"`
	FulcioSAN    string    `json:"fulcio_san,omitempty"`
	FulcioIssuer string    `json:"fulcio_issuer,omitempty"`
	QueuedAt     time.Time `json:"queued_at"`
}

type codeSigningEventAuditor struct{ log *events.Log }

func (a codeSigningEventAuditor) Audit(ctx context.Context, eventType, tenantID string, data []byte) error {
	if a.log == nil {
		return nil
	}
	_, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	return err
}

type emptyCodeSigningKeys struct{}

func (emptyCodeSigningKeys) Signer(_ string, keyID string) (crypto.DigestSigner, error) {
	return nil, fmt.Errorf("codesign: no key %s", keyID)
}

// CodeSigningIdentities answers B-4: the tenant's recent signing operations
// with the transparency-log state of each. The Rekor handler refuses to
// acknowledge an entry whose signed receipt does not verify, so a delivered
// transparency outbox row IS a verified entry — the store join reads that
// state rather than a parallel flag that could drift from it.
func (s *Server) CodeSigningIdentities(ctx context.Context, tenantID string) ([]api.CodeSigningIdentity, error) {
	if s.store == nil {
		return nil, nil
	}
	destination := defaultRekorDestination
	if s.codeSign != nil && s.codeSign.cfg.RekorDestination != "" {
		destination = s.codeSign.cfg.RekorDestination
	}
	rows, err := s.store.ListCodeSigningIdentities(ctx, tenantID, destination, 0)
	if err != nil {
		return nil, err
	}
	out := make([]api.CodeSigningIdentity, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.CodeSigningIdentity{
			OperationID: row.OperationID, Mode: row.Mode, Status: row.Status,
			RequestHash: row.RequestHash, Transparency: row.Transparency,
			TransparencyError: row.TransparencyError, LastError: row.LastError,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		})
	}
	return out, nil
}
