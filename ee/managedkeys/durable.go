// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

// Durable served managed-key composition. API handlers append a requested
// event whose projection atomically creates the tenant read row and
// managedkey.command outbox entry. The licensed outbox handler is the sole
// caller of the isolated signer's ManageKey RPC. Completion is another event,
// so restart/rebuild uses PostgreSQL + NATS rather than process-local maps.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

const managedKeyCommandDestination = "managedkey.command"

type durableService struct {
	store         *store.Store
	log           *events.Log
	provider      string
	approvals     api.ExactApprovalChecker
	loadOperation func(context.Context, string, string) (store.ManagedKeyOperation, error)
	loadKey       func(context.Context, string, string, string) (store.ManagedKey, error)
}

func (s *durableService) operation(ctx context.Context, tenantID, operationID string) (store.ManagedKeyOperation, error) {
	if s.loadOperation != nil {
		return s.loadOperation(ctx, tenantID, operationID)
	}
	return s.store.GetManagedKeyOperation(ctx, tenantID, operationID)
}

func (s *durableService) key(ctx context.Context, tenantID, provider, keyID string) (store.ManagedKey, error) {
	if s.loadKey != nil {
		return s.loadKey(ctx, tenantID, provider, keyID)
	}
	return s.store.GetManagedKey(ctx, tenantID, provider, keyID)
}

// NewDurableFactory returns the production managed-key API service. It does not
// receive a provider backend or signer client and therefore cannot make an
// external call from the HTTP transaction.
func NewDurableFactory(provider string) server.ManagedKeyServiceFactory {
	provider = normalizeProvider(provider)
	return func(d server.ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
		if d.Store == nil || d.Log == nil {
			return nil, errors.New("managedkeys: durable store and event log are required")
		}
		if provider == "" {
			return nil, errors.New("managedkeys: a signer-local provider selection is required")
		}
		if d.ApprovalChecker == nil {
			return nil, errors.New("managedkeys: durable destructive commands require exact one-shot approval authority")
		}
		svc := &durableService{store: d.Store, log: d.Log, provider: provider, approvals: d.ApprovalChecker}
		return svc, nil
	}
}

// NewDurableOutboxFactory installs the only production caller of
// signing.Client.ManageKey.
func NewDurableOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		if d.Store == nil || d.Log == nil {
			return nil, errors.New("managedkeys: outbox handler requires store and event log")
		}
		return &durableOutboxHandler{store: d.Store, log: d.Log, signer: d.ManagedKeyCustody}, nil
	}
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "aws", "aws-kms":
		return "aws-kms"
	case "azure", "azure-kv", "azure-key-vault", "azure-managed-hsm":
		return "azure-key-vault"
	case "gcp", "gcp-kms":
		return "gcp-kms"
	case "pkcs11", "pkcs#11":
		return "pkcs11"
	case "tpm", "tpm2":
		return "tpm2"
	case "yubihsm", "yubihsm2":
		return "yubihsm2"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func (s *durableService) Generate(ctx context.Context, tenantID string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (Result, error) {
	return s.submit(ctx, tenantID, "", "", ActionGenerate, alg, idempotencyKey, requestBinding)
}

func (s *durableService) Rotate(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (Result, error) {
	return s.submit(ctx, tenantID, keyID, requester, ActionRotate, "", idempotencyKey, requestBinding)
}

func (s *durableService) Revoke(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (Result, error) {
	return s.submit(ctx, tenantID, keyID, requester, ActionRevoke, "", idempotencyKey, requestBinding)
}

func (s *durableService) Zeroize(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (Result, error) {
	return s.submit(ctx, tenantID, keyID, requester, ActionZeroize, "", idempotencyKey, requestBinding)
}

func (s *durableService) submit(ctx context.Context, tenantID, keyID, requester, action string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (Result, error) {
	if tenantID == "" {
		return Result{}, ErrTenantRequired
	}
	if idempotencyKey == "" {
		return Result{}, errors.New("managedkeys: idempotency key is required")
	}
	if requestBinding == "" {
		return Result{}, errors.New("managedkeys: authenticated request binding is required")
	}
	if action == ActionGenerate && alg == "" {
		return Result{}, errors.New("managedkeys: generation algorithm is required")
	}
	if action != ActionGenerate {
		if keyID == "" {
			return Result{}, ErrKeyRefRequired
		}
	}
	operationID, err := durableOperationID(tenantID, idempotencyKey)
	if err != nil {
		return Result{}, err
	}
	command := projections.ManagedKeyCommand{
		OperationID: operationID, Provider: s.provider, Action: strings.TrimPrefix(action, "managedkey:"),
		KeyID: keyID, Algorithm: string(alg), RequestBinding: requestBinding,
	}
	if existing, getErr := s.operation(ctx, tenantID, operationID); getErr == nil {
		if !managedKeyCommandMatches(existing, command, action == ActionGenerate) {
			return Result{}, fmt.Errorf("%w: managed-key command differs", orchestrator.ErrIdempotencyConflict)
		}
		// The durable operation owns replay after the general HTTP recorder has
		// expired. Return/wait before consulting current key or approval state: an
		// exact replay is the original command, not a new authorization decision.
		return s.wait(ctx, tenantID, operationID)
	} else if !errors.Is(getErr, pgx.ErrNoRows) {
		return Result{}, getErr
	}
	if action != ActionGenerate {
		key, err := s.key(ctx, tenantID, s.provider, keyID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Result{}, ErrUnknownKey
			}
			return Result{}, err
		}
		alg = crypto.Algorithm(key.Algorithm)
		if key.Version < 0 {
			return Result{}, store.ErrApprovalDrifted
		}
		command.Algorithm = string(alg)
		command.Requester = requester
		command.FromState = key.State
		command.TargetVersion = uint64(key.Version)
		command.ToState, _ = projections.ManagedKeyCommandTargetState(command.Action)
		command.IdempotencyKeyDigest = projections.ManagedKeyIdempotencyKeyDigest(idempotencyKey)
		evidence, err := projections.ManagedKeyApprovalEvidence(command)
		if err != nil {
			return Result{}, err
		}
		command.ApprovalEvidenceRefs = evidence
		if s.approvals == nil {
			return Result{}, fmt.Errorf("%w: exact one-shot approval authority is unavailable", ErrNotApproved)
		}
		authority, approved, reason := s.approvals.AuthorizeApproval(ctx, api.ApprovalIntent{
			TenantID: tenantID, ResourceKind: "managed_key", ResourceID: keyID,
			ResourceName: keyID, Action: action, Requester: requester,
			FromState: key.State, ToState: command.ToState, TargetVersion: uint64(key.Version),
			Reason: "authorize one exact managed-key " + command.Action + " command", EvidenceRefs: evidence,
		})
		if !approved {
			// Another copy of the same request may have committed while this one
			// was opening/checking the authority. Durable operation state wins over
			// a now-consumed approval on an exact replay.
			if replay, replayErr := s.operation(ctx, tenantID, operationID); replayErr == nil &&
				managedKeyCommandMatches(replay, command, false) {
				return s.wait(ctx, tenantID, operationID)
			}
			if reason == "" {
				reason = "an exact approved operation request is required"
			}
			return Result{}, fmt.Errorf("%w: %s", ErrNotApproved, reason)
		}
		command.Approval = &store.OperationApprovalUse{
			RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
			Requester: authority.Requester, ResourceKind: authority.ResourceKind,
			ResourceID: authority.ResourceID, Action: authority.Action,
			FromState: authority.FromState, ToState: authority.ToState,
			TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
		}
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return Result{}, err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("managed-key-command\x00"+tenantID+"\x00"+operationID)).String()
	schemaVersion := events.DefaultSchemaVersion
	if command.Approval != nil {
		schemaVersion = projections.ManagedKeyApprovalEventSchemaVersion
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		eventTime := time.Now().UTC()
		if command.Approval != nil {
			if _, err := s.store.ValidateManagedKeyApprovalCommandTx(ctx, tx, tenantID,
				*command.Approval, command.KeyID, command.ApprovalEvidenceRefs); err != nil {
				return err
			}
			if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID,
				*command.Approval, eventTime); err != nil {
				return err
			}
			locked, err := s.store.ManagedKeyApprovalTargetTx(ctx, tx, tenantID, command.Provider, command.KeyID, true)
			if err != nil {
				return err
			}
			if locked.Algorithm != command.Algorithm || locked.State != command.FromState ||
				locked.Version < 0 || uint64(locked.Version) != command.TargetVersion {
				return store.ErrApprovalDrifted
			}
		}
		event, err := s.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventManagedKeyCommandRequested,
			TenantID: tenantID, Time: eventTime,
			SchemaVersion: schemaVersion, Data: payload,
		})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventManagedKeyCommandRequested ||
			event.TenantID != tenantID || schemaVersionOfManagedKeyEvent(event) != schemaVersion ||
			!bytes.Equal(event.Data, payload) {
			return fmt.Errorf("%w: canonical managed-key event differs", orchestrator.ErrIdempotencyConflict)
		}
		return projections.New(s.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		if existing, getErr := s.operation(ctx, tenantID, operationID); getErr == nil &&
			managedKeyCommandMatches(existing, command, action == ActionGenerate) {
			return s.wait(ctx, tenantID, operationID)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, fmt.Errorf("%w: managed-key operation already binds a different command", orchestrator.ErrIdempotencyConflict)
		}
		if managedKeyApprovalFailure(err) {
			return Result{}, fmt.Errorf("%w: %v", ErrNotApproved, err)
		}
		return Result{}, err
	}
	return s.wait(ctx, tenantID, operationID)
}

func schemaVersionOfManagedKeyEvent(event events.Event) int {
	if event.SchemaVersion == 0 {
		return events.DefaultSchemaVersion
	}
	return event.SchemaVersion
}

func managedKeyApprovalFailure(err error) bool {
	return errors.Is(err, store.ErrApprovalRequestNotFound) ||
		errors.Is(err, store.ErrApprovalDigestMismatch) ||
		errors.Is(err, store.ErrApprovalSelfDecision) ||
		errors.Is(err, store.ErrApprovalExpired) ||
		errors.Is(err, store.ErrApprovalSuperseded) ||
		errors.Is(err, store.ErrApprovalConsumed) ||
		errors.Is(err, store.ErrApprovalDrifted) ||
		errors.Is(err, store.ErrApprovalNotReady)
}

func managedKeyCommandMatches(existing store.ManagedKeyOperation, requested projections.ManagedKeyCommand, compareAlgorithm bool) bool {
	if !crypto.ConstantTimeEqual([]byte(existing.RequestBinding), []byte(requested.RequestBinding)) {
		return false
	}
	if existing.OperationID != requested.OperationID || existing.Provider != requested.Provider || existing.Action != requested.Action || existing.KeyID != requested.KeyID {
		return false
	}
	return !compareAlgorithm || existing.Algorithm == requested.Algorithm
}

func (s *durableService) wait(ctx context.Context, tenantID, operationID string) (Result, error) {
	waitCtx := ctx
	var cancel context.CancelFunc = func() {}
	if _, ok := ctx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := s.operation(waitCtx, tenantID, operationID)
		if err != nil {
			return Result{}, err
		}
		switch op.Status {
		case "completed":
			key, err := s.key(waitCtx, tenantID, op.Provider, op.ResultKeyID)
			if err != nil {
				return Result{}, err
			}
			return Result{KeyID: key.KeyID, Algorithm: crypto.Algorithm(key.Algorithm), Version: key.Version, State: key.State, PublicDER: key.PublicDER}, nil
		case "failed":
			return Result{}, fmt.Errorf("managedkeys: signer operation failed: %s", op.LastError)
		}
		select {
		case <-waitCtx.Done():
			return Result{}, fmt.Errorf("managedkeys: wait for durable outbox result: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func durableOperationID(tenantID, idempotencyKey string) (string, error) {
	digest, err := crypto.Digest(crypto.SHA256, []byte(tenantID+"\x00"+idempotencyKey))
	if err != nil {
		return "", err
	}
	return "managedkey:" + hex.EncodeToString(digest), nil
}

type durableOutboxHandler struct {
	store         *store.Store
	log           *events.Log
	signer        editionseam.ManagedKeyCustody
	loadOperation func(context.Context, string, string) (store.ManagedKeyOperation, error)
}

func (h *durableOutboxHandler) operation(ctx context.Context, tenantID, operationID string) (store.ManagedKeyOperation, error) {
	if h.loadOperation != nil {
		return h.loadOperation(ctx, tenantID, operationID)
	}
	return h.store.GetManagedKeyOperation(ctx, tenantID, operationID)
}

// DeliverLicensedTerminalFailure makes the user-visible managed-key operation
// terminal before the generic outbox row is dead-lettered. The raw signer/provider
// error is intentionally not persisted because upstream error strings can contain
// credentials; the outbox exposes a sanitized retry-budget status separately.
func (h *durableOutboxHandler) DeliverLicensedTerminalFailure(ctx context.Context, message orchestrator.Message, _ error) (bool, error) {
	if message.Destination != managedKeyCommandDestination {
		return false, nil
	}
	var command projections.ManagedKeyCommand
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return true, fmt.Errorf("managedkeys: decode terminal command: %w", err)
	}
	if command.OperationID == "" || command.OperationID != message.IdempotencyKey || command.RequestBinding == "" {
		return true, errors.New("managedkeys: terminal command identity is invalid")
	}
	if message.EffectLane != store.ManagedKeyEffectLane(command.Provider, command.KeyID, command.OperationID) {
		return true, errors.New("managedkeys: terminal command effect lane is invalid")
	}
	stored, err := h.operation(ctx, message.TenantID, command.OperationID)
	if err != nil {
		return true, fmt.Errorf("managedkeys: load terminal command identity: %w", err)
	}
	if stored.OutboxID != message.ID || !managedKeyCommandMatches(stored, command, true) {
		return true, errors.New("managedkeys: terminal outbox payload does not match its durable operation")
	}
	if stored.Status == "completed" || stored.Status == "failed" {
		return true, nil
	}
	if stored.Status != "queued" {
		return true, fmt.Errorf("managedkeys: terminal command has invalid durable status %q", stored.Status)
	}
	payload, err := managedKeyTerminalFailurePayload(command)
	if err != nil {
		return true, err
	}
	event, err := h.log.Append(ctx, events.Event{
		Type: projections.EventManagedKeyCommandFailed, TenantID: message.TenantID, Data: payload,
	})
	if err != nil {
		return true, err
	}
	return true, projections.New(h.store).Apply(ctx, event)
}

func managedKeyTerminalFailurePayload(command projections.ManagedKeyCommand) ([]byte, error) {
	return json.Marshal(projections.ManagedKeyCommandFailed{
		OperationID:    command.OperationID,
		RequestBinding: command.RequestBinding,
		Error:          "isolated signer operation exhausted its retry budget",
	})
}

func (h *durableOutboxHandler) DeliverLicensed(ctx context.Context, message orchestrator.Message) (bool, error) {
	if message.Destination != managedKeyCommandDestination {
		return false, nil
	}
	var command projections.ManagedKeyCommand
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return true, fmt.Errorf("managedkeys: decode outbox command: %w", err)
	}
	if command.OperationID != message.IdempotencyKey || command.OperationID == "" || command.Provider == "" || command.Action == "" || command.Algorithm == "" || command.RequestBinding == "" {
		return true, errors.New("managedkeys: outbox command identity is invalid")
	}
	if message.EffectLane != store.ManagedKeyEffectLane(command.Provider, command.KeyID, command.OperationID) {
		return true, errors.New("managedkeys: outbox command effect lane is invalid")
	}
	stored, err := h.operation(ctx, message.TenantID, command.OperationID)
	if err != nil {
		return true, fmt.Errorf("managedkeys: load outbox command identity: %w", err)
	}
	if stored.OutboxID != message.ID || !managedKeyCommandMatches(stored, command, true) {
		return true, errors.New("managedkeys: outbox payload does not match its durable operation")
	}
	switch stored.Status {
	case "completed":
		// The completion event committed but the worker crashed before ACK. The
		// projected result is authoritative; acknowledge without another provider
		// call, even if the isolated signer also has its own replay journal.
		return true, nil
	case "failed":
		return true, errors.New("managedkeys: refusing signer call for failed durable operation")
	case "queued":
		// The only state allowed to cross the isolated signer boundary.
	default:
		return true, fmt.Errorf("managedkeys: outbox command has invalid durable status %q", stored.Status)
	}
	if h.signer == nil {
		return true, errors.New("managedkeys: isolated signer managed-key RPC is unavailable")
	}
	result, err := h.signer.ManageKey(ctx, signing.ManagedKeyCommand{
		TenantID: message.TenantID, Provider: command.Provider, OperationID: command.OperationID,
		Action: signing.ManagedKeyAction(command.Action), KeyID: command.KeyID,
		Algorithm: crypto.Algorithm(command.Algorithm),
	})
	if err != nil {
		return true, err
	}
	if result.Provider != command.Provider || result.KeyID == "" || result.Algorithm != crypto.Algorithm(command.Algorithm) || len(result.PublicDER) == 0 {
		return true, errors.New("managedkeys: signer returned a result that does not match the durable command")
	}
	if (command.Action == "revoke" || command.Action == "zeroize") && result.KeyID != command.KeyID {
		return true, errors.New("managedkeys: signer returned a different key for a destructive command")
	}
	payload, err := json.Marshal(projections.ManagedKeyCommandCompleted{
		ManagedKeyCommand: command, ResultKeyID: result.KeyID,
		PublicDER: result.PublicDER, State: result.State,
	})
	if err != nil {
		return true, err
	}
	schemaVersion := events.DefaultSchemaVersion
	if command.Approval != nil {
		schemaVersion = projections.ManagedKeyApprovalEventSchemaVersion
	}
	event, err := h.log.Append(ctx, events.Event{
		Type: projections.EventManagedKeyCommandCompleted, TenantID: message.TenantID,
		SchemaVersion: schemaVersion, Data: payload,
	})
	if err != nil {
		return true, err
	}
	if err := projections.New(h.store).Apply(ctx, event); err != nil {
		return true, err
	}
	return true, nil
}
