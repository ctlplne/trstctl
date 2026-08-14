// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

const (
	ctSubmissionEventQueued                          = "ct.submission.queued"
	ctSubmissionDestination                          = "ct.submit"
	ctSubmissionCapability                           = "CAP-REV-06"
	licensedCryptoMigrationReissueDestination        = "licensed_crypto.migration.reissue"
	licensedCryptoMigrationTLSPostureDestination     = "connector.licensed_crypto.migration.tls_posture"
	licensedCryptoMigrationTLSRollbackDestination    = "connector.licensed_crypto.migration.tls_posture.rollback"
	licensedCryptoMigrationTLSRollbackRequestedEvent = "licensed_crypto.migration.tls_posture.rollback_requested"
)

type licensedCryptoMigrationTLSRollbackIntent struct {
	TargetID       string          `json:"target_id"`
	AssetIDs       []string        `json:"asset_ids"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
}

type licensedCryptoMigrationTLSRollbackRequested struct {
	RunID   string                                     `json:"run_id"`
	Intents []licensedCryptoMigrationTLSRollbackIntent `json:"intents"`
}

// Orchestrator is the command (write) side of the event-sourced spine. It drives
// an identity through its lifecycle state machine and records every served
// domain mutation (owners, issuers, identities, certificates) as an event (AN-2,
// the source of truth). For a lifecycle transition it atomically projects the
// read-model status change and enqueues any outbox side effect (AN-6) in one
// transaction. The read model is written only by the projector, so the state and
// history are reconstructable purely from the event log.
type Orchestrator struct {
	log                  *events.Log
	store                *store.Store
	outbox               *Outbox
	proj                 *projections.Projector
	durableIdem          *Idempotency
	tenantDataRewrite    []events.TenantDataRewriteOption
	profileEditApprovals map[string]approvalProfileEditRequest
	profileEditMu        sync.Mutex
	// effectRole classifies a transition side effect's per-row agent-role demand
	// (epic A3) from its destination and RAW (pre-seal) payload. Injected by the
	// composition root; nil means every row gets the empty demand, which is the
	// pre-A3 behaviour.
	effectRole func(destination string, payload []byte) string
	// ownershipAttestationCadence enables the I1 steady-state authority gate.
	// Zero keeps source-compatible embedded/test orchestrators disabled; the
	// shipped composition always supplies its validated production setting.
	ownershipAttestationCadence time.Duration
}

// OrchestratorOption configures served command-side behavior while keeping the
// long-standing NewOrchestrator call source-compatible.
type OrchestratorOption func(*Orchestrator)

// WithProjector supplies the already-assembled live projector. The server uses
// this to give tenant lifecycle commands the same licensed projection set as
// catch-up/tail, allowing opted-in transactional extensions to join the core
// lifecycle transaction instead of running after its fence is released.
func WithProjector(projector *projections.Projector) OrchestratorOption {
	return func(orchestrator *Orchestrator) {
		if projector != nil {
			orchestrator.proj = projector
		}
	}
}

// WithDurableIdempotency supplies the production result-protected recorder used
// by command families whose durable recovery authority must inspect or rewrite
// the generic idempotency receiver. Each family still owns its narrower lock
// order and receiver protocol.
func WithDurableIdempotency(idempotency *Idempotency) OrchestratorOption {
	return func(orchestrator *Orchestrator) {
		if idempotency != nil {
			orchestrator.durableIdem = idempotency
		}
	}
}

// WithTenantRegistrationIdempotency is the source-compatible name retained for
// embedders compiled against the original tenant-registration-only seam. New
// composition roots should use WithDurableIdempotency because the same protected
// receiver owner also resolves scheduler privacy erasure.
func WithTenantRegistrationIdempotency(idempotency *Idempotency) OrchestratorOption {
	return WithDurableIdempotency(idempotency)
}

// WithSideEffectRoleClassifier wires the function that stamps a transition side
// effect's required agent role onto its outbox row (epic A3). The classifier
// sees the destination and the raw payload BEFORE any sealing transform; for
// connector deploys the composition root consults the shipped vantage census by
// the payload's connector name. The result is durable in the lifecycle event's
// side-effect record, so reconciliation replays the same stamp instead of
// re-deriving it against a possibly-changed census.
func WithSideEffectRoleClassifier(classify func(destination string, payload []byte) string) OrchestratorOption {
	return func(orchestrator *Orchestrator) {
		orchestrator.effectRole = classify
	}
}

func WithOwnershipAttestationCadence(cadence time.Duration) OrchestratorOption {
	return func(orchestrator *Orchestrator) {
		if cadence > 0 {
			orchestrator.ownershipAttestationCadence = cadence
		}
	}
}

// WithTenantDataRewriteOptions wires the mandatory history-generation proof
// walls used by subject erasure. The slice is copied so a caller cannot replace
// production authority callbacks after assembly.
func WithTenantDataRewriteOptions(options ...events.TenantDataRewriteOption) OrchestratorOption {
	copied := append([]events.TenantDataRewriteOption(nil), options...)
	return func(orchestrator *Orchestrator) {
		orchestrator.tenantDataRewrite = copied
	}
}

// NewOrchestrator returns an Orchestrator over the event log, read store, and
// outbox. It builds its own projector so a mutation it records is projected with
// the same logic a rebuild uses.
func NewOrchestrator(log *events.Log, st *store.Store, ob *Outbox, options ...OrchestratorOption) *Orchestrator {
	orch := &Orchestrator{
		log: log, store: st, outbox: ob, proj: projections.New(st),
		durableIdem:          NewIdempotency(st),
		profileEditApprovals: map[string]approvalProfileEditRequest{},
	}
	for _, option := range options {
		if option != nil {
			option(orch)
		}
	}
	return orch
}

// SideEffectPayloadContext is the final outbox boundary for a lifecycle side
// effect: destination and idempotency key have been derived, but the row has not
// been inserted yet. Callers use it to transform sensitive payloads before they
// become durable outbox bytes.
type SideEffectPayloadContext struct {
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
}

// SideEffectPayloadTransform returns the payload bytes to store in outbox.payload.
// The caller context is carried through so tenant-custody transforms can hold the
// same cross-replica fence as the surrounding authenticated mutation.
type SideEffectPayloadTransform func(context.Context, SideEffectPayloadContext) ([]byte, error)

// Transition moves an identity from its current state to "to". It rejects an
// invalid transition with a *TransitionError before any effect. For a valid
// transition it appends the lifecycle event, then in a single tenant-scoped
// transaction updates the identity's status and enqueues any outbox side effect,
// so the external call is recorded with the state change (AN-6).
func (o *Orchestrator) Transition(ctx context.Context, tenantID, identityID string, to State, reason string) error {
	return o.transition(ctx, tenantID, identityID, to, reason, nil, "", "", nil, nil, nil)
}

// TransitionWithIdempotency moves an identity like Transition, but binds any
// outbox side effect to the served request's Idempotency-Key. The generic HTTP
// idempotency cache should normally catch a replay before this method is called;
// carrying the same key into the lifecycle event is the second guard that keeps
// async issue/revoke/deploy work from minting twice if the response cache is not
// the layer that observes the retry (CORRECT-001).
func (o *Orchestrator) TransitionWithIdempotency(ctx context.Context, tenantID, identityID string, to State, reason, idempotencyKey string) error {
	return o.transition(ctx, tenantID, identityID, to, reason, nil, idempotencyKey, "", nil, nil, nil)
}

// TransitionWithSubjectCSR is TransitionWithIdempotency for a requested→issued
// transition whose subject key was generated by the caller (epic B1). The CSR
// travels on the transition payload so the issuance dispatcher signs it instead
// of minting a key of its own — the custody difference between "we made your key"
// and "you made your key and we signed for it".
//
// The CSR is public material and is stored as-is. Callers must have parsed and
// validated it first; this method carries it, it does not vouch for it.
func (o *Orchestrator) TransitionWithSubjectCSR(ctx context.Context, tenantID, identityID string, to State, reason, idempotencyKey, csrPEM string, issuance ...*store.OperationApprovalIssuanceBinding) error {
	if len(issuance) > 1 {
		return errors.New("orchestrator: lifecycle transition has multiple issuance bindings")
	}
	var binding *store.OperationApprovalIssuanceBinding
	if len(issuance) == 1 {
		binding = issuance[0]
	}
	if strings.TrimSpace(csrPEM) == "" {
		return o.transition(ctx, tenantID, identityID, to, reason, nil, idempotencyKey, "", nil, nil, binding)
	}
	return o.transition(ctx, tenantID, identityID, to, reason, nil, idempotencyKey, csrPEM, nil, nil, binding)
}

// TransitionWithSubjectCSRAndApproval is the served dual-control path. The exact
// request/digest authority is embedded in the lifecycle event; its projection
// consumes that authority in the same PostgreSQL transaction as the status and
// external-effect outbox intent.
func (o *Orchestrator) TransitionWithSubjectCSRAndApproval(ctx context.Context, tenantID, identityID string, to State, reason, idempotencyKey, csrPEM string, approval store.OperationApprovalUse) error {
	return o.transition(ctx, tenantID, identityID, to, reason, nil, idempotencyKey, strings.TrimSpace(csrPEM), nil, &approval, nil)
}

// TransitionWithSideEffectPayload moves an identity through the normal lifecycle
// state machine but stores payload as the replayable outbox body for transitions
// that have a side effect. The payload is durable event-log and outbox data; callers
// carrying sensitive bytes must use TransitionWithSideEffectPayloadTransform to seal
// or otherwise transform them before persistence.
func (o *Orchestrator) TransitionWithSideEffectPayload(ctx context.Context, tenantID, identityID string, to State, reason string, payload []byte) error {
	if len(payload) == 0 {
		return o.Transition(ctx, tenantID, identityID, to, reason)
	}
	return o.transition(ctx, tenantID, identityID, to, reason, payload, "", "", nil, nil, nil)
}

// TransitionWithSideEffectPayloadTransform is TransitionWithSideEffectPayload with
// a storage-boundary transform. It is used for sensitive side effects whose
// durable event/outbox body must be sealed with AAD that includes the final outbox
// idempotency key.
func (o *Orchestrator) TransitionWithSideEffectPayloadTransform(ctx context.Context, tenantID, identityID string, to State, reason string, payload []byte, transform SideEffectPayloadTransform) error {
	if len(payload) == 0 {
		return o.Transition(ctx, tenantID, identityID, to, reason)
	}
	return o.transition(ctx, tenantID, identityID, to, reason, payload, "", "", transform, nil, nil)
}

func (o *Orchestrator) transition(ctx context.Context, tenantID, identityID string, to State, reason string, sideEffectPayload []byte, idempotencyKey, subjectCSRPEM string, transform SideEffectPayloadTransform, approval *store.OperationApprovalUse, issuance *store.OperationApprovalIssuanceBinding) error {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	subjectCSRPEM = strings.TrimSpace(subjectCSRPEM)
	if approval != nil && issuance != nil {
		return errors.New("orchestrator: lifecycle issuance binding must have one authority source")
	}
	if issuance != nil {
		if _, err := issuance.EvidenceRefs(); err != nil {
			return fmt.Errorf("orchestrator: invalid lifecycle issuance binding: %w", err)
		}
	}
	ident, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("orchestrator: load identity %s: %w", identityID, err)
	}
	from := State(ident.Status)
	if approval != nil && from == to {
		// DoDurableEffectBound may retry after the target transaction committed but
		// before its HTTP result was cached. The consumed request is not enough by
		// itself: load the one deterministic event and prove its envelope, edge,
		// command body, side effect, and current projected version before returning
		// the original success.
		eventID := approvalExecutionEventID(tenantID, *approval)
		retained, found, loadErr := lifecycleApprovalEventByID(ctx, o.log, eventID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return fmt.Errorf("%w: consumed lifecycle approval has no retained target event", store.ErrIdempotencyConflict)
		}
		return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			current, version, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, true)
			if err != nil {
				return err
			}
			request, err := o.store.GetOperationApprovalForUpdateTx(ctx, tx, tenantID, approval.RequestID)
			if err != nil {
				return err
			}
			if request.Status != store.ApprovalStatusConsumed || request.ConsumedEventID != eventID ||
				State(current.Status) != to || version != retained.Sequence || request.Reason != reason {
				return store.ErrApprovalDrifted
			}
			if err := projections.ValidateLifecycleApprovalAttemptEvidence(request.EvidenceRefs, idempotencyKey, subjectCSRPEM); err != nil {
				return err
			}
			if err := validateRetainedLifecycleApprovalEvent(retained, tenantID, identityID, to,
				reason, idempotencyKey, subjectCSRPEM, *approval); err != nil {
				return err
			}
			return o.store.ConsumeOperationApprovalTx(ctx, tx, tenantID, *approval, eventID, retained.Time)
		})
	}

	evType, ok := EventTypeFor(from, to)
	if !ok {
		return &TransitionError{IdentityID: identityID, From: from, To: to}
	}
	if issuance != nil && (from != StateRequested || to != StateIssued) {
		return errors.New("orchestrator: issuance binding is only valid for requested -> issued")
	}
	commandTime := time.Now().UTC()
	var ownershipReadiness *store.OwnershipReadinessEvidence
	if o.ownershipAttestationCadence > 0 && to == StateDeployed {
		if approval != nil || issuance != nil {
			return errors.New("orchestrator: ownership-readiness deployment cannot carry issuance authority")
		}
		var evidence store.OwnershipReadinessEvidence
		if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var resolveErr error
			evidence, resolveErr = o.store.ResolveOwnershipReadinessTx(ctx, tx, tenantID, identityID,
				commandTime, o.ownershipAttestationCadence)
			return resolveErr
		}); err != nil {
			return err
		}
		ownershipReadiness = &evidence
	}

	sideEffectDest, hasSideEffect := sideEffectFor(from, to)
	schemaVersion := 0
	if idempotencyKey != "" {
		schemaVersion = projections.LifecycleEventSchemaVersion
	}
	eventID := ""
	sideEffectKey := ""
	if hasSideEffect {
		eventID = events.NewID()
		sideEffectKey = transitionOutboxIdempotencyKey(eventID, idempotencyKey)
		schemaVersion = projections.LifecycleSideEffectEventSchemaVersion
	}
	basePayload := transitionPayload{IdentityID: identityID, From: from, To: to, Reason: reason, IdempotencyKey: idempotencyKey, SubjectCSRPEM: subjectCSRPEM, Approval: approval, Issuance: issuance, OwnershipReadiness: ownershipReadiness}
	if approval != nil {
		schemaVersion = projections.LifecycleApprovalEventSchemaVersion
		eventID = approvalExecutionEventID(tenantID, *approval)
		if hasSideEffect {
			sideEffectKey = transitionOutboxIdempotencyKey(eventID, idempotencyKey)
		}
	}
	if issuance != nil {
		schemaVersion = projections.LifecycleIssuanceEventSchemaVersion
	}
	if ownershipReadiness != nil {
		schemaVersion = projections.LifecycleOwnershipReadinessEventSchemaVersion
	}
	// Classify the claim demand from the RAW side-effect payload, before any
	// sealing transform makes it opaque (epic A3). The classifier is injected by
	// the composition root because vantage is the connector registry's census,
	// and the orchestrator must not import the registry.
	requiredAgentRole := ""
	if hasSideEffect && o.effectRole != nil {
		requiredAgentRole = o.effectRole(sideEffectDest, sideEffectPayload)
	}
	payload, err := json.Marshal(basePayload)
	if err != nil {
		return err
	}
	outboxPayload := payload
	if len(sideEffectPayload) > 0 {
		outboxPayload = sideEffectPayload
	}
	if hasSideEffect && len(sideEffectPayload) > 0 && transform != nil {
		outboxPayload, err = transform(ctx, SideEffectPayloadContext{
			TenantID:       tenantID,
			Destination:    sideEffectDest,
			IdempotencyKey: sideEffectKey,
			Payload:        outboxPayload,
		})
		if err != nil {
			return err
		}
	}
	if hasSideEffect {
		replayPayload := append([]byte(nil), outboxPayload...)
		if approval != nil || issuance != nil || (ownershipReadiness != nil && len(sideEffectPayload) == 0) {
			// V4 approval, v5 issuance, and v6 ownership-readiness events have one command body, not an
			// opaque base64 copy inside themselves. An ownership-ready transition
			// with an EXPLICIT side-effect body is different: its transformed body
			// may be a tenant-sealed credential that cannot be reconstructed from
			// the outer ownership metadata, so v6 retains that exact replay body.
			// Warm enqueue and boot reconciliation derive only the ordinary body by
			// removing this SideEffect object from the canonical event.
			replayPayload = nil
		}
		basePayload.SideEffect = &transitionSideEffect{
			Destination:       sideEffectDest,
			IdempotencyKey:    sideEffectKey,
			Payload:           replayPayload,
			RequiredAgentRole: requiredAgentRole,
		}
		payload, err = json.Marshal(basePayload)
		if err != nil {
			return err
		}
	}

	var terminalApprovalErr error
	apply := func(ctx context.Context) error {
		return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			eventTime := commandTime
			locked, version, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, true)
			if err != nil {
				return err
			}
			if State(locked.Status) != from {
				if approval != nil {
					return store.ErrApprovalDrifted
				}
				return &TransitionError{IdentityID: identityID, From: State(locked.Status), To: to}
			}
			if approval != nil {
				if approval.ResourceKind != "identity" || approval.ResourceID != identityID ||
					approval.FromState != string(from) || approval.ToState != string(to) ||
					approval.TargetVersion != version {
					return store.ErrApprovalDrifted
				}
				authority, err := o.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, *approval, eventTime)
				if err != nil {
					return err
				}
				if authority.Reason != reason {
					return store.ErrApprovalDrifted
				}
				if approval.EvidenceRefs == nil || approval.Reason != authority.Reason ||
					!sameApprovalEvidence(approval.EvidenceRefs, authority.EvidenceRefs) {
					return store.ErrApprovalDrifted
				}
				if err := projections.ValidateLifecycleApprovalAttemptEvidence(authority.EvidenceRefs, idempotencyKey, subjectCSRPEM); err != nil {
					return err
				}
				if approval.Issuance != nil {
					if to != StateIssued || approval.Action != "issue" {
						return store.ErrApprovalDrifted
					}
					if approval.Issuance.ProfileID != "" {
						if err := o.store.ValidateActiveProfileApprovalBindingTx(ctx, tx, tenantID, *approval.Issuance); err != nil {
							if errors.Is(err, store.ErrApprovalDrifted) {
								if statusErr := o.changeOperationApprovalStatusTx(ctx, tx, tenantID, authority,
									store.ApprovalStatusSuperseded, "", eventTime); statusErr != nil {
									return statusErr
								}
								terminalApprovalErr = store.ErrApprovalDrifted
								return nil
							}
							return err
						}
					}
				}
			}
			if issuance != nil && issuance.ProfileID != "" {
				if err := o.store.ValidateActiveProfileApprovalBindingTx(ctx, tx, tenantID, *issuance); err != nil {
					return err
				}
			}
			if ownershipReadiness != nil {
				// The first resolution supplied the immutable event bytes. Repeat it
				// under the final identity/owner locks before append: if an owner edit
				// won the gap, refuse without publishing a permanently unprojectable
				// event. The projector validates once more in this same transaction.
				if err := o.store.ValidateOwnershipReadinessEvidenceTx(ctx, tx, tenantID,
					*ownershipReadiness, o.ownershipAttestationCadence); err != nil {
					return err
				}
			}
			ev, err := o.log.Append(ctx, events.Event{ID: eventID, Type: evType, TenantID: tenantID, Time: eventTime, SchemaVersion: schemaVersion, Data: payload})
			if err != nil {
				return err
			}
			expectedSchemaVersion := schemaVersion
			if expectedSchemaVersion == 0 {
				expectedSchemaVersion = events.DefaultSchemaVersion
			}
			if (eventID != "" && ev.ID != eventID) || ev.Type != evType || ev.TenantID != tenantID ||
				ev.SchemaVersion != expectedSchemaVersion || !bytes.Equal(ev.Data, payload) {
				return fmt.Errorf("%w: canonical lifecycle event differs", store.ErrIdempotencyConflict)
			}
			var canonical transitionPayload
			if err := json.Unmarshal(ev.Data, &canonical); err != nil {
				return fmt.Errorf("orchestrator: decode canonical lifecycle event: %w", err)
			}
			// Project the status change through the projector (the sole read-model
			// writer, AN-2) in the same transaction as the outbox enqueue (AN-6).
			if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
				return err
			}
			if hasSideEffect {
				canonicalKey, canonicalPayload, err := lifecycleOutboxIntentFromEvent(ev, canonical, sideEffectDest)
				if err != nil {
					return err
				}
				// Enqueue the side effect idempotently (SPINE-011): legacy/internal
				// transitions key by event ID, while served lifecycle requests key by
				// their Idempotency-Key so a replay cannot enqueue a second async effect.
				// If a prior attempt already enqueued the effect, EnqueueIfAbsent is a
				// no-op, so the inline path and boot reconciliation cannot both enqueue it.
				if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
					TenantID:          tenantID,
					Destination:       sideEffectDest,
					IdempotencyKey:    canonicalKey,
					Payload:           canonicalPayload,
					EffectLane:        lifecycleEffectLane(sideEffectDest, identityID, canonicalPayload),
					RequiredAgentRole: canonical.SideEffect.RequiredAgentRole,
				}); err != nil {
					return err
				}
			}
			return nil
		})
	}
	profileBound := approval != nil && approval.Issuance != nil && approval.Issuance.ProfileID != ""
	profileBound = profileBound || issuance != nil && issuance.ProfileID != ""
	if profileBound || ownershipReadiness != nil {
		// Profile writes already use this cross-replica lock. Taking it around
		// validation+append makes event order agree with the active profile or
		// ownership revision we observed. Either the authority update wins and this
		// command drifts, or this lifecycle event commits before the later update.
		err := o.store.WithProjectionLock(ctx, apply)
		if err == nil && terminalApprovalErr != nil {
			return terminalApprovalErr
		}
		return err
	}
	err = apply(ctx)
	if err == nil && terminalApprovalErr != nil {
		return terminalApprovalErr
	}
	return err
}

func sameApprovalEvidence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func approvalExecutionEventID(tenantID string, approval store.OperationApprovalUse) string {
	return projections.LifecycleApprovalEventID(tenantID, approval)
}

func lifecycleApprovalEventByID(ctx context.Context, log *events.Log, eventID string) (events.Event, bool, error) {
	if log == nil || eventID == "" {
		return events.Event{}, false, errors.New("orchestrator: lifecycle approval event lookup is incomplete")
	}
	stop := errors.New("orchestrator: lifecycle approval event found")
	var found events.Event
	err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.ID != eventID {
			return nil
		}
		found = event
		return stop
	})
	if errors.Is(err, stop) {
		return found, true, nil
	}
	return events.Event{}, false, err
}

func validateRetainedLifecycleApprovalEvent(
	event events.Event,
	tenantID, identityID string,
	to State,
	reason, idempotencyKey, subjectCSRPEM string,
	approval store.OperationApprovalUse,
) error {
	expectedType, ok := EventTypeFor(State(approval.FromState), State(approval.ToState))
	if !ok || State(approval.ToState) != to || event.ID != approvalExecutionEventID(tenantID, approval) ||
		event.Type != expectedType || event.TenantID != tenantID ||
		event.SchemaVersion != projections.LifecycleApprovalEventSchemaVersion || event.Sequence == 0 {
		return store.ErrApprovalDrifted
	}
	if err := projections.ValidateLifecycleApprovalEvent(event); err != nil {
		return err
	}
	var payload transitionPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return fmt.Errorf("orchestrator: decode retained lifecycle approval event: %w", err)
	}
	if payload.IdentityID != identityID || payload.From != State(approval.FromState) || payload.To != to ||
		payload.Reason != reason || payload.IdempotencyKey != strings.TrimSpace(idempotencyKey) ||
		payload.SubjectCSRPEM != strings.TrimSpace(subjectCSRPEM) || payload.Approval == nil {
		return store.ErrApprovalDrifted
	}
	wantApproval, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	gotApproval, err := json.Marshal(payload.Approval)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotApproval, wantApproval) {
		return store.ErrApprovalDrifted
	}
	return nil
}

func transitionOutboxIdempotencyKey(eventID, requestKey string) string {
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" {
		return eventID
	}
	return "transition:" + requestKey
}

// rewriteLifecycleOutboxFromCanonicalHistory keeps executable lifecycle commands
// and approval notifications in the same privacy generation as their source
// events. It first validates and collects the complete tenant history, then
// changes PostgreSQL, so malformed or colliding history cannot produce a partial
// rewrite. The historical name is retained because lifecycle commands were the
// first consumer of this privacy fence.
func (o *Orchestrator) rewriteLifecycleOutboxFromCanonicalHistory(ctx context.Context, tenantID string) error {
	if o.outbox == nil {
		return errors.New("orchestrator: lifecycle outbox rewrite is not configured")
	}
	entries := make(map[string]Entry)
	addEntry := func(key string, candidate Entry) error {
		if prior, exists := entries[key]; exists {
			if prior.Destination != candidate.Destination ||
				effectiveOutboxLane(prior.Destination, prior.EffectLane) != effectiveOutboxLane(candidate.Destination, candidate.EffectLane) ||
				prior.RequiredAgentRole != candidate.RequiredAgentRole || prior.RequiredAgentID != candidate.RequiredAgentID ||
				!bytes.Equal(prior.Payload, candidate.Payload) {
				return fmt.Errorf("%w: rewritten history reuses receiver key %q", store.ErrIdempotencyConflict, key)
			}
			return nil
		}
		entries[key] = candidate
		return nil
	}
	err := o.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		if ev.Type == projections.EventApprovalRequested {
			request, err := operationApprovalRequestFromEvent(ev)
			if err != nil {
				return err
			}
			entry, err := approvalRequestOutboxEntry(tenantID, request)
			if err != nil {
				return err
			}
			return addEntry(entry.IdempotencyKey, entry)
		}
		if !isLifecycleTransition(ev.Type) {
			return nil
		}
		if err := projections.ValidateSchemaVersion(ev); err != nil {
			return err
		}
		if err := projections.ValidateLifecycleApprovalEvent(ev); err != nil {
			return err
		}
		var payload transitionPayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("orchestrator: privacy decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
		}
		destination, ok := sideEffectFor(payload.From, payload.To)
		if !ok {
			return nil
		}
		key, command, err := lifecycleOutboxIntentFromEvent(ev, payload, destination)
		if err != nil {
			return err
		}
		requiredAgentRole := ""
		if payload.SideEffect != nil {
			requiredAgentRole = payload.SideEffect.RequiredAgentRole
		}
		candidate := Entry{
			TenantID: tenantID, Destination: destination, IdempotencyKey: key,
			Payload: command, EffectLane: lifecycleEffectLane(destination, payload.IdentityID, command),
			RequiredAgentRole: requiredAgentRole,
		}
		return addEntry(key, candidate)
	})
	if err != nil {
		return fmt.Errorf("orchestrator: collect canonical lifecycle outbox: %w", err)
	}

	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, key := range keys {
			if _, err := o.outbox.rewriteCanonicalIfPresent(ctx, tx, entries[key]); err != nil {
				return fmt.Errorf("rewrite lifecycle outbox %q: %w", key, err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("orchestrator: rewrite lifecycle outbox transaction: %w", err)
	}
	return nil
}

// ReconcileOutbox heals the narrow crash window between an event append and the
// transaction that projects it and enqueues its side effect (SPINE-011). Transition
// appends the lifecycle event first (durable, the source of truth — AN-2), then in a
// SEPARATE transaction projects the status change and enqueues the outbox effect
// (AN-6). If the process dies in that gap, the event survives but the effect was
// never enqueued — a transition recorded but never acted on.
//
// This pass makes the side effect log-derivable: it resumes from the persisted
// reconciliation checkpoint and, for each lifecycle transition that carries a
// side effect, enqueues that effect idempotently. Legacy v1 events key by event
// ID, v2 served events key by the request Idempotency-Key, and v3 events carry
// the exact replayable side-effect payload plus the event-derived outbox key
// (EnqueueIfAbsent). An effect that already landed (the common case) is left
// untouched; one lost to a crash is re-created exactly once. After each event's
// effect has been checked, the checkpoint advances so later boots scan only the
// unreconciled tail. It is meant to run on boot (after the projection catch-up)
// and is safe to run repeatedly. It returns how many missing effects it healed.
//
// It does not re-drive the projection itself — that is the projector's job (the boot
// catch-up and the tailing worker), and a re-driven transition is in any case
// rejected by the state machine. This pass is strictly about the AN-6 side-effect
// durability edge.
func (o *Orchestrator) ReconcileOutbox(ctx context.Context, log *events.Log) (int, error) {
	healed := 0
	from, err := o.store.OutboxReconciliationCheckpoint(ctx)
	if err != nil {
		return 0, err
	}
	err = log.Replay(ctx, from+1, func(ev events.Event) (reconcileErr error) {
		healedBefore := healed
		defer func() {
			if reconcileErr == nil {
				return
			}
			var conflict *OutboxCommandConflictError
			if !errors.As(reconcileErr, &conflict) {
				return
			}
			// Any inserts attempted for a multi-command event shared the failed
			// tenant transaction and rolled back. Keep the return count honest and
			// quarantine the whole immutable event instead of partly executing it.
			healed = healedBefore
			reconcileErr = o.quarantineOutboxReconciliationConflict(ctx, log, ev, conflict)
		}()
		if ev.Type == projections.EventAuditFeedBatchQueued {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var queued projections.AuditFeedBatchQueued
			if err := json.Unmarshal(ev.Data, &queued); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if queued.StartSequence == 0 || queued.EndSequence < queued.StartSequence ||
				queued.RecordCount < 1 || len(queued.RecordIDs) != queued.RecordCount ||
				queued.ChainHead == "" {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): queued range authority is incomplete", ev.Type, ev.Sequence)
			}
			auditService := audit.NewService(log, nil,
				audit.WithCheckpoints(o.store), audit.WithPrivacyErasures(o.store))
			records, seed, err := auditService.SearchWithSeed(ctx, audit.Query{
				TenantID: ev.TenantID, AfterSequence: queued.StartSequence - 1,
				AsOfSequence: queued.EndSequence, ExcludeTypePrefixes: []string{"audit.feed."},
				Limit: queued.RecordCount,
			})
			if err != nil {
				return fmt.Errorf("orchestrator: reconstruct %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if seed != queued.PrevHash || len(records) != queued.RecordCount ||
				records[0].Sequence != queued.StartSequence ||
				records[len(records)-1].Sequence != queued.EndSequence ||
				records[len(records)-1].Hash != queued.ChainHead {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): reconstructed range changed", ev.Type, ev.Sequence)
			}
			entry, err := auditFeedOutboxEntry(ev.TenantID, queued, records)
			if err != nil {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
				if inserted {
					healed++
				}
				return err
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventEnrollmentDiagnosticVerificationQueued {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var queued projections.EnrollmentDiagnosticVerificationQueued
			if err := json.Unmarshal(ev.Data, &queued); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			entry, err := enrollmentDiagnosticVerificationOutboxEntry(ev.TenantID, ev.ID, queued)
			if err != nil {
				return err
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
				if inserted {
					healed++
				}
				return err
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventCMDBSweepDispatched || ev.Type == projections.EventCMDBSweepPageObserved {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var intent *ownership.CMDBSyncIntent
			switch ev.Type {
			case projections.EventCMDBSweepDispatched:
				var dispatched projections.CMDBSweepDispatched
				if err := json.Unmarshal(ev.Data, &dispatched); err != nil {
					return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				intent = &dispatched.Intent
			case projections.EventCMDBSweepPageObserved:
				var page projections.CMDBSweepPageObserved
				if err := json.Unmarshal(ev.Data, &page); err != nil {
					return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				intent = page.NextIntent
			}
			if intent != nil {
				entry, err := cmdbSweepOutboxEntry(ev.TenantID, *intent)
				if err != nil {
					return fmt.Errorf("orchestrator: reconcile %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
					if inserted {
						healed++
					}
					return err
				}); err != nil {
					return err
				}
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventTicketIntakeSweepDispatched || ev.Type == projections.EventTicketIntakeSweepPageObserved {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var intent *ticketintake.SyncIntent
			switch ev.Type {
			case projections.EventTicketIntakeSweepDispatched:
				var dispatched projections.TicketIntakeSweepDispatched
				if err := json.Unmarshal(ev.Data, &dispatched); err != nil {
					return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				intent = &dispatched.Intent
			case projections.EventTicketIntakeSweepPageObserved:
				var page projections.TicketIntakeSweepPageObserved
				if err := json.Unmarshal(ev.Data, &page); err != nil {
					return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				intent = page.NextIntent
			}
			if intent != nil {
				entry, err := ticketIntakeOutboxEntry(ev.TenantID, *intent)
				if err != nil {
					return fmt.Errorf("orchestrator: reconcile %s (seq %d): %w", ev.Type, ev.Sequence, err)
				}
				if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
					if inserted {
						healed++
					}
					return err
				}); err != nil {
					return err
				}
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventOwnerReattestationRequested {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var request projections.OwnerReattestationRequested
			if err := json.Unmarshal(ev.Data, &request); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			entry, err := ownershipReattestationOutboxEntry(ev.TenantID, ev.ID, request)
			if err != nil {
				return err
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
				if inserted {
					healed++
				}
				return err
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		// Approval requests notify reviewers. The ordinary command path projects the
		// request and records this intent in one PostgreSQL transaction; this branch
		// heals the earlier append-ACK / transaction-rollback gap from the immutable
		// request event. Migration 0151 rewinds the checkpoint once so events skipped
		// by pre-fix binaries are covered after upgrade too.
		if ev.Type == projections.EventApprovalRequested {
			request, err := operationApprovalRequestFromEvent(ev)
			if err != nil {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			entry, err := approvalRequestOutboxEntry(ev.TenantID, request)
			if err != nil {
				return err
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
				if inserted {
					healed++
				}
				return err
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		// Lifecycle transitions and queued discovery runs carry outbox side effects;
		// skip everything else (domain CRUD events, tenant events, certificate events).
		if ev.Type == EventITSMTicketRequested {
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
					TenantID:       ev.TenantID,
					Destination:    DestinationITSMServiceNow,
					IdempotencyKey: ev.ID,
					Payload:        ev.Data,
				})
				if err != nil {
					return err
				}
				if inserted {
					healed++
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventDiscoveryRunQueued {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var pl projections.DiscoveryRunQueued
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			destination := discoveryRunDestination
			switch pl.JobKind {
			case "":
				// Historical network/SSH/control-plane events predate the explicit
				// job-kind discriminator and always used discovery.run.
			case adcsdiscovery.JobKind:
				destination = adcsdiscovery.JobKind
			default:
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): unsupported job_kind %q", ev.Type, ev.Sequence, pl.JobKind)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
					TenantID:          ev.TenantID,
					Destination:       destination,
					IdempotencyKey:    ev.ID,
					Payload:           ev.Data,
					RequiredAgentRole: pl.RequiredAgentRole,
					RequiredAgentID:   pl.RequiredAgentID,
				})
				if err != nil {
					return err
				}
				if inserted {
					healed++
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventRevocationProbeQueued {
			inserted, err := o.reconcileRevocationProbe(ctx, ev)
			if err != nil {
				return err
			}
			if inserted {
				healed++
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventRevocationHealthObserved {
			inserted, err := o.reconcileRevocationAlerts(ctx, ev)
			if err != nil {
				return err
			}
			healed += inserted
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventMigrationRunRecorded {
			inserted, err := o.reconcileMigrationRun(ctx, ev)
			if err != nil {
				return err
			}
			healed += inserted
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventIncidentFleetReissuanceRecorded {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var pl projections.IncidentFleetReissuanceRecorded
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			// Paused, halted, rolled-back, and completed snapshots deliberately
			// publish nothing. A running snapshot names its one durable cursor.
			if pl.Status == "running" && pl.NextBatchIndex > 0 && pl.NextBatchIndex <= len(pl.Batches) {
				body, err := json.Marshal(FleetReissuanceBatchCommand{RunID: pl.ID, BatchIndex: pl.NextBatchIndex})
				if err != nil {
					return err
				}
				if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID: ev.TenantID, Destination: DestinationFleetReissuanceBatch,
						IdempotencyKey: FleetReissuanceBatchIdempotencyKey(pl.ID, pl.NextBatchIndex),
						EffectLane:     DestinationFleetReissuanceBatch + ":" + pl.ID,
						Payload:        body, RequiredAgentRole: "control_plane",
					})
					if inserted {
						healed++
					}
					return err
				}); err != nil {
					return err
				}
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventRemediationPlaybookRunRecorded {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var pl projections.RemediationPlaybookRunRecorded
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if pl.Action != "right_size" {
				return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
			}
			outboxKey := pl.OutboxIdempotencyKey
			if outboxKey == "" {
				outboxKey = ev.ID
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
					TenantID:       ev.TenantID,
					Destination:    DestinationConnectorRightSize,
					IdempotencyKey: outboxKey,
					EffectLane:     DestinationConnectorRightSize + ":" + pl.Connector + ":" + pl.Target,
					Payload:        ev.Data,
				})
				if err != nil {
					return err
				}
				if inserted {
					healed++
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventResponseIntegrationDispatched {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var pl ResponseIntegrationDispatch
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				for _, dst := range pl.Destinations {
					outboxDestination, body, err := responseIntegrationOutboxPayload(ev.TenantID, pl, dst)
					if err != nil {
						return err
					}
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID:       ev.TenantID,
						Destination:    outboxDestination,
						IdempotencyKey: ev.ID + ":" + dst.ID,
						Payload:        body,
					})
					if err != nil {
						return err
					}
					if inserted {
						healed++
					}
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == ctSubmissionEventQueued {
			var pl ctSubmissionQueuedEvent
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if pl.Capability != "" && pl.Capability != ctSubmissionCapability {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): invalid capability %q", ev.Type, ev.Sequence, pl.Capability)
			}
			if len(pl.Payloads) == 0 {
				// Legacy ct.submission.queued events were audit-only and the old served
				// path enqueued before appending them. They cannot heal a crash, but
				// they also should not block boot reconciliation for upgraded nodes.
				return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				for _, raw := range pl.Payloads {
					var p ctSubmissionPayloadEnvelope
					if err := json.Unmarshal(raw, &p); err != nil {
						return fmt.Errorf("orchestrator: reconcile decode CT payload (seq %d): %w", ev.Sequence, err)
					}
					key, err := ctSubmissionOutboxKey(p)
					if err != nil {
						return err
					}
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID:       ev.TenantID,
						Destination:    ctSubmissionDestination,
						IdempotencyKey: key,
						Payload:        raw,
					})
					if err != nil {
						return err
					}
					if inserted {
						healed++
					}
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == licensedCryptoMigrationTLSRollbackRequestedEvent {
			var requested licensedCryptoMigrationTLSRollbackRequested
			if err := json.Unmarshal(ev.Data, &requested); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if requested.RunID == "" || len(requested.Intents) == 0 {
				return fmt.Errorf("orchestrator: reconcile %s (seq %d): run_id and intents are required", ev.Type, ev.Sequence)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				for _, intent := range requested.Intents {
					if intent.TargetID == "" || len(intent.AssetIDs) == 0 || intent.IdempotencyKey == "" || len(intent.Payload) == 0 {
						return fmt.Errorf("orchestrator: reconcile %s (seq %d): complete sealed rollback intent is required", ev.Type, ev.Sequence)
					}
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID: ev.TenantID, Destination: licensedCryptoMigrationTLSRollbackDestination,
						IdempotencyKey: intent.IdempotencyKey, Payload: append([]byte(nil), intent.Payload...),
					})
					if err != nil {
						return err
					}
					if inserted {
						healed++
					}
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if ev.Type == projections.EventLicensedCryptoMigrationStarted {
			if err := projections.ValidateSchemaVersion(ev); err != nil {
				return err
			}
			var pl projections.LicensedCryptoMigrationStarted
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
			}
			if len(pl.Reissues) == 0 && len(pl.TLSPostures) == 0 {
				// Older start events carried only an audit summary; their inline
				// outbox rows were already the only delivery source.
				return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
			}
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				for _, reissue := range pl.Reissues {
					if reissue.RunID == "" || reissue.AssetID == "" {
						return fmt.Errorf("orchestrator: reconcile %s (seq %d): reissue requires run_id and asset_id", ev.Type, ev.Sequence)
					}
					body, err := json.Marshal(reissue)
					if err != nil {
						return err
					}
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID:       ev.TenantID,
						Destination:    licensedCryptoMigrationReissueDestination,
						IdempotencyKey: "licensed-crypto-migration:" + reissue.RunID + ":" + reissue.AssetID,
						Payload:        body,
					})
					if err != nil {
						return err
					}
					if inserted {
						healed++
					}
				}
				for _, posture := range pl.TLSPostures {
					if posture.RunID == "" || posture.AssetID == "" || posture.TargetID == "" || posture.TargetRevision == "" || posture.Connector == "" {
						return fmt.Errorf("orchestrator: reconcile %s (seq %d): TLS posture requires run_id, asset_id, target_id, revision, and connector", ev.Type, ev.Sequence)
					}
					body := []byte(posture.SealedOutboxPayload)
					if len(body) == 0 {
						return fmt.Errorf("orchestrator: reconcile %s (seq %d): TLS posture is missing sealed outbox payload", ev.Type, ev.Sequence)
					}
					inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
						TenantID: ev.TenantID, Destination: licensedCryptoMigrationTLSPostureDestination,
						IdempotencyKey: "licensed-crypto-migration-tls:" + posture.RunID + ":" + posture.AssetID,
						Payload:        body,
					})
					if err != nil {
						return err
					}
					if inserted {
						healed++
					}
				}
				return nil
			}); err != nil {
				return err
			}
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if !isLifecycleTransition(ev.Type) {
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		if err := projections.ValidateSchemaVersion(ev); err != nil {
			return err
		}
		if err := projections.ValidateLifecycleApprovalEvent(ev); err != nil {
			return err
		}
		var pl transitionPayload
		if err := json.Unmarshal(ev.Data, &pl); err != nil {
			// A malformed transition payload is a producer bug; surface it rather than
			// silently skipping (the same stance the projector takes).
			return fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
		}
		dest, ok := sideEffectFor(pl.From, pl.To)
		if !ok {
			// A transition with no external effect is still reconciled: after this
			// point the boot pass never needs to inspect it again.
			return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
		}
		idempotencyKey, outboxPayload, err := lifecycleOutboxIntentFromEvent(ev, pl, dest)
		if err != nil {
			return err
		}
		if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			// The claim demand is COPIED from the durable side-effect record,
			// never re-derived: a census change between enqueue and replay must
			// not silently relocate work that was already committed (epic A3).
			requiredAgentRole := ""
			if pl.SideEffect != nil {
				requiredAgentRole = pl.SideEffect.RequiredAgentRole
			}
			inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:          ev.TenantID,
				Destination:       dest,
				IdempotencyKey:    idempotencyKey,
				Payload:           outboxPayload,
				EffectLane:        lifecycleEffectLane(dest, pl.IdentityID, outboxPayload),
				RequiredAgentRole: requiredAgentRole,
			})
			if err != nil {
				return err
			}
			if inserted {
				healed++
			}
			return nil
		}); err != nil {
			return err
		}
		return o.store.AdvanceOutboxReconciliationCheckpoint(ctx, ev.Sequence)
	})
	if err != nil {
		return healed, fmt.Errorf("orchestrator: reconcile outbox: %w", err)
	}
	return healed, nil
}

func (o *Orchestrator) quarantineOutboxReconciliationConflict(ctx context.Context, log *events.Log, source events.Event, conflict *OutboxCommandConflictError) error {
	if conflict == nil || conflict.TenantID != source.TenantID {
		return fmt.Errorf("orchestrator: quarantine outbox conflict: tenant identity mismatch")
	}
	payload, err := json.Marshal(projections.OutboxReconciliationConflictRecorded{
		SourceEventID: source.ID, SourceEventSequence: source.Sequence, SourceEventType: source.Type,
		IdempotencyKey:             conflict.IdempotencyKey,
		ExistingOutboxID:           conflict.ExistingOutboxID,
		ExistingDestination:        conflict.ExistingDestination,
		ExistingEffectLane:         conflict.ExistingEffectLane,
		ExistingPayloadSHA256:      conflict.ExistingPayloadSHA256,
		ExistingRequiredAgentRole:  conflict.ExistingRequiredAgentRole,
		ExistingRequiredAgentID:    conflict.ExistingRequiredAgentID,
		CandidateDestination:       conflict.CandidateDestination,
		CandidateEffectLane:        conflict.CandidateEffectLane,
		CandidatePayloadSHA256:     conflict.CandidatePayloadSHA256,
		CandidateRequiredAgentRole: conflict.CandidateRequiredAgentRole,
		CandidateRequiredAgentID:   conflict.CandidateRequiredAgentID,
		Reason:                     "receiver idempotency key is already bound to a different immutable command",
		Status:                     "quarantined",
	})
	if err != nil {
		return fmt.Errorf("orchestrator: encode outbox reconciliation conflict: %w", err)
	}
	recorded, err := log.Append(ctx, events.Event{
		ID:       "outbox-reconciliation-conflict:" + source.ID,
		Type:     projections.EventOutboxReconciliationConflictRecorded,
		TenantID: source.TenantID, Time: source.Time, Data: payload,
	})
	if err != nil {
		return fmt.Errorf("orchestrator: append outbox reconciliation conflict: %w", err)
	}
	if err := o.store.WithTenant(ctx, source.TenantID, func(tx pgx.Tx) error {
		return o.proj.ApplyTx(ctx, tx, recorded)
	}); err != nil {
		return fmt.Errorf("orchestrator: project outbox reconciliation conflict: %w", err)
	}
	if err := o.store.AdvanceOutboxReconciliationCheckpoint(ctx, source.Sequence); err != nil {
		return fmt.Errorf("orchestrator: advance quarantined outbox reconciliation checkpoint: %w", err)
	}
	return nil
}

func lifecycleEffectLane(destination, identityID string, payload []byte) string {
	if destination == "connector.deploy" && identityID != "" {
		return ConnectorDeployEffectLane(identityID, payload)
	}
	return destination
}

// ConnectorDeployEffectLane derives the mutex name for a deploy. Modern target
// payloads expose target_id outside the credential seal, so deploy and rollback
// share one target lane. Legacy payloads retain identity ordering rather than
// being silently collapsed into one global connector lane.
func ConnectorDeployEffectLane(identityID string, payload []byte) string {
	var route struct {
		TargetID string `json:"target_id"`
	}
	if json.Unmarshal(payload, &route) == nil && strings.TrimSpace(route.TargetID) != "" {
		return ConnectorTargetEffectLane(route.TargetID)
	}
	return "connector.deploy:identity:" + strings.TrimSpace(identityID)
}

// ConnectorTargetEffectLane is shared by a target deploy and its inverse.
func ConnectorTargetEffectLane(targetID string) string {
	return "connector.bind:target:" + strings.TrimSpace(targetID)
}

func lifecycleOutboxIntentFromEvent(ev events.Event, pl transitionPayload, dest string) (string, []byte, error) {
	expectedKey := transitionOutboxIdempotencyKey(ev.ID, pl.IdempotencyKey)
	if pl.SideEffect == nil {
		if ev.SchemaVersion >= projections.LifecycleSideEffectEventSchemaVersion {
			return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): replayable side_effect is required", ev.Type, ev.Sequence)
		}
		return expectedKey, ev.Data, nil
	}
	if pl.SideEffect.Destination != dest {
		return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): side_effect destination %q does not match transition destination %q", ev.Type, ev.Sequence, pl.SideEffect.Destination, dest)
	}
	if pl.SideEffect.IdempotencyKey != expectedKey {
		return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): side_effect idempotency key is not event-derived", ev.Type, ev.Sequence)
	}
	if ev.SchemaVersion == projections.LifecycleApprovalEventSchemaVersion ||
		ev.SchemaVersion == projections.LifecycleIssuanceEventSchemaVersion {
		if len(pl.SideEffect.Payload) != 0 {
			return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): canonical side_effect must not duplicate the outer payload", ev.Type, ev.Sequence)
		}
		canonical := pl
		canonical.SideEffect = nil
		payload, err := json.Marshal(canonical)
		if err != nil {
			return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): derive canonical outbox payload: %w", ev.Type, ev.Sequence, err)
		}
		return pl.SideEffect.IdempotencyKey, payload, nil
	}
	if ev.SchemaVersion == projections.LifecycleOwnershipReadinessEventSchemaVersion {
		// An explicit v6 body has already crossed the caller's storage-boundary
		// transform (connector credentials are tenant-sealed here). It is the only
		// replay authority for those bytes. Ordinary v6 transitions still omit the
		// duplicate and derive their command from the outer lifecycle envelope.
		if len(pl.SideEffect.Payload) != 0 {
			return pl.SideEffect.IdempotencyKey, pl.SideEffect.Payload, nil
		}
		canonical := pl
		canonical.SideEffect = nil
		payload, err := json.Marshal(canonical)
		if err != nil {
			return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): derive canonical outbox payload: %w", ev.Type, ev.Sequence, err)
		}
		return pl.SideEffect.IdempotencyKey, payload, nil
	}
	if len(pl.SideEffect.Payload) == 0 {
		return "", nil, fmt.Errorf("orchestrator: reconcile %s (seq %d): side_effect payload is required", ev.Type, ev.Sequence)
	}
	return pl.SideEffect.IdempotencyKey, pl.SideEffect.Payload, nil
}

type ctSubmissionQueuedEvent struct {
	Capability string            `json:"capability"`
	Payloads   []json.RawMessage `json:"payloads,omitempty"`
}

type ctSubmissionPayloadEnvelope struct {
	SubmissionID   string `json:"submission_id"`
	EntryType      string `json:"entry_type"`
	IdempotencyKey string `json:"idempotency_key"`
}

func ctSubmissionOutboxKey(p ctSubmissionPayloadEnvelope) (string, error) {
	if p.SubmissionID == "" || p.EntryType == "" || p.IdempotencyKey == "" {
		return "", fmt.Errorf("orchestrator: reconcile %s requires submission_id, entry_type, and idempotency_key", ctSubmissionEventQueued)
	}
	return fmt.Sprintf("%s:%s:%s:%s", ctSubmissionDestination, p.IdempotencyKey, p.EntryType, p.SubmissionID), nil
}

// isLifecycleTransition reports whether an event type is an identity lifecycle
// transition (identity.issued, identity.deployed, …). It intentionally checks the
// explicit transition registry rather than every identity.* prefix, so a future
// lifecycle event is not decoded by an older reconciler until its schema is added.
func isLifecycleTransition(eventType string) bool {
	for _, known := range transitionEvents {
		if eventType == known {
			return true
		}
	}
	return false
}

// State returns an identity's current lifecycle state. It reads the last
// projected transition for the identity in its tenant context — a single
// indexed, tenant-scoped query (SPINE-001), not a scan of the cross-tenant event
// log. The transitions are a projection of the log (AN-2), which stays the source
// of truth (a Rebuild re-derives them). An identity with no transitions is
// StateRequested.
func (o *Orchestrator) State(ctx context.Context, tenantID, identityID string) (State, error) {
	hist, err := o.History(ctx, tenantID, identityID)
	if err != nil {
		return "", err
	}
	state := StateRequested
	if n := len(hist); n > 0 {
		state = hist[n-1].To
	}
	return state, nil
}

// History returns an identity's transitions in order, read from the
// identity_transitions projection in the identity's tenant context (SPINE-001).
// The work is bounded by this identity's transition count and confined to its
// tenant by row-level security (AN-1) — it never scans another tenant's events,
// and its cost does not grow with the total log size. The transitions are a
// projection of the event log, which remains the source of truth (AN-2): a
// projection Rebuild re-derives them from the log.
func (o *Orchestrator) History(ctx context.Context, tenantID, identityID string) ([]Transition, error) {
	var rows []store.IdentityTransition
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		got, err := o.store.ListIdentityTransitions(ctx, tx, tenantID, identityID)
		if err != nil {
			return err
		}
		rows = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: load identity %s history: %w", identityID, err)
	}
	hist := make([]Transition, 0, len(rows))
	for _, r := range rows {
		hist = append(hist, Transition{
			From: State(r.FromState), To: State(r.ToState), Event: r.EventType,
			Reason: r.Reason, Sequence: r.Seq, At: r.OccurredAt,
		})
	}
	return hist, nil
}
