// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
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
	tenantDataRewrite    []events.TenantDataRewriteOption
	profileEditApprovals map[string]approvalProfileEditRequest
	profileEditMu        sync.Mutex
}

// OrchestratorOption configures served command-side behavior while keeping the
// long-standing NewOrchestrator call source-compatible.
type OrchestratorOption func(*Orchestrator)

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
	return o.transition(ctx, tenantID, identityID, to, reason, nil, "", nil)
}

// TransitionWithIdempotency moves an identity like Transition, but binds any
// outbox side effect to the served request's Idempotency-Key. The generic HTTP
// idempotency cache should normally catch a replay before this method is called;
// carrying the same key into the lifecycle event is the second guard that keeps
// async issue/revoke/deploy work from minting twice if the response cache is not
// the layer that observes the retry (CORRECT-001).
func (o *Orchestrator) TransitionWithIdempotency(ctx context.Context, tenantID, identityID string, to State, reason, idempotencyKey string) error {
	return o.transition(ctx, tenantID, identityID, to, reason, nil, idempotencyKey, nil)
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
	return o.transition(ctx, tenantID, identityID, to, reason, payload, "", nil)
}

// TransitionWithSideEffectPayloadTransform is TransitionWithSideEffectPayload with
// a storage-boundary transform. It is used for sensitive side effects whose
// durable event/outbox body must be sealed with AAD that includes the final outbox
// idempotency key.
func (o *Orchestrator) TransitionWithSideEffectPayloadTransform(ctx context.Context, tenantID, identityID string, to State, reason string, payload []byte, transform SideEffectPayloadTransform) error {
	if len(payload) == 0 {
		return o.Transition(ctx, tenantID, identityID, to, reason)
	}
	return o.transition(ctx, tenantID, identityID, to, reason, payload, "", transform)
}

func (o *Orchestrator) transition(ctx context.Context, tenantID, identityID string, to State, reason string, sideEffectPayload []byte, idempotencyKey string, transform SideEffectPayloadTransform) error {
	ident, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("orchestrator: load identity %s: %w", identityID, err)
	}
	from := State(ident.Status)

	evType, ok := EventTypeFor(from, to)
	if !ok {
		return &TransitionError{IdentityID: identityID, From: from, To: to}
	}

	idempotencyKey = strings.TrimSpace(idempotencyKey)
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
	basePayload := transitionPayload{IdentityID: identityID, From: from, To: to, Reason: reason, IdempotencyKey: idempotencyKey}
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
		basePayload.SideEffect = &transitionSideEffect{
			Destination:    sideEffectDest,
			IdempotencyKey: sideEffectKey,
			Payload:        append([]byte(nil), outboxPayload...),
		}
		payload, err = json.Marshal(basePayload)
		if err != nil {
			return err
		}
	}

	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{ID: eventID, Type: evType, TenantID: tenantID, SchemaVersion: schemaVersion, Data: payload})
		if err != nil {
			return err
		}
		// Project the status change through the projector (the sole read-model
		// writer, AN-2) in the same transaction as the outbox enqueue (AN-6).
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if hasSideEffect {
			// Enqueue the side effect idempotently (SPINE-011): legacy/internal
			// transitions key by event ID, while served lifecycle requests key by
			// their Idempotency-Key so a replay cannot enqueue a second async effect.
			// If a prior attempt already enqueued the effect, EnqueueIfAbsent is a
			// no-op, so the inline path and boot reconciliation cannot both enqueue it.
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:       tenantID,
				Destination:    sideEffectDest,
				IdempotencyKey: sideEffectKey,
				Payload:        outboxPayload,
				EffectLane:     lifecycleEffectLane(sideEffectDest, identityID),
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func transitionOutboxIdempotencyKey(eventID, requestKey string) string {
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" {
		return eventID
	}
	return "transition:" + requestKey
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
	err = log.Replay(ctx, from+1, func(ev events.Event) error {
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
			if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
				inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
					TenantID:       ev.TenantID,
					Destination:    discoveryRunDestination,
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
			inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:       ev.TenantID,
				Destination:    dest,
				IdempotencyKey: idempotencyKey,
				Payload:        outboxPayload,
				EffectLane:     lifecycleEffectLane(dest, pl.IdentityID),
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

func lifecycleEffectLane(destination, identityID string) string {
	if destination == "connector.deploy" && identityID != "" {
		return destination + ":identity:" + identityID
	}
	return destination
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
