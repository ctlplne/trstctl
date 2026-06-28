package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

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
	profileEditApprovals map[string]approvalProfileEditRequest
	profileEditMu        sync.Mutex
}

// NewOrchestrator returns an Orchestrator over the event log, read store, and
// outbox. It builds its own projector so a mutation it records is projected with
// the same logic a rebuild uses.
func NewOrchestrator(log *events.Log, st *store.Store, ob *Outbox) *Orchestrator {
	return &Orchestrator{
		log: log, store: st, outbox: ob, proj: projections.New(st),
		profileEditApprovals: map[string]approvalProfileEditRequest{},
	}
}

// Transition moves an identity from its current state to "to". It rejects an
// invalid transition with a *TransitionError before any effect. For a valid
// transition it appends the lifecycle event, then in a single tenant-scoped
// transaction updates the identity's status and enqueues any outbox side effect,
// so the external call is recorded with the state change (AN-6).
func (o *Orchestrator) Transition(ctx context.Context, tenantID, identityID string, to State, reason string) error {
	ident, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("orchestrator: load identity %s: %w", identityID, err)
	}
	from := State(ident.Status)

	evType, ok := EventTypeFor(from, to)
	if !ok {
		return &TransitionError{IdentityID: identityID, From: from, To: to}
	}

	payload, err := json.Marshal(transitionPayload{IdentityID: identityID, From: from, To: to, Reason: reason})
	if err != nil {
		return err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: evType, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}

	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Project the status change through the projector (the sole read-model
		// writer, AN-2) in the same transaction as the outbox enqueue (AN-6).
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if dest, ok := sideEffectFor(from, to); ok {
			// Enqueue the side effect keyed by the lifecycle event's globally-unique
			// ID, idempotently (SPINE-011): if a prior attempt for this exact event
			// already enqueued the effect, EnqueueIfAbsent is a no-op, so the inline
			// path and the boot reconciliation pass (ReconcileOutbox) can never both
			// enqueue the same transition's effect.
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:       tenantID,
				Destination:    dest,
				IdempotencyKey: ev.ID,
				Payload:        payload,
			}); err != nil {
				return err
			}
		}
		return nil
	})
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
// side effect, enqueues that effect idempotently keyed by the event's ID
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
		if err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:       ev.TenantID,
				Destination:    dest,
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
	})
	if err != nil {
		return healed, fmt.Errorf("orchestrator: reconcile outbox: %w", err)
	}
	return healed, nil
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
