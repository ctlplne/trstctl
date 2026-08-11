// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TenantRegistrationCommand is the one live tenant.registered producer shape.
// RequestMaterial is the stable authenticated request (without producer time or
// raw Idempotency-Key). PayloadAt must reconstruct the exact event payload for a
// supplied canonical event time, which makes append-before-SQL crash recovery an
// exact envelope check instead of a best-effort duplicate guess.
type TenantRegistrationCommand struct {
	TenantID        string
	Name            string
	IdempotencyKey  string
	RequestMaterial []byte
	PayloadAt       func(time.Time) ([]byte, error)
}

// TenantRegistrationAuthority is the immutable identity of one currently live
// tenant lifecycle. EventID and EventSequence always name the same retained
// tenant.registered envelope; callers persist both and revalidate EventSequence
// under LockLiveTenantRegistrationSnapshotTx before committing a receiver.
type TenantRegistrationAuthority struct {
	EventID       string
	EventSequence uint64
}

// ResolveLiveTenantRegistrationAuthority resolves the current tenants.event_seq
// under the shared missing-row-capable lifecycle fence and proves that exact
// position is a canonical durable tenant.registered event in the pinned history
// generation. Commands that also participate in privacy rewrites must place
// WithPrivacyRecoveryBarrier outside this helper, preserving the global
// privacy -> history -> lifecycle lock order.
func ResolveLiveTenantRegistrationAuthority(
	ctx context.Context,
	log *events.Log,
	st *store.Store,
	tenantID string,
) (TenantRegistrationAuthority, error) {
	if log == nil || st == nil || tenantID == "" {
		return TenantRegistrationAuthority{}, errors.New("orchestrator: tenant registration authority is incomplete")
	}
	var authority TenantRegistrationAuthority
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		return st.WithTenant(readCtx, tenantID, func(tx pgx.Tx) error {
			snapshot, err := st.LockLiveTenantRegistrationSnapshotTx(readCtx, tx, tenantID)
			if err != nil {
				return err
			}
			if snapshot.EventSeq == 0 {
				return fmt.Errorf("%w: live tenant has no retained registration sequence", ErrIdempotencyConflict)
			}
			registration, found, err := log.EventAtSequence(readCtx, snapshot.EventSeq)
			if err != nil {
				return err
			}
			if !found || registration.Sequence != snapshot.EventSeq ||
				registration.Type != projections.EventTenantRegistered ||
				registration.TenantID != tenantID || registration.ID == "" ||
				registration.Time.IsZero() {
				return fmt.Errorf("%w: live tenant registration sequence has no exact retained envelope", ErrIdempotencyConflict)
			}
			if err := projections.ValidateSchemaVersion(registration); err != nil {
				return err
			}
			if err := validateTenantRegistrationPayload(registration.Data, snapshot.Name); err != nil {
				return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
			}
			authority = TenantRegistrationAuthority{
				EventID: registration.ID, EventSequence: registration.Sequence,
			}
			return nil
		})
	})
	return authority, err
}

// ExecuteTenantRegistration serializes registration with offboard and secret
// synchronization, reconciles a deterministic retained event, and atomically
// commits its core tenant projection with the pending idempotency binding. The
// protected result is completed in a second fenced transaction so the tenant
// crypto resolver never needs a second pooled connection while SQL is held.
func ExecuteTenantRegistration(
	ctx context.Context,
	log *events.Log,
	st *store.Store,
	projector *projections.Projector,
	idempotency *Idempotency,
	command TenantRegistrationCommand,
) (events.Event, error) {
	if log == nil || st == nil || projector == nil || idempotency == nil ||
		command.TenantID == "" || command.Name == "" ||
		command.IdempotencyKey == "" || command.PayloadAt == nil {
		return events.Event{}, errors.New("orchestrator: tenant registration command is incomplete")
	}

	actor := tenantRegistrationActor(ctx)
	binding := tenantRegistrationBinding(command, actor)
	candidateEventID := "tenant-registration-" + uuid.NewString()
	var canonical events.Event
	err := st.WithPrivacyRecoveryBarrier(ctx, command.TenantID, "tenant registration", func(privacyCtx context.Context) error {
		return log.WithHistoryRead(privacyCtx, func(readCtx context.Context) error {
			var (
				claim   TenantRegistrationIdempotencyClaim
				wasLive bool
			)
			// Phase one is deliberately SQL-only. It commits one random producer
			// identity and PostgreSQL timestamp before Append, so a crash has a
			// permanent receiver even after JetStream forgets duplicate IDs.
			if err := st.WithTenantRegistrationFence(readCtx, command.TenantID, func(tx pgx.Tx) error {
				snapshot, err := st.LockTenantRegistrationSnapshotTx(readCtx, tx, command.TenantID)
				if err != nil {
					return err
				}
				wasLive = snapshot.Exists
				if snapshot.Exists {
					canonical, err = tenantRegistrationAtSequence(
						readCtx, log, command.TenantID, snapshot.EventSeq)
					if err != nil {
						return err
					}
				}
				claim, err = idempotency.PrepareTenantRegistrationTx(
					readCtx, tx, command.TenantID, command.IdempotencyKey,
					binding, candidateEventID)
				if err != nil {
					return err
				}
				if !snapshot.Exists {
					if claim.Completed {
						return fmt.Errorf("%w: completed registration has no live tenant", ErrIdempotencyConflict)
					}
					return nil
				}
				if claim.Created {
					return fmt.Errorf("%w: %s", store.ErrTenantRegistrationConflict, command.TenantID)
				}
				if !claim.Completed &&
					(claim.EventID != canonical.ID || !claim.EventTime.Equal(canonical.Time)) {
					return fmt.Errorf("%w: live tenant differs from pending registration anchor", ErrIdempotencyConflict)
				}
				if err := validateTenantRegistrationCanonical(command, actor, canonical.ID, canonical); err != nil {
					return err
				}
				return projector.ApplyTenantLifecycleTx(readCtx, tx, canonical)
			}); err != nil {
				secret.Wipe(claim.ProtectedResult)
				return err
			}

			if !wasLive {
				var recovered bool
				// Only a retry of an already-committed pending receiver scans by ID.
				// The first attempt and every completed replay stay O(1).
				if !claim.Created {
					var err error
					canonical, recovered, err = log.EventByID(readCtx, claim.EventID)
					if err != nil {
						return err
					}
				}
				// Phase two re-locks lifecycle before deciding whether Append is
				// allowed. Same-key contenders converge; a different-key preclaim
				// cannot pass phase one, so exactly one envelope can be published.
				if err := st.WithTenantRegistrationFence(readCtx, command.TenantID, func(tx pgx.Tx) error {
					current, err := idempotency.PrepareTenantRegistrationTx(
						readCtx, tx, command.TenantID, command.IdempotencyKey,
						binding, claim.EventID)
					if err != nil {
						return err
					}
					defer func() { secret.Wipe(current.ProtectedResult) }()
					if !current.Completed &&
						(current.EventID != claim.EventID || !current.EventTime.Equal(claim.EventTime)) {
						return fmt.Errorf("%w: registration receiver changed between phases", ErrIdempotencyConflict)
					}
					snapshot, err := st.LockTenantRegistrationSnapshotTx(readCtx, tx, command.TenantID)
					if err != nil {
						return err
					}
					if current.Completed {
						if !snapshot.Exists {
							return fmt.Errorf("%w: completed registration has no live tenant", ErrIdempotencyConflict)
						}
						canonical, err = tenantRegistrationAtSequence(
							readCtx, log, command.TenantID, snapshot.EventSeq)
						if err != nil {
							return err
						}
						if err := validateTenantRegistrationCanonical(
							command, actor, canonical.ID, canonical); err != nil {
							return err
						}
						secret.Wipe(claim.ProtectedResult)
						claim = current
						current.ProtectedResult = nil
						return nil
					}
					if snapshot.Exists {
						canonical, err = tenantRegistrationAtSequence(
							readCtx, log, command.TenantID, snapshot.EventSeq)
						if err != nil {
							return err
						}
					} else if !recovered {
						expected, err := tenantRegistrationExpected(
							command, actor, current.EventID, current.EventTime)
						if err != nil {
							return err
						}
						canonical, err = log.Append(readCtx, expected)
						if err != nil {
							return err
						}
					}
					if err := validateTenantRegistrationCanonical(
						command, actor, current.EventID, canonical); err != nil {
						return err
					}
					if snapshot.Exists &&
						(snapshot.Name != command.Name || snapshot.EventSeq != canonical.Sequence) {
						return fmt.Errorf("%w: %s", store.ErrTenantRegistrationConflict, command.TenantID)
					}
					return projector.ApplyTenantLifecycleTx(readCtx, tx, canonical)
				}); err != nil {
					return err
				}
			}

			// The cached receipt deliberately excludes payload and Actor. Protect
			// it after the core SQL transaction so the protector may use the pool.
			result, err := json.Marshal(struct {
				EventID       string `json:"event_id"`
				EventSequence uint64 `json:"event_sequence"`
			}{EventID: canonical.ID, EventSequence: canonical.Sequence})
			if err != nil {
				return err
			}
			defer secret.Wipe(result)
			if claim.Completed {
				opened, err := idempotency.openResult(
					readCtx, command.TenantID, command.IdempotencyKey, binding,
					claim.ResultCodec, claim.ProtectedResult)
				claim.ProtectedResult = nil
				if err != nil {
					return err
				}
				defer secret.Wipe(opened)
				if !bytes.Equal(opened, result) {
					return fmt.Errorf("%w: tenant registration result differs from retained event", ErrIdempotencyConflict)
				}
			} else if err := idempotency.completeTenantRegistration(
				readCtx, command, canonical, binding, result); err != nil {
				return err
			}

			return nil
		})
	})
	if err != nil {
		return events.Event{}, err
	}
	return canonical, nil
}

func tenantRegistrationAtSequence(
	ctx context.Context,
	log *events.Log,
	tenantID string,
	sequence uint64,
) (events.Event, error) {
	canonical, found, err := log.EventAtSequence(ctx, sequence)
	if err != nil {
		return events.Event{}, err
	}
	if !found || canonical.Type != projections.EventTenantRegistered ||
		canonical.TenantID != tenantID {
		return events.Event{}, fmt.Errorf(
			"%w: tenant row points at a non-registration event sequence",
			ErrIdempotencyConflict)
	}
	return canonical, nil
}

func tenantRegistrationExpected(
	command TenantRegistrationCommand,
	actor *events.Actor,
	eventID string,
	eventTime time.Time,
) (events.Event, error) {
	if eventTime.IsZero() {
		return events.Event{}, errors.New("orchestrator: tenant registration event time is zero")
	}
	payload, err := command.PayloadAt(eventTime)
	if err != nil {
		return events.Event{}, err
	}
	if err := validateTenantRegistrationPayload(payload, command.Name); err != nil {
		return events.Event{}, err
	}
	return events.Event{
		ID: eventID, Type: projections.EventTenantRegistered,
		TenantID: command.TenantID, Time: eventTime,
		SchemaVersion: events.DefaultSchemaVersion,
		Data:          payload, Actor: actor,
	}, nil
}

func validateTenantRegistrationCanonical(
	command TenantRegistrationCommand,
	actor *events.Actor,
	eventID string,
	canonical events.Event,
) error {
	expected, err := tenantRegistrationExpected(command, actor, eventID, canonical.Time)
	if err != nil {
		return err
	}
	if err := projections.ValidateTenantLifecycleCanonical(expected, canonical); err != nil {
		return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
	}
	return nil
}

// emitTenantOffboard is the live tenant.offboarded producer. The privacy
// operation barrier is outermost, then the fixed history view, then the tenant
// transaction/lifecycle fence. That order lets a privacy cutover finish without
// deadlocking an offboard that already owns PostgreSQL's backup fence.
func (o *Orchestrator) emitTenantOffboard(
	ctx context.Context,
	next events.Event,
) (events.Event, error) {
	if o == nil || o.log == nil || o.store == nil || o.proj == nil || next.TenantID == "" {
		return events.Event{}, errors.New("orchestrator: tenant offboard command is incomplete")
	}
	if next.Type != projections.EventTenantOffboarded {
		return events.Event{}, errors.New("orchestrator: tenant offboard command has the wrong event type")
	}
	if next.SchemaVersion == 0 {
		next.SchemaVersion = events.DefaultSchemaVersion
	}
	if err := projections.ValidateSchemaVersion(next); err != nil {
		return events.Event{}, err
	}
	if !next.Time.IsZero() {
		return events.Event{}, errors.New("orchestrator: tenant offboard event time is assigned by the durable receiver")
	}
	var payload struct {
		RowsDeleted int `json:"rows_deleted"`
	}
	if err := json.Unmarshal(next.Data, &payload); err != nil {
		return events.Event{}, fmt.Errorf("orchestrator: decode tenant offboard payload: %w", err)
	}
	if next.Actor == nil {
		next.Actor = tenantRegistrationActor(ctx)
	} else {
		next.Actor = canonicalTenantActor(*next.Actor)
	}

	var (
		canonical                   events.Event
		claim                       tenantOffboardClaim
		recoveredAfterReceiverErase bool
	)
	err := o.store.WithPrivacyRecoveryBarrier(ctx, next.TenantID, "tenant offboard", func(privacyCtx context.Context) error {
		return o.log.WithHistoryRead(privacyCtx, func(readCtx context.Context) error {
			// Commit the non-PII receiver before Append. Offboard deletes this row
			// atomically with the tenant; if Append wins but deletion rolls back, a
			// retry sees the pending receiver and performs the rare ID recovery scan.
			if err := o.store.WithTenant(readCtx, next.TenantID, func(tx pgx.Tx) error {
				// First callback statement: this takes the fail-fast transaction
				// side of the already-held privacy grant, then the lifecycle lock.
				if err := o.store.PreflightTenantOffboardTx(readCtx, tx, next.TenantID); err != nil {
					return err
				}
				snapshot, err := o.store.LockTenantRegistrationSnapshotTx(readCtx, tx, next.TenantID)
				if err != nil {
					return err
				}
				if !snapshot.Exists {
					receiverExists, err := tenantOffboardReceiverExistsTx(
						readCtx, tx, next.TenantID)
					if err != nil {
						return err
					}
					if receiverExists {
						return fmt.Errorf(
							"%w: tenant is absent while an offboard receiver remains",
							ErrIdempotencyConflict,
						)
					}
					// Successful offboard atomically removes both the tenant row and
					// its pending receiver. Only that exact missing/missing shape may
					// pay for a pinned O(total) lifecycle fold.
					canonical, err = recoverErasedTenantOffboard(
						readCtx, o.log, next)
					if err != nil {
						return err
					}
					recoveredAfterReceiverErase = true
					return o.proj.ApplyTenantLifecycleTx(readCtx, tx, canonical)
				}
				registrationIdentity, err := tenantRegistrationIdentityForOffboard(
					readCtx, o.log, next.TenantID, snapshot)
				if err != nil {
					return err
				}
				eventID := projections.TenantOffboardEventID(next.TenantID, registrationIdentity)
				if next.ID != "" && next.ID != eventID {
					return ErrIdempotencyConflict
				}
				next.ID = eventID
				claim, err = prepareTenantOffboardTx(readCtx, tx, next)
				return err
			}); err != nil {
				return err
			}
			if recoveredAfterReceiverErase {
				return nil
			}

			var recovered bool
			if !claim.Created {
				var err error
				canonical, recovered, err = o.log.EventByID(readCtx, claim.EventID)
				if err != nil {
					return err
				}
			}

			if err := o.store.WithTenant(readCtx, next.TenantID, func(tx pgx.Tx) error {
				// Keep the privacy-operation try-lock as the first callback statement.
				if err := o.store.PreflightTenantOffboardTx(readCtx, tx, next.TenantID); err != nil {
					return err
				}
				snapshot, err := o.store.LockTenantRegistrationSnapshotTx(readCtx, tx, next.TenantID)
				if err != nil {
					return err
				}
				if !snapshot.Exists {
					// A same-command contender may have committed the erase while this
					// retry waited on lifecycle. Recover its exact envelope once.
					if !recovered {
						canonical, recovered, err = o.log.EventByID(readCtx, claim.EventID)
						if err != nil {
							return err
						}
					}
					if !recovered {
						return fmt.Errorf("%w: offboard receiver disappeared without its event", ErrIdempotencyConflict)
					}
					expected := next
					expected.Time = canonical.Time
					if err := projections.ValidateTenantLifecycleCanonical(expected, canonical); err != nil {
						return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
					}
					return o.proj.ApplyTenantLifecycleTx(readCtx, tx, canonical)
				}
				registrationIdentity, err := tenantRegistrationIdentityForOffboard(
					readCtx, o.log, next.TenantID, snapshot)
				if err != nil {
					return err
				}
				if projections.TenantOffboardEventID(next.TenantID, registrationIdentity) != claim.EventID {
					return fmt.Errorf("%w: tenant lifecycle changed before offboard append", ErrIdempotencyConflict)
				}
				current, err := prepareTenantOffboardTx(readCtx, tx, next)
				if err != nil {
					return err
				}
				if current.EventID != claim.EventID || !current.EventTime.Equal(claim.EventTime) {
					return fmt.Errorf("%w: offboard receiver changed between phases", ErrIdempotencyConflict)
				}
				next.Time = current.EventTime
				if !recovered {
					canonical, err = o.log.Append(readCtx, next)
					if err != nil {
						return err
					}
				}
				if err := projections.ValidateTenantLifecycleCanonical(next, canonical); err != nil {
					return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
				}
				return o.proj.ApplyTenantLifecycleTx(readCtx, tx, canonical)
			}); err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		return events.Event{}, err
	}
	return canonical, nil
}

type tenantOffboardClaim struct {
	Created   bool
	EventID   string
	EventTime time.Time
}

const tenantOffboardAnchorPrefix = "trstctl-tenant-offboard-anchor-v1\x00tenant-offboard-"

func tenantOffboardAnchor(eventID string) ([]byte, error) {
	const eventPrefix = "tenant-offboard-"
	if len(eventID) <= len(eventPrefix) || eventID[:len(eventPrefix)] != eventPrefix {
		return nil, errors.New("orchestrator: tenant offboard event id has the wrong prefix")
	}
	if _, err := uuid.Parse(eventID[len(eventPrefix):]); err != nil {
		return nil, errors.New("orchestrator: tenant offboard event id is malformed")
	}
	return []byte("trstctl-tenant-offboard-anchor-v1\x00" + eventID), nil
}

func parseTenantOffboardAnchor(raw []byte) (string, error) {
	if !bytes.HasPrefix(raw, []byte(tenantOffboardAnchorPrefix)) {
		return "", errors.New("orchestrator: pending offboard anchor has the wrong format")
	}
	eventID := string(raw[len("trstctl-tenant-offboard-anchor-v1\x00"):])
	canonical, err := tenantOffboardAnchor(eventID)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errors.New("orchestrator: pending offboard anchor is malformed")
	}
	return eventID, nil
}

func prepareTenantOffboardTx(
	ctx context.Context,
	tx pgx.Tx,
	next events.Event,
) (tenantOffboardClaim, error) {
	if tx == nil || next.TenantID == "" || next.ID == "" {
		return tenantOffboardClaim{}, errors.New("orchestrator: tenant offboard receiver is incomplete")
	}
	anchor, err := tenantOffboardAnchor(next.ID)
	if err != nil {
		return tenantOffboardClaim{}, err
	}
	defer secret.Wipe(anchor)
	binding := tenantOffboardBinding(next)
	key := "trstctl.internal.tenant-offboard.v1/" + next.ID
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO idempotency_keys
		       (tenant_id, key, status, request_binding, result_codec, result, created_at)
		VALUES ($1, $2, 'pending', $3, $4, $5, clock_timestamp())
		ON CONFLICT (tenant_id, key) DO NOTHING
		RETURNING created_at`, next.TenantID, key, binding,
		ResultCodecRawV0, anchor).Scan(&createdAt)
	if err == nil {
		return tenantOffboardClaim{
			Created: true, EventID: next.ID, EventTime: createdAt.UTC(),
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return tenantOffboardClaim{}, fmt.Errorf("orchestrator: prepare tenant offboard receiver: %w", err)
	}
	var status, storedBinding, codec string
	var stored []byte
	if err := tx.QueryRow(ctx, `
		SELECT status, request_binding, result_codec, result, created_at
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = $2
		 FOR UPDATE`, next.TenantID, key).Scan(
		&status, &storedBinding, &codec, &stored, &createdAt); err != nil {
		return tenantOffboardClaim{}, fmt.Errorf("orchestrator: load tenant offboard receiver: %w", err)
	}
	defer secret.Wipe(stored)
	eventID, parseErr := parseTenantOffboardAnchor(stored)
	if status != "pending" || !idempotencyBindingEqual(storedBinding, binding) ||
		codec != ResultCodecRawV0 || parseErr != nil || eventID != next.ID || createdAt.IsZero() {
		return tenantOffboardClaim{}, ErrIdempotencyConflict
	}
	return tenantOffboardClaim{EventID: eventID, EventTime: createdAt.UTC()}, nil
}

func tenantOffboardReceiverExistsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM idempotency_keys
			 WHERE tenant_id = $1
			   AND key LIKE 'trstctl.internal.tenant-offboard.v1/%'
		)`, tenantID).Scan(&exists); err != nil {
		return false, fmt.Errorf("orchestrator: inspect erased tenant offboard receiver: %w", err)
	}
	return exists, nil
}

// recoverErasedTenantOffboard is the one deliberately expensive retry path.
// The caller has already proved both SQL lifecycle anchors absent while holding
// the exclusive missing-row fence and a history-generation read grant. Pinning
// one head makes the fold deterministic even while unrelated tenants append.
func recoverErasedTenantOffboard(
	ctx context.Context,
	log *events.Log,
	next events.Event,
) (events.Event, error) {
	head, err := log.LastSequence(ctx)
	if err != nil {
		return events.Event{}, fmt.Errorf("orchestrator: capture erased tenant lifecycle head: %w", err)
	}
	var (
		latest             events.Event
		activeRegistration events.Event
		byID               = make(map[string]events.Event)
	)
	if head != 0 {
		err = log.ReplayThrough(ctx, 1, head, func(event events.Event) error {
			if event.TenantID != next.TenantID ||
				!isTenantLifecycleEvent(event.Type) {
				return nil
			}
			if err := projections.ValidateSchemaVersion(event); err != nil {
				return err
			}
			if event.ID == "" || event.Sequence == 0 || event.Time.IsZero() {
				return fmt.Errorf("%w: retained tenant lifecycle envelope is incomplete", ErrIdempotencyConflict)
			}
			if prior, duplicate := byID[event.ID]; duplicate {
				if err := projections.ValidateTenantLifecycleCanonical(prior, event); err != nil {
					return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
				}
				// An exact duplicate producer identity is one logical event. Keep
				// the first canonical sequence, matching EventByID semantics.
				return nil
			}
			byID[event.ID] = event
			switch event.Type {
			case projections.EventTenantRegistered:
				var payload struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(event.Data, &payload); err != nil || payload.Name == "" {
					return fmt.Errorf("%w: retained tenant registration payload is malformed", ErrIdempotencyConflict)
				}
				if activeRegistration.ID != "" && isDurableTenantRegistrationIdentity(event.ID) {
					return fmt.Errorf("%w: retained tenant lifecycle has consecutive live registrations", ErrIdempotencyConflict)
				}
				// Pre-durable-producer logs used tenant.registered as an upsert/rename
				// event. Their arbitrary IDs are not a second lifecycle: the latest
				// rename is exactly the tenants.event_seq identity from which a legacy
				// offboard was derived. A v2 durable producer ID while a registration
				// is already live is impossible and was rejected above.
				activeRegistration = event
			case projections.EventTenantOffboarded:
				var payload struct {
					RowsDeleted int `json:"rows_deleted"`
				}
				if err := json.Unmarshal(event.Data, &payload); err != nil {
					return fmt.Errorf("%w: retained tenant offboard payload is malformed", ErrIdempotencyConflict)
				}
				if _, err := tenantOffboardAnchor(event.ID); err != nil {
					return fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
				}
				if activeRegistration.ID == "" {
					return fmt.Errorf("%w: retained tenant lifecycle has an offboard without a live registration", ErrIdempotencyConflict)
				}
				if event.ID != projections.TenantOffboardEventID(
					next.TenantID, activeRegistration.ID) {
					return fmt.Errorf("%w: retained offboard identity does not name its registration", ErrIdempotencyConflict)
				}
				activeRegistration = events.Event{}
			}
			latest = event
			return nil
		})
		if err != nil {
			return events.Event{}, fmt.Errorf("orchestrator: fold erased tenant lifecycle: %w", err)
		}
	}
	if latest.Type != projections.EventTenantOffboarded {
		return events.Event{}, fmt.Errorf(
			"%w: tenant %s has no exact terminal offboard lifecycle",
			store.ErrTenantRegistrationConflict, next.TenantID,
		)
	}
	if next.ID != "" && next.ID != latest.ID {
		return events.Event{}, ErrIdempotencyConflict
	}
	expected := next
	expected.ID = latest.ID
	expected.Time = latest.Time
	// rows_deleted is producer output, not retry input. Once the successful erase
	// removes both SQL anchors, retained history is its only canonical value. Keep
	// validating the retry's envelope and actor, but compare the exact retained
	// output payload so a caller that naturally observes zero rows after deletion
	// can recover a first attempt whose attestation was non-zero.
	expected.Data = append([]byte(nil), latest.Data...)
	if err := projections.ValidateTenantLifecycleCanonical(expected, latest); err != nil {
		return events.Event{}, fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
	}
	return latest, nil
}

func isDurableTenantRegistrationIdentity(eventID string) bool {
	if !bytes.HasPrefix([]byte(eventID), []byte("tenant-registration-")) {
		return false
	}
	anchor, err := tenantRegistrationAnchor(eventID)
	secret.Wipe(anchor)
	return err == nil
}

func isTenantLifecycleEvent(eventType string) bool {
	return eventType == projections.EventTenantRegistered ||
		eventType == projections.EventTenantOffboarded
}

func tenantRegistrationIdentityForOffboard(
	ctx context.Context,
	log *events.Log,
	tenantID string,
	snapshot store.TenantRegistrationSnapshot,
) (string, error) {
	if snapshot.EventSeq != 0 {
		registration, found, err := log.EventAtSequence(ctx, snapshot.EventSeq)
		if err != nil {
			return "", err
		}
		if !found {
			return "", fmt.Errorf("%w: tenant row registration sequence is not retained", ErrIdempotencyConflict)
		}
		if registration.Type != projections.EventTenantRegistered ||
			registration.TenantID != tenantID || registration.ID == "" ||
			registration.Time.IsZero() {
			return "", fmt.Errorf("%w: tenant row has a conflicting registration sequence", ErrIdempotencyConflict)
		}
		if err := projections.ValidateSchemaVersion(registration); err != nil {
			return "", err
		}
		if err := validateTenantRegistrationPayload(registration.Data, snapshot.Name); err != nil {
			return "", fmt.Errorf("%w: %v", ErrIdempotencyConflict, err)
		}
		return registration.ID, nil
	}
	return projections.LegacyTenantRegistrationIdentity(
		tenantID, snapshot.Name, snapshot.EventSeq, snapshot.CreatedAt), nil
}

func tenantOffboardBinding(next events.Event) string {
	actorBytes, _ := json.Marshal(next.Actor)
	fields := [][]byte{
		[]byte("trstctl.tenant-offboard.binding.v1"),
		[]byte(next.Type), []byte(next.TenantID), []byte(next.ID),
		[]byte(fmt.Sprintf("%d", next.SchemaVersion)), next.Data, actorBytes,
	}
	length := 0
	for _, field := range fields {
		length += 8 + len(field)
	}
	material := make([]byte, 0, length)
	var size [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		material = append(material, size[:]...)
		material = append(material, field...)
	}
	defer secret.Wipe(material)
	return "sha256:" + crypto.SHA256Hex(material)
}

func (i *Idempotency) completeTenantRegistration(
	ctx context.Context,
	command TenantRegistrationCommand,
	canonical events.Event,
	binding string,
	result []byte,
) error {
	codec, candidateProtected, err := i.protectResult(
		ctx, command.TenantID, command.IdempotencyKey, binding, result)
	if err != nil {
		return err
	}
	defer secret.Wipe(candidateProtected)

	storedCodec := codec
	storedProtected := append([]byte(nil), candidateProtected...)
	defer secret.Wipe(storedProtected)
	err = i.store.WithTenantRegistrationFence(ctx, command.TenantID, func(tx pgx.Tx) error {
		snapshot, err := i.store.LockTenantRegistrationSnapshotTx(ctx, tx, command.TenantID)
		if err != nil {
			return err
		}
		if !snapshot.Exists || snapshot.Name != command.Name || snapshot.EventSeq != canonical.Sequence {
			return fmt.Errorf("%w: tenant lifecycle changed before idempotency completion", ErrIdempotencyConflict)
		}

		var status, storedBinding, currentCodec string
		var currentResult []byte
		var anchorTime time.Time
		if err := tx.QueryRow(ctx, `
			SELECT status, request_binding, result_codec, result, created_at
			  FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2
			 FOR UPDATE`, command.TenantID, command.IdempotencyKey).Scan(
			&status, &storedBinding, &currentCodec, &currentResult, &anchorTime); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrIdempotencyConflict
			}
			return fmt.Errorf("orchestrator: load registration completion binding: %w", err)
		}
		defer secret.Wipe(currentResult)
		if !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		switch status {
		case "pending":
			anchorEventID, err := parseTenantRegistrationAnchor(currentResult)
			if err != nil || currentCodec != ResultCodecRawV0 ||
				anchorEventID != canonical.ID || !anchorTime.Equal(canonical.Time) {
				return fmt.Errorf("%w: pending registration receiver differs from projected lifecycle", ErrIdempotencyConflict)
			}
			tag, err := tx.Exec(ctx, `
				UPDATE idempotency_keys
				   SET status = 'completed', result_codec = $4, result = $5,
				       completed_at = now()
				 WHERE tenant_id = $1 AND key = $2 AND request_binding = $3
				   AND status = 'pending' AND result_codec = $6
				   AND result = $7 AND created_at = $8`,
				command.TenantID, command.IdempotencyKey, binding, codec,
				candidateProtected, ResultCodecRawV0, currentResult, anchorTime)
			if err != nil {
				return fmt.Errorf("orchestrator: complete tenant registration key: %w", err)
			}
			if tag.RowsAffected() != 1 {
				return ErrInProgress
			}
			return nil
		case "completed":
			secret.Wipe(storedProtected)
			storedCodec = currentCodec
			storedProtected = append([]byte(nil), currentResult...)
			return nil
		default:
			return incompleteResultError(status)
		}
	})
	if err != nil {
		return err
	}
	opened, err := i.openResult(
		ctx, command.TenantID, command.IdempotencyKey, binding,
		storedCodec, storedProtected)
	// openResult consumes storedProtected; make the deferred wipe harmless.
	storedProtected = nil
	if err != nil {
		return err
	}
	defer secret.Wipe(opened)
	if !bytes.Equal(opened, result) {
		return fmt.Errorf("%w: completed tenant registration result differs from retained event", ErrIdempotencyConflict)
	}
	return nil
}

func tenantRegistrationActor(ctx context.Context) *events.Actor {
	actor, ok := events.ActorFromContext(ctx)
	if !ok {
		return nil
	}
	return canonicalTenantActor(actor)
}

func canonicalTenantActor(actor events.Actor) *events.Actor {
	canonical := events.Actor{Subject: actor.Subject}
	canonical.Roles = append([]string(nil), actor.Roles...)
	sort.Strings(canonical.Roles)
	write := 0
	for _, role := range canonical.Roles {
		if write > 0 && canonical.Roles[write-1] == role {
			continue
		}
		canonical.Roles[write] = role
		write++
	}
	canonical.Roles = canonical.Roles[:write]
	if len(canonical.Roles) == 0 {
		canonical.Roles = nil
	}
	return &canonical
}

func tenantRegistrationBinding(
	command TenantRegistrationCommand,
	actor *events.Actor,
) string {
	actorBytes, _ := json.Marshal(actor)
	fields := [][]byte{
		// v2 binds the canonicalized actor and the durable pre-Append receiver
		// protocol. It must not alias a v1 completion produced before those rules.
		[]byte("trstctl.tenant-registration.binding.v2"),
		[]byte(command.TenantID), []byte(command.Name),
		actorBytes, command.RequestMaterial,
	}
	length := 0
	for _, field := range fields {
		length += 8 + len(field)
	}
	material := make([]byte, 0, length)
	var size [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		material = append(material, size[:]...)
		material = append(material, field...)
	}
	defer secret.Wipe(material)
	return "sha256:" + crypto.SHA256Hex(material)
}

func validateTenantRegistrationPayload(payload []byte, name string) error {
	var decoded struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("orchestrator: decode tenant registration payload: %w", err)
	}
	if decoded.Name != name {
		return errors.New("orchestrator: tenant registration payload name differs from command")
	}
	return nil
}
