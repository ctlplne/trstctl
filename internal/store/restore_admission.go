// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"trstctl.com/trstctl/internal/events"
)

//go:embed restore_admission_bootstrap.sql
var restoreAdmissionBootstrapSQL string

// BootstrapRestoreAdmission creates only the target-local restore fence. It is
// safe before the application schema exists, so a full restore can commit its
// marker before ordinary migrations or signer/file writes.
func (s *Store) BootstrapRestoreAdmission(ctx context.Context) error {
	if s == nil {
		return ErrRestoreAdmissionLost
	}
	var markers, activities, ingressJournal, markerPolicy, activityPolicy, ingressPolicy bool
	var markerRLS, activityRLS, ingressRLS bool
	// Target-local schema bootstrap precedes tenant selection. The system pool
	// inspects only pg_catalog existence and RLS metadata, never tenant rows.
	//trstctl:system-query — system pg_catalog schema and RLS lookup before any tenant is known; reads no tenant row or payload.
	err := s.SystemPool().QueryRow(ctx, `SELECT
		to_regclass('trstctl_recovery.restore_markers') IS NOT NULL,
		to_regclass('trstctl_recovery.restore_activity_tokens') IS NOT NULL,
		to_regclass('trstctl_recovery.event_ingress_journal') IS NOT NULL,
		EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=to_regclass('trstctl_recovery.restore_markers')
			AND polname='restore_markers_control_isolation'),
		EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=to_regclass('trstctl_recovery.restore_activity_tokens')
			AND polname='restore_activity_tenant_isolation'),
		EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=to_regclass('trstctl_recovery.event_ingress_journal')
			AND polname='event_ingress_journal_tenant_isolation'),
		EXISTS (SELECT 1 FROM pg_class WHERE oid=to_regclass('trstctl_recovery.restore_markers')
			AND relrowsecurity AND relforcerowsecurity),
		EXISTS (SELECT 1 FROM pg_class WHERE oid=to_regclass('trstctl_recovery.restore_activity_tokens')
			AND relrowsecurity AND relforcerowsecurity),
		EXISTS (SELECT 1 FROM pg_class WHERE oid=to_regclass('trstctl_recovery.event_ingress_journal')
			AND relrowsecurity AND relforcerowsecurity)`).
		Scan(&markers, &activities, &ingressJournal, &markerPolicy, &activityPolicy, &ingressPolicy,
			&markerRLS, &activityRLS, &ingressRLS)
	if err != nil {
		return fmt.Errorf("store: inspect restore admission schema: %w", err)
	}
	if markers && activities && ingressJournal && markerPolicy && activityPolicy && ingressPolicy &&
		markerRLS && activityRLS && ingressRLS {
		return nil
	}
	if markers || activities || ingressJournal || markerPolicy || activityPolicy || ingressPolicy {
		return errors.New("store: restore admission schema is incomplete; refusing startup")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, restoreAdmissionBootstrapSQL); err != nil {
		return fmt.Errorf("store: bootstrap restore admission: %w", err)
	}
	return tx.Commit(ctx)
}

const RestoreControlTenantID = "00000000-0000-0000-0000-000000000004"

const (
	restoreAdmissionSessionKey int64 = 0x726573746f726541
	restoreAdmissionCommitKey  int64 = 0x726573746f726542
)

var (
	ErrRestoreInProgress         = errors.New("store: full restore is in progress")
	ErrRestoreActivityUnresolved = errors.New("store: unresolved activity blocks full restore")
	ErrRestoreAdmissionLost      = errors.New("store: restore admission session was lost")
	ErrRestoreIncomplete         = errors.New("store: full restore has not reached its verified final phase")
	restoreArtifactDigest        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RestoreMarker struct {
	OperationID        string
	ArtifactSHA256     string
	EventHistorySHA256 string
	EventCut           uint64
	DeploymentID       string
}

type restoreOwnerContextKey struct{}
type restoreOwnerLease struct {
	marker RestoreMarker
	origin *Store
	active atomic.Bool
}

type restoreRebuildContextKey struct{}
type restoreRebuildLease struct {
	origin *Store
	active atomic.Bool
}

type restoreRawHistoryContextKey struct{}
type restoreRawHistoryLease struct {
	origin *Store
	active atomic.Bool
}

type restoreActivityContextKey struct{}
type restoreActivityLease struct {
	origin *Store
	conn   *pgxpool.Conn
	active atomic.Bool
	mu     sync.Mutex // pgx connections cannot run two token statements at once
}

type restoreActivityTokenContextKey struct{}
type restoreIngressEventTypeContextKey struct{}
type restoreIngressTenantScopeContextKey struct{}
type restoreActivityToken struct {
	origin                                     *Store
	lease                                      *restoreActivityLease
	tenantID, operationID, kind, lane, eventID string
	active                                     atomic.Bool
}

type restoreActivityNoEffectError struct{ cause error }
type restoreActivityTerminalError struct{ cause error }

func (e *restoreActivityNoEffectError) Error() string { return e.cause.Error() }
func (e *restoreActivityNoEffectError) Unwrap() error { return e.cause }
func (e *restoreActivityTerminalError) Error() string { return e.cause.Error() }
func (e *restoreActivityTerminalError) Unwrap() error { return e.cause }

// RestoreActivityNoEffect marks an error only when the callback has proved no
// event, SQL mutation, file write or external effect could have occurred. The
// durable start is then terminal evidence, while callers still see the cause.
func RestoreActivityNoEffect(err error) error {
	if err == nil {
		return nil
	}
	return &restoreActivityNoEffectError{cause: err}
}

// RestoreActivityTerminal is for a callback that changed state but proved its
// entire attempt has a durable terminal outcome (for example, a projected key
// transition failure snapshot). It must never be used for an unacknowledged
// broker write, external call, or uncertain transaction outcome.
func RestoreActivityTerminal(err error) error {
	if err == nil {
		return nil
	}
	return &restoreActivityTerminalError{cause: err}
}

func validateRestoreMarker(marker RestoreMarker) error {
	if _, err := uuid.Parse(marker.OperationID); err != nil ||
		!restoreArtifactDigest.MatchString(marker.ArtifactSHA256) ||
		(marker.EventHistorySHA256 != "" && !restoreArtifactDigest.MatchString(marker.EventHistorySHA256)) ||
		marker.DeploymentID == "" || marker.EventCut > uint64(^uint64(0)>>1) {
		return errors.New("store: restore marker identity is incomplete")
	}
	return nil
}

// withRestoreAdmission holds the session half across an entire activity. The
// distinct transaction key serializes a token or marker commit with another
// replica even if the session connection disappears before the commit outcome.
func (s *Store) withRestoreAdmission(ctx context.Context, exclusive bool, fn func(context.Context, pgx.Tx) error) (retErr error) {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	conn, err := s.lockSessionPool(ctx).Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire restore admission session: %w", err)
	}
	locked := false
	uncertain := false
	defer func() {
		if uncertain {
			retErr = errors.Join(retErr, discardHistoryRewriteSession(conn))
			return
		}
		if !locked {
			conn.Release()
			return
		}
		if err := releaseHistoryRewriteLock(conn, restoreAdmissionSessionKey, !exclusive); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("store: release restore admission: %w", err), discardHistoryRewriteSession(conn))
			return
		}
		conn.Release()
	}()
	if err := acquireHistoryRewriteLock(ctx, conn, restoreAdmissionSessionKey, !exclusive); err != nil {
		uncertain = true
		return fmt.Errorf("store: acquire restore admission: %w", err)
	}
	locked = true
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	lockQuery := `SELECT pg_advisory_xact_lock_shared($1)`
	if exclusive {
		lockQuery = `SELECT pg_advisory_xact_lock($1)`
	}
	if _, err := tx.Exec(ctx, lockQuery, restoreAdmissionCommitKey); err != nil {
		return fmt.Errorf("store: acquire restore admission commit lock: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	return tx.Commit(ctx)
}

func (s *Store) restoreMarkerPresentTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	if err := s.SetTenantGUCTx(ctx, tx, RestoreControlTenantID); err != nil {
		return false, err
	}
	var present bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_markers
		WHERE tenant_id=$1)`, RestoreControlTenantID).Scan(&present)
	return present, err
}

// RequireRestoreEffectStartTx serializes the marker decision with the durable
// receiver_pending_ids insert in this same caller transaction. Once the insert
// commits, BeginFullRestore sees that token even if the worker connection dies
// while the external receiver is still executing.
func (s *Store) RequireRestoreEffectStartTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if s == nil || tx == nil {
		return ErrRestoreAdmissionLost
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return ErrRestoreAdmissionLost
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	present, err := s.restoreMarkerPresentTx(ctx, tx)
	if err != nil {
		return err
	}
	if present {
		return ErrRestoreInProgress
	}
	return s.SetTenantGUCTx(ctx, tx, tenantID)
}

// The target-local journal cannot replace independent receiver evidence:
// an accepted remote attempt may finish after the worker session disappears.
// A fresh target has no application schema yet; an existing one must have the
// complete outbox/agent receipt schema or fail closed.
func (s *Store) requireRestoreRemoteQuiescentTx(ctx context.Context, tx pgx.Tx) error {
	var tenantsPresent, outboxPresent bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('public.tenants') IS NOT NULL,
		to_regclass('public.outbox') IS NOT NULL`).Scan(&tenantsPresent, &outboxPresent); err != nil {
		return err
	}
	if !tenantsPresent && !outboxPresent {
		return nil
	}
	if !tenantsPresent || !outboxPresent {
		return fmt.Errorf("%w: target remote-work schema is incomplete", ErrRestoreActivityUnresolved)
	}
	//trstctl:system-query — cross-tenant system restore reads tenant_id only from the target outbox to find affected tenants; each tenant's unresolved remote work is then checked under its own RLS context before mutation.
	rows, err := tx.Query(ctx, `SELECT DISTINCT tenant_id::text FROM outbox ORDER BY tenant_id::text`)
	if err != nil {
		return fmt.Errorf("%w: enumerate target remote work: %v", ErrRestoreActivityUnresolved, err)
	}
	var tenantIDs []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return err
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, tenantID := range tenantIDs {
		if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := s.RequireTenantAgentWorkQuiescentTx(ctx, tx, tenantID); err != nil {
			return fmt.Errorf("%w: tenant %s: %v", ErrRestoreActivityUnresolved, tenantID, err)
		}
		var effectPossible bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox
			WHERE tenant_id=$1 AND destination LIKE 'secret.sync.%'
			AND secret_sync_receiver_effect_state='effect_possible')`, tenantID).Scan(&effectPossible); err != nil {
			return fmt.Errorf("%w: inspect tenant %s secret-sync receiver state: %v", ErrRestoreActivityUnresolved, tenantID, err)
		}
		if effectPossible {
			return fmt.Errorf("%w: tenant %s has a secret-sync effect without terminal receiver evidence", ErrRestoreActivityUnresolved, tenantID)
		}
	}
	return nil
}

// A multi-step rewrap can have no live worker between steps while its durable
// gate still protects ciphertext. Full restore must refuse that whole interval.
// A fresh target may not have installed the application schema yet.
func (s *Store) requireNoArmedRewrapGatesTx(ctx context.Context, tx pgx.Tx) error {
	var present bool
	if err := tx.QueryRow(ctx,
		`SELECT to_regclass('public.application_secret_rewrap_gates') IS NOT NULL`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return nil
	}
	var armed bool
	//trstctl:system-query — cross-tenant system restore holds exclusive admission and checks the rewrap gate for every tenant_id before changing target artifacts; this query returns only whether any gate is armed.
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_secret_rewrap_gates
		WHERE rewrap_in_progress=true)`).Scan(&armed); err != nil {
		return err
	}
	if armed {
		return fmt.Errorf("%w: credential key rewrap remains in progress", ErrRestoreActivityUnresolved)
	}
	return nil
}

// WithRestoreActivity commits the exact start before invoking a mutation or
// external effect. A callback error leaves the start unresolved; a nil or
// explicitly terminal result clears it under a bounded deadline even if the
// caller is canceled just after commit. A failed session is never no-effect
// evidence.
func (s *Store) WithRestoreActivity(ctx context.Context, tenantID, operationID, kind, lane string,
	fn func(context.Context) error,
) error {
	return s.withRestoreActivity(ctx, tenantID, operationID, kind, lane, "", fn)
}

// WithRestoreEventIngress commits a durable start tied to the normalized event
// ID after key-state preadmission and before broker publication. A full-restore
// owner uses the separate raw-artifact path while its marker remains armed.
func (s *Store) WithRestoreEventIngress(ctx context.Context, tenantID, eventID, eventType string,
	fn func(context.Context) error,
) error {
	if s == nil || eventID == "" || eventType == "" || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		// The raw-history capability authorizes exact artifact bytes only.
		// Ordinary Append/Import under that owner could publish unrelated
		// events while the target is still fenced and partially restored.
		return ErrRestoreInProgress
	}
	activityTenant := tenantID
	if _, err := uuid.Parse(activityTenant); err != nil {
		activityTenant = RestoreControlTenantID
	}
	if s.HasKeyStateSnapshotEvent(ctx) {
		return s.withRestoreActivity(ctx, activityTenant, uuid.NewString(), "ingress", "event-append", eventID,
			func(admitted context.Context) error {
				admitted = context.WithValue(admitted, restoreIngressEventTypeContextKey{}, eventType)
				admitted = context.WithValue(admitted, restoreIngressTenantScopeContextKey{}, tenantID)
				if err := s.requireKeyStateSnapshotEvent(admitted, tenantID, eventType); err != nil {
					return RestoreActivityNoEffect(err)
				}
				return fn(admitted)
			})
	}
	// Preserve the restore session -> key-state A -> key-state B order, but
	// create the durable ingress start only after A/B are held. A queued
	// exclusive rewrap must not wait on a token whose writer is waiting on it.
	return s.withRestoreActivitySession(ctx, func(session context.Context, lease *restoreActivityLease) error {
		return s.withRewrapEventIngress(session, tenantID, eventType, func(locked context.Context) error {
			return s.withRestoreActivityOnLease(locked, lease, activityTenant, uuid.NewString(),
				"ingress", "event-append", eventID, func(ingress context.Context) error {
					ingress = context.WithValue(ingress, restoreIngressEventTypeContextKey{}, eventType)
					ingress = context.WithValue(ingress, restoreIngressTenantScopeContextKey{}, tenantID)
					return s.withOwnerCommandProjectionActivity(ingress, lease, activityTenant, eventID, fn)
				})
		})
	})
}

// The second token spans a nested command's broker ACK and its SQL projection
// commit. The ingress token itself can finish at ACK; an owner rollback must
// leave this separate evidence started until canonical replay reconciles it.
func (s *Store) withOwnerCommandProjectionActivity(ctx context.Context, lease *restoreActivityLease,
	tenantID, eventID string, fn func(context.Context) error,
) error {
	owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner)
	if !ok {
		return fn(ctx)
	}
	if owner == nil || owner.store != s || owner.tenantID != tenantID || lease == nil || lease.origin != s {
		return ErrKeyStateOwnerUnavailable
	}
	owner.mu.Lock()
	if owner.projectionActivities == nil {
		owner.projectionActivities = make(map[string]string)
	}
	operationID, exists := owner.projectionActivities[eventID]
	if !exists {
		operationID = uuid.NewString()
		lease.mu.Lock()
		err := s.withRestoreActivityTokenTx(ctx, lease.conn, tenantID, operationID,
			"projection", "command-apply", eventID, false)
		lease.mu.Unlock()
		if err != nil {
			owner.mu.Unlock()
			return RestoreActivityNoEffect(err) // the publication callback has not run
		}
		owner.projectionActivities[eventID] = operationID
	}
	owner.mu.Unlock()
	callbackErr := fn(ctx)
	var noEffect *restoreActivityNoEffectError
	if !exists && errors.As(callbackErr, &noEffect) {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		lease.mu.Lock()
		settleErr := s.withRestoreActivityTokenTx(settleCtx, lease.conn, tenantID, operationID,
			"projection", "command-apply", eventID, true)
		lease.mu.Unlock()
		if settleErr != nil {
			return fmt.Errorf("store: settle proven no-publication command projection: %w", settleErr)
		}
		owner.mu.Lock()
		delete(owner.projectionActivities, eventID)
		owner.mu.Unlock()
	}
	return callbackErr
}

// The shared A session and distinct B transaction remain held across the
// broker ACK. Gate activation takes both exclusively before it changes a
// tenant's wrapper state, so an append is wholly before or after that change.
func (s *Store) withRewrapEventIngress(ctx context.Context, tenantID, eventType string,
	fn func(context.Context) error,
) error {
	mode := KeyStateShared
	if events.RequiresExclusiveKeyStateAdmission(eventType) {
		mode = KeyStateExclusive
	}
	if owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner); ok {
		if owner == nil || owner.store != s || owner.tenantID != tenantID {
			return ErrKeyStateOwnerUnavailable
		}
		if err := s.RequireKeyStateOwnerTx(ctx, owner.tx, tenantID, mode); err != nil {
			return err
		}
		if err := s.requireTenantEventGateOpenTx(ctx, owner.tx, tenantID); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return s.RequireKeyStateOwnerTx(ctx, owner.tx, tenantID, mode)
	}
	return s.WithGlobalKeyStateAdmission(ctx, mode, func(admitted context.Context) error {
		tx, err := s.begin(admitted)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := s.LockGlobalKeyStateCommitTx(admitted, tx, mode); err != nil {
			return err
		}
		if err := s.requireTenantEventGateOpenTx(admitted, tx, tenantID); err != nil {
			return err
		}
		if err := fn(admitted); err != nil {
			return err
		}
		if err := s.AssertGlobalKeyStateAdmissionAlive(admitted); err != nil {
			return err
		}
		return tx.Commit(admitted)
	})
}

func (s *Store) requireTenantEventGateOpenTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil // Non-UUID fixture identities cannot own a tenant gate row.
	}
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var armed bool
	err := tx.QueryRow(ctx, `SELECT rewrap_in_progress FROM application_secret_rewrap_gates
		WHERE tenant_id=$1`, tenantID).Scan(&armed)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if armed {
		return ErrApplicationSecretRewrapInProgress
	}
	return nil
}

// WithRestoreProjectionAdmission covers a direct projector's complete apply,
// including attached projections that run after the core tenant transaction.
func (s *Store) WithRestoreProjectionAdmission(ctx context.Context, tenantID, eventID string,
	fn func(context.Context) error,
) error {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		if err := s.requireRestoreOwnerRebuildScope(ctx); err != nil {
			return err
		}
		return fn(ctx)
	}
	if lease, ok := ctx.Value(restoreRebuildContextKey{}).(*restoreRebuildLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		return fn(ctx)
	}
	return s.withRestoreActivity(ctx, tenantID, uuid.NewString(), "projection", "direct-apply", eventID, fn)
}

// RequireRestoreProjectionTx is the transaction half for callers that own an
// ApplyTx transaction themselves. The shared commit lock survives until their
// commit, so a restore marker cannot slip between this check and the write.
func (s *Store) RequireRestoreProjectionTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if s == nil || tx == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		return s.requireRestoreOwnerRebuildScope(ctx)
	}
	if lease, ok := ctx.Value(restoreRebuildContextKey{}).(*restoreRebuildLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	present, err := s.restoreMarkerPresentTx(ctx, tx)
	if err != nil {
		return err
	}
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if present {
		return ErrRestoreInProgress
	}
	return nil
}

// SettleCommandProjectionTx records a nested command's exact event projection
// in the caller's transaction. A later rollback also rolls back this terminal
// phase, leaving the independently committed pre-ACK token for reconciliation.
func (s *Store) SettleCommandProjectionTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) error {
	owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner)
	if !ok || owner == nil || owner.store != s || owner.tx != tx || owner.tenantID != tenantID {
		return nil // no nested command projection token belongs to this transaction
	}
	owner.mu.Lock()
	operationID := owner.projectionActivities[eventID]
	owner.mu.Unlock()
	if operationID == "" {
		return nil
	}
	if err := s.RequireKeyStateOwnerTx(ctx, tx, tenantID, KeyStateShared); err != nil {
		return err
	}
	var originalRole string
	if err := tx.QueryRow(ctx, `SELECT current_role`).Scan(&originalRole); err != nil {
		return err
	}
	// Recovery tokens are owner-write only. Briefly switch this already proven
	// transaction to its session owner, then restore its exact original role.
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		return err
	}
	tag, updateErr := tx.Exec(ctx, `UPDATE trstctl_recovery.restore_activity_tokens
		SET phase='terminal',terminal_at=now()
		WHERE tenant_id=$1 AND operation_id=$2 AND activity_kind='projection'
		AND lane='command-apply' AND event_id=$3 AND phase='started'`, tenantID, operationID, eventID)
	_, roleErr := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{originalRole}.Sanitize())
	if roleErr != nil {
		return fmt.Errorf("store: restore caller role after command projection settlement: %w", roleErr)
	}
	if updateErr != nil {
		return updateErr
	}
	if tag.RowsAffected() != 1 {
		return ErrRestoreActivityUnresolved
	}
	return nil
}

// NeedsCanonicalCommandProjectionTx reports a durable second token that this
// exact transaction did not create. A new tail/recovery owner must compare the
// proposed Event with the retained log before it can write a read-model row.
// The current command owner may use its already returned broker Event.
func (s *Store) NeedsCanonicalCommandProjectionTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) (bool, error) {
	if s == nil || tx == nil {
		return false, ErrRestoreAdmissionLost
	}
	if eventID == "" {
		return false, nil // ingress refuses an empty ID, so no matching start can exist
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return false, nil
	}
	currentOperationID := uuid.Nil.String()
	if owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner); ok && owner != nil &&
		owner.store == s && owner.tx == tx && owner.tenantID == tenantID {
		owner.mu.Lock()
		if operationID := owner.projectionActivities[eventID]; operationID != "" {
			currentOperationID = operationID
		}
		owner.mu.Unlock()
	}
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return false, err
	}
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection'
		AND lane='command-apply' AND phase='started' AND operation_id<>$3)`,
		tenantID, eventID, currentOperationID).Scan(&pending)
	return pending, err
}

func (s *Store) requireRestoreOwnerRebuildScope(ctx context.Context) error {
	lease, ok := ctx.Value(restoreRebuildContextKey{}).(*restoreRebuildLease)
	if !ok || lease == nil || !lease.active.Load() || lease.origin != s {
		return ErrRestoreInProgress
	}
	return nil
}

// WithRestoreActivityAfterDrain is for the serving process after it has
// stopped its listener and joined every worker. That verified callback result
// may settle its lifetime token even though cancellation was how Run stopped;
// a callback error or lost PostgreSQL session still leaves the token unresolved.
func (s *Store) WithRestoreActivityAfterDrain(ctx context.Context, tenantID, operationID, kind, lane string,
	fn func(context.Context) error,
) error {
	return s.withRestoreActivity(ctx, tenantID, operationID, kind, lane, "", fn)
}

func (s *Store) withRestoreActivity(ctx context.Context, tenantID, operationID, kind, lane string,
	eventID string, fn func(context.Context) error,
) (retErr error) {
	if s == nil {
		return ErrRestoreAdmissionLost
	}
	if _, err := uuid.Parse(tenantID); err != nil ||
		operationID == "" || lane == "" || fn == nil {
		return errors.New("store: restore activity identity is incomplete")
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return errors.New("store: restore activity operation is invalid")
	}
	switch kind {
	case "request", "build", "worker", "maintenance", "backup", "effect", "ingress", "projection":
	default:
		return errors.New("store: restore activity kind is unclassified")
	}
	return s.withRestoreActivitySession(ctx, func(session context.Context, lease *restoreActivityLease) error {
		return s.withRestoreActivityOnLease(session, lease, tenantID, operationID,
			kind, lane, eventID, fn)
	})
}

// WithRestoreIngressSession holds the restore admission session while a caller
// acquires key-state A and the event history read wall. Nested ingress borrows
// the same session before it commits its exact activity start and opens B.
func (s *Store) WithRestoreIngressSession(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return ErrRestoreAdmissionLost
	}
	return s.withRestoreActivitySession(ctx, func(session context.Context, _ *restoreActivityLease) error {
		return fn(session)
	})
}

func (s *Store) withRestoreActivitySession(ctx context.Context,
	fn func(context.Context, *restoreActivityLease) error,
) (retErr error) {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if parent, ok := ctx.Value(restoreActivityContextKey{}).(*restoreActivityLease); ok {
		if parent == nil || parent.origin != s || !parent.active.Load() {
			return ErrRestoreAdmissionLost
		}
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		return fn(ctx, parent)
	}
	// The session grant spans both short token transactions and the caller's
	// action. A marker cannot commit while the action still holds this session.
	// The callback can acquire both a key-state lock session and a request or
	// reserved transaction. A separate bounded pool prevents concurrent outer
	// restore sessions from consuming either of those nested resources.
	sessionPool := s.restorePool
	if sessionPool == nil {
		return ErrRestoreAdmissionLost
	}
	conn, err := sessionPool.Acquire(ctx)
	if err != nil {
		return err
	}
	if err := acquireHistoryRewriteLock(ctx, conn, restoreAdmissionSessionKey, true); err != nil {
		_ = discardHistoryRewriteSession(conn)
		return err
	}
	defer func() {
		if err := releaseHistoryRewriteLock(conn, restoreAdmissionSessionKey, true); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("store: release restore activity admission: %w", err), discardHistoryRewriteSession(conn))
		} else {
			conn.Release()
		}
	}()
	lease := &restoreActivityLease{origin: s, conn: conn}
	lease.active.Store(true)
	defer lease.active.Store(false)
	return fn(context.WithValue(ctx, restoreActivityContextKey{}, lease), lease)
}

func (s *Store) withRestoreActivityOnLease(ctx context.Context, lease *restoreActivityLease,
	tenantID, operationID, kind, lane, eventID string,
	fn func(context.Context) error,
) error {
	if lease == nil || lease.origin != s || !lease.active.Load() {
		return ErrRestoreAdmissionLost
	}
	lease.mu.Lock()
	if !lease.active.Load() {
		lease.mu.Unlock()
		return ErrRestoreAdmissionLost
	}
	err := s.withRestoreActivityTokenTx(ctx, lease.conn, tenantID, operationID, kind, lane, eventID, false)
	lease.mu.Unlock()
	if err != nil {
		return err
	}
	token := &restoreActivityToken{origin: s, lease: lease, tenantID: tenantID,
		operationID: operationID, kind: kind, lane: lane, eventID: eventID}
	token.active.Store(true)
	defer token.active.Store(false)
	callbackErr := fn(context.WithValue(ctx, restoreActivityTokenContextKey{}, token))
	var noEffect *restoreActivityNoEffectError
	var terminal *restoreActivityTerminalError
	if callbackErr != nil && !errors.As(callbackErr, &noEffect) && !errors.As(callbackErr, &terminal) {
		return callbackErr
	}
	// A nil callback means its effect committed. Cancellation between that
	// commit and token settlement cannot undo it, so finish the exact token
	// under a short independent deadline. Errors without terminal/no-effect
	// proof returned above still leave the durable start unresolved.
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.active.Load() {
		return ErrRestoreAdmissionLost
	}
	if err := s.withRestoreActivityTokenTx(settleCtx, lease.conn, tenantID, operationID, kind, lane, eventID, true); err != nil {
		return errors.Join(callbackErr, err)
	}
	if noEffect != nil {
		return noEffect.cause
	}
	if terminal != nil {
		return terminal.cause
	}
	return nil
}

func (s *Store) withRestoreActivityTokenTx(ctx context.Context, conn *pgxpool.Conn,
	tenantID, operationID, kind, lane, eventID string, terminal bool,
) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	if !terminal {
		present, err := s.restoreMarkerPresentTx(ctx, tx)
		if err != nil {
			return err
		}
		if present {
			return ErrRestoreInProgress
		}
	}
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if terminal {
		tag, err := tx.Exec(ctx, `UPDATE trstctl_recovery.restore_activity_tokens
			SET phase='terminal',terminal_at=now()
			WHERE tenant_id=$1 AND operation_id=$2 AND activity_kind=$3 AND lane=$4 AND event_id=$5 AND phase='started'`,
			tenantID, operationID, kind, lane, eventID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRestoreActivityUnresolved
		}
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.restore_activity_tokens
			(tenant_id,operation_id,activity_kind,lane,event_id) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, operationID, kind, lane, eventID); err != nil {
			return fmt.Errorf("%w: %v", ErrRestoreActivityUnresolved, err)
		}
	}
	if _, err := conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	return tx.Commit(ctx)
}

// BeginFullRestore commits a destination-local marker only after every active
// session has drained and no ambiguous durable activity start remains. A same
// artifact/target may resume; a different artifact cannot replace its marker.
func (s *Store) BeginFullRestore(ctx context.Context, marker RestoreMarker) error {
	if err := validateRestoreMarker(marker); err != nil {
		return err
	}
	return s.withRestoreAdmission(ctx, true, func(ctx context.Context, tx pgx.Tx) error {
		// A system role must see all tenant partitions. On a role without RLS
		// bypass PostgreSQL refuses this query rather than silently omitting rows.
		if _, err := tx.Exec(ctx, `SET LOCAL row_security = off`); err != nil {
			return err
		}
		var unresolved bool
		//trstctl:system-query — owner-only restore fence checks one cross-tenant pending-activity boolean after disabling incomplete RLS reads.
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_activity_tokens
			WHERE phase='started')`).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved {
			return ErrRestoreActivityUnresolved
		}
		if err := s.requireNoPendingEventIngressTx(ctx, tx); err != nil {
			return err
		}
		if err := s.requireNoArmedRewrapGatesTx(ctx, tx); err != nil {
			return err
		}
		if err := s.requireRestoreRemoteQuiescentTx(ctx, tx); err != nil {
			return err
		}
		if err := s.SetTenantGUCTx(ctx, tx, RestoreControlTenantID); err != nil {
			return err
		}
		var existing RestoreMarker
		err := tx.QueryRow(ctx, `SELECT operation_id::text,artifact_sha256,
			COALESCE(event_history_sha256,''),event_cut,deployment_id
			FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 FOR UPDATE`, RestoreControlTenantID).
			Scan(&existing.OperationID, &existing.ArtifactSHA256, &existing.EventHistorySHA256,
				&existing.EventCut, &existing.DeploymentID)
		if err == nil {
			if existing != marker {
				return ErrRestoreInProgress
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO trstctl_recovery.restore_markers
			(tenant_id,operation_id,artifact_sha256,event_history_sha256,event_cut,deployment_id,phase)
			VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,'prepared')`, RestoreControlTenantID,
			marker.OperationID, marker.ArtifactSHA256, marker.EventHistorySHA256,
			marker.EventCut, marker.DeploymentID)
		return err
	})
}

// WithFullRestoreOwner holds exclusive deployment admission through one exact
// restore phase. It prevents another same-artifact resume from running a phase
// concurrently and refuses an absent or different committed marker.
func (s *Store) WithFullRestoreOwner(ctx context.Context, marker RestoreMarker,
	fn func(context.Context) error,
) (retErr error) {
	if err := validateRestoreMarker(marker); err != nil {
		return err
	}
	if fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.marker != marker || lease.origin != s {
			return ErrRestoreInProgress
		}
		return fn(ctx)
	}
	conn, err := s.lockSessionPool(ctx).Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire full restore owner session: %w", err)
	}
	if err := acquireHistoryRewriteLock(ctx, conn, restoreAdmissionSessionKey, false); err != nil {
		_ = discardHistoryRewriteSession(conn)
		return fmt.Errorf("store: acquire full restore owner admission: %w", err)
	}
	defer func() {
		if err := releaseHistoryRewriteLock(conn, restoreAdmissionSessionKey, false); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("store: release full restore owner: %w", err), discardHistoryRewriteSession(conn))
			return
		}
		conn.Release()
	}()
	// The distinct B lock and row check are short. Keeping this transaction
	// open across ordinary migrations would block their schema locks; the
	// exclusive session A continues to serialize the whole restore phase.
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	if _, err := s.lockedRestoreMarkerTx(ctx, tx, marker); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	lease := &restoreOwnerLease{marker: marker, origin: s}
	lease.active.Store(true)
	defer lease.active.Store(false)
	if err := fn(context.WithValue(ctx, restoreOwnerContextKey{}, lease)); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	return nil
}

// RequireFullRestoreHistoryOwner refuses direct raw event-history writes. The
// active lease was checked against the committed target marker when it was
// created; a different event cut or raw event artifact cannot borrow it.
func (s *Store) RequireFullRestoreHistoryOwner(ctx context.Context, eventCut uint64, eventHistorySHA256 string) error {
	if s == nil {
		return ErrRestoreAdmissionLost
	}
	lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease)
	if !ok || lease == nil || lease.origin != s || !lease.active.Load() ||
		lease.marker.EventCut != eventCut || lease.marker.EventHistorySHA256 == "" ||
		lease.marker.EventHistorySHA256 != eventHistorySHA256 {
		return ErrRestoreInProgress
	}
	return nil
}

// RequireFullRestoreImportOwner permits deferred sealed-pair proof only for the
// exact live, artifact-bound full restore. The generic PostgreSQL importer has
// no such lease and must keep its original exact-byte comparison.
func (s *Store) RequireFullRestoreImportOwner(ctx context.Context, marker RestoreMarker) error {
	if s == nil || validateRestoreMarker(marker) != nil || ctx.Err() != nil {
		return ErrRestoreInProgress
	}
	lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease)
	if !ok || lease == nil || lease.origin != s || !lease.active.Load() || lease.marker != marker {
		return ErrRestoreInProgress
	}
	return nil
}

// WithRestoreRebuildAdmission is the only restore-owner bypass for an atomic
// read-model rebuild. A normal direct rebuild commits a durable maintenance
// start before its history read or TRUNCATE; a full restore borrows its live
// exact-artifact owner session instead of admitting an ordinary writer.
func (s *Store) WithRestoreRebuildAdmission(ctx context.Context, fn func(context.Context) error) error {
	return s.withRestoreProjectionMaintenance(ctx, "read-model-rebuild", fn)
}

// WithRestoreCatchUpAdmission covers a direct catch-up from history preflight
// through its final projection checkpoint and attached projection commit.
func (s *Store) WithRestoreCatchUpAdmission(ctx context.Context, fn func(context.Context) error) error {
	return s.withRestoreProjectionMaintenance(ctx, "read-model-catch-up", fn)
}

// WithRestoreSnapshotAdmission covers both snapshot replay and its fallback
// rebuild before any snapshot/history preflight starts.
func (s *Store) WithRestoreSnapshotAdmission(ctx context.Context, fn func(context.Context) error) error {
	return s.withRestoreProjectionMaintenance(ctx, "snapshot-restore", fn)
}

func (s *Store) withRestoreProjectionMaintenance(ctx context.Context, lane string, fn func(context.Context) error) error {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		rebuild := &restoreRebuildLease{origin: s}
		rebuild.active.Store(true)
		defer rebuild.active.Store(false)
		return fn(context.WithValue(ctx, restoreRebuildContextKey{}, rebuild))
	}
	if lease, ok := ctx.Value(restoreRebuildContextKey{}).(*restoreRebuildLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		return fn(ctx)
	}
	return s.WithRestoreActivity(ctx, RestoreControlTenantID, uuid.NewString(),
		"projection", lane, func(admitted context.Context) error {
			lease := &restoreRebuildLease{origin: s}
			lease.active.Store(true)
			defer lease.active.Store(false)
			return fn(context.WithValue(admitted, restoreRebuildContextKey{}, lease))
		})
}

// WithRestoreImportAdmission prevents a direct PostgreSQL-state import from
// bypassing a committed full-restore marker. Only the exact live restore owner
// may import under that marker; other callers hold a durable maintenance token
// across artifact verification and the final database commit.
func (s *Store) WithRestoreImportAdmission(ctx context.Context, fn func(context.Context) error) error {
	return s.withRestoreMaintenanceAdmission(ctx, "postgres-state-import", fn)
}

// WithRestoreRawHistoryAdmission protects the event-log library's direct raw
// history restore path, including its stream binding and gap writes.
func (s *Store) WithRestoreRawHistoryAdmission(ctx context.Context, fn func(context.Context) error) error {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreRawHistoryContextKey{}).(*restoreRawHistoryLease); ok {
		if lease == nil || lease.origin != s || !lease.active.Load() || ctx.Err() != nil {
			return ErrRestoreAdmissionLost
		}
		if err := s.AssertGlobalKeyStateAdmissionAlive(ctx); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return s.AssertGlobalKeyStateAdmissionAlive(ctx)
	}
	return s.withRestoreMaintenanceAdmission(ctx, "raw-history-restore", func(restored context.Context) error {
		return s.WithGlobalKeyStateAdmission(restored, KeyStateShared, func(admitted context.Context) error {
			tx, err := s.begin(admitted)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := s.LockGlobalKeyStateCommitTx(admitted, tx, KeyStateShared); err != nil {
				return err
			}
			lease := &restoreRawHistoryLease{origin: s}
			lease.active.Store(true)
			defer lease.active.Store(false)
			if err := fn(context.WithValue(admitted, restoreRawHistoryContextKey{}, lease)); err != nil {
				return err
			}
			if err := s.AssertGlobalKeyStateAdmissionAlive(admitted); err != nil {
				return err
			}
			return tx.Commit(admitted)
		})
	})
}

func (s *Store) withRestoreMaintenanceAdmission(ctx context.Context, lane string, fn func(context.Context) error) error {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	if lease, ok := ctx.Value(restoreOwnerContextKey{}).(*restoreOwnerLease); ok {
		if !lease.active.Load() || lease.origin != s {
			return ErrRestoreAdmissionLost
		}
		return fn(ctx)
	}
	if err := s.BootstrapRestoreAdmission(ctx); err != nil {
		return err
	}
	return s.WithRestoreActivity(ctx, RestoreControlTenantID, uuid.NewString(),
		"maintenance", lane, fn)
}

var restorePhaseOrder = []string{
	"prepared", "artifacts_restored", "event_partial", "postgres_imported", "pair_verified", "final_rebuild",
}

func restorePhaseIndex(phase string) int {
	for index, candidate := range restorePhaseOrder {
		if phase == candidate {
			return index
		}
	}
	return -1
}

func (s *Store) lockedRestoreMarkerTx(ctx context.Context, tx pgx.Tx, marker RestoreMarker) (string, error) {
	if err := s.SetTenantGUCTx(ctx, tx, RestoreControlTenantID); err != nil {
		return "", err
	}
	var existing RestoreMarker
	var phase string
	err := tx.QueryRow(ctx, `SELECT operation_id::text,artifact_sha256,
		COALESCE(event_history_sha256,''),event_cut,deployment_id,phase
		FROM trstctl_recovery.restore_markers WHERE tenant_id=$1 FOR UPDATE`, RestoreControlTenantID).
		Scan(&existing.OperationID, &existing.ArtifactSHA256, &existing.EventHistorySHA256,
			&existing.EventCut, &existing.DeploymentID, &phase)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRestoreInProgress
	}
	if err != nil {
		return "", err
	}
	if existing != marker {
		return "", ErrRestoreInProgress
	}
	return phase, nil
}

// AdvanceFullRestore records only the next verified phase of the same exact
// artifact and target. A caller cannot skip directly to final clearance.
func (s *Store) AdvanceFullRestore(ctx context.Context, marker RestoreMarker, next string) error {
	if err := validateRestoreMarker(marker); err != nil {
		return err
	}
	nextIndex := restorePhaseIndex(next)
	if nextIndex <= 0 {
		return ErrRestoreIncomplete
	}
	return s.withRestoreAdmission(ctx, true, func(ctx context.Context, tx pgx.Tx) error {
		current, err := s.lockedRestoreMarkerTx(ctx, tx, marker)
		if err != nil {
			return err
		}
		if next == "pair_verified" {
			if _, err := tx.Exec(ctx, `SET LOCAL row_security = off`); err != nil {
				return err
			}
			var unresolved bool
			//trstctl:system-query — system restore checks cross-tenant unresolved pairs for this exact operation before advancing its target-local marker; it returns only a Boolean.
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_outbox_pairs
				WHERE operation_id=$1)`, marker.OperationID).Scan(&unresolved); err != nil {
				return err
			}
			if unresolved {
				return ErrRecoveryPairProofMismatch
			}
		}
		currentIndex := restorePhaseIndex(current)
		if currentIndex == nextIndex {
			return nil // exact phase retry after its artifact checks repeated
		}
		if currentIndex+1 != nextIndex {
			return ErrRestoreIncomplete
		}
		_, err = tx.Exec(ctx, `UPDATE trstctl_recovery.restore_markers
			SET phase=$1,updated_at=now() WHERE tenant_id=$2 AND operation_id=$3 AND phase=$4`,
			next, RestoreControlTenantID, marker.OperationID, current)
		return err
	})
}

// FinishFullRestore removes the target fence only after the final verified
// phase and after all independent activity starts have terminal evidence.
func (s *Store) FinishFullRestore(ctx context.Context, marker RestoreMarker) error {
	if err := validateRestoreMarker(marker); err != nil {
		return err
	}
	return s.withRestoreAdmission(ctx, true, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL row_security = off`); err != nil {
			return err
		}
		var unresolved bool
		//trstctl:system-query — owner-only restore fence checks one cross-tenant pending-activity boolean after disabling incomplete RLS reads.
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_activity_tokens
			WHERE phase='started')`).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved {
			return ErrRestoreActivityUnresolved
		}
		if err := s.requireNoPendingEventIngressTx(ctx, tx); err != nil {
			return err
		}
		if err := s.requireNoArmedRewrapGatesTx(ctx, tx); err != nil {
			return err
		}
		if err := s.requireRestoreRemoteQuiescentTx(ctx, tx); err != nil {
			return err
		}
		phase, err := s.lockedRestoreMarkerTx(ctx, tx, marker)
		if err != nil {
			return err
		}
		if phase != "final_rebuild" {
			return ErrRestoreIncomplete
		}
		//trstctl:system-query — system restore checks cross-tenant raw broker starts for this exact artifact-bound operation before unfencing; it returns only a Boolean.
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.raw_history_journal
			WHERE operation_id=$1 AND phase='started')`, marker.OperationID).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved {
			return ErrRestoreIncomplete
		}
		//trstctl:system-query — system restore checks cross-tenant pair starts for this exact artifact-bound operation before unfencing; it returns only a Boolean.
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_outbox_pairs
			WHERE operation_id=$1)`, marker.OperationID).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved {
			return ErrRecoveryPairProofMismatch
		}
		tag, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.restore_markers
			WHERE tenant_id=$1 AND operation_id=$2 AND artifact_sha256=$3 AND event_cut=$4
			AND deployment_id=$5 AND phase='final_rebuild'`,
			RestoreControlTenantID, marker.OperationID, marker.ArtifactSHA256, marker.EventCut, marker.DeploymentID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRestoreInProgress
		}
		return nil
	})
}

// The ingress activity may already be terminal while its separate broker
// evidence is still ambiguous. Only a verified publication, duplicate or
// proven no-publication outcome lets the target proceed toward restore.
func (s *Store) requireNoPendingEventIngressTx(ctx context.Context, tx pgx.Tx) error {
	var unresolved bool
	//trstctl:system-query — cross-tenant system restore under exclusive admission checks only a Boolean for unfinished ingress; no tenant payload is returned.
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.event_ingress_journal
		WHERE phase IN ('started','candidate_staged'))`).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return ErrRestoreActivityUnresolved
	}
	return nil
}
