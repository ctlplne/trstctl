// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

const (
	PrivacyRecoveryFenceApplicationSecret = "application_secret"
	PrivacyRecoveryFenceApprovedTarget    = "approved_target"

	PrivacyRecoveryFenceDeleted       = "deleted"
	PrivacyRecoveryFencePseudonymized = "pseudonymized"
)

// ErrPrivacySubjectErasurePreparationActive means a tenant has already crossed
// the PostgreSQL half of privacy erasure but has not yet projected its canonical
// privacy.subject.erased event. Recovery publication and read-model replacement
// fail closed until the exact operation resumes.
var ErrPrivacySubjectErasurePreparationActive = errors.New("store: privacy subject erasure preparation is active")

// ErrPrivacyHistoryOperationActive means a direct transaction tried to enter a
// tenant lifecycle erase while an exclusive privacy history operation was
// already running. The direct path fails fast to preserve the global
// privacy-operation -> history-cutover -> backup -> tenant-lifecycle lock order.
var ErrPrivacyHistoryOperationActive = errors.New("store: privacy history operation is active")

type privacyReadModelBarrierContextKey struct{}

// privacyReadModelBarrierLease makes the shared history-operation grant safely
// re-entrant for layered public APIs such as Projector.Snapshot -> Store snapshot
// capture. Revocation waits for an already-entered nested user, so an escaped
// callback context cannot keep using the grant after PostgreSQL releases it.
type privacyReadModelBarrierLease struct {
	store     *Store
	mu        sync.Mutex
	condition *sync.Cond
	active    bool
	users     int
}

func newPrivacyReadModelBarrierLease(s *Store) *privacyReadModelBarrierLease {
	lease := &privacyReadModelBarrierLease{store: s, active: true}
	lease.condition = sync.NewCond(&lease.mu)
	return lease
}

func (l *privacyReadModelBarrierLease) acquire(s *Store) bool {
	if l == nil || l.store != s {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active {
		return false
	}
	l.users++
	return true
}

func (l *privacyReadModelBarrierLease) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.users--
	if l.users == 0 {
		l.condition.Broadcast()
	}
}

func (l *privacyReadModelBarrierLease) revokeAndWait() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = false
	for l.users > 0 {
		l.condition.Wait()
	}
}

// PrivacyRecoveryFenceDisposition records what preparation did to one durable
// append-recovery command. It contains only the immutable event ID and bounded
// class/disposition labels, never command data or the raw erased subject.
type PrivacyRecoveryFenceDisposition struct {
	Kind        string `json:"kind"`
	EventID     string `json:"event_id"`
	Disposition string `json:"disposition"`
}

// ValidatePrivacyRecoveryFenceDispositionsV3 accepts only the two recovery
// receiver classes, their two closed dispositions, and UUID event identities.
// No payload, semantic digest, subject spelling, or arbitrary map key can enter
// canonical privacy history through this evidence field.
func ValidatePrivacyRecoveryFenceDispositionsV3(
	fences []PrivacyRecoveryFenceDisposition,
) error {
	if len(fences) > 100000 {
		return errors.New("store: privacy recovery fence evidence exceeds its bounded maximum")
	}
	seen := make(map[string]struct{}, len(fences))
	for _, fence := range fences {
		if fence.Kind != PrivacyRecoveryFenceApplicationSecret &&
			fence.Kind != PrivacyRecoveryFenceApprovedTarget {
			return fmt.Errorf("store: privacy recovery fence kind %q is unsupported", fence.Kind)
		}
		if fence.Disposition != PrivacyRecoveryFenceDeleted &&
			fence.Disposition != PrivacyRecoveryFencePseudonymized {
			return fmt.Errorf("store: privacy recovery fence disposition %q is unsupported", fence.Disposition)
		}
		parsedEventID, err := uuid.Parse(fence.EventID)
		if err != nil || parsedEventID.String() != fence.EventID {
			return errors.New("store: privacy recovery fence event id is not a UUID")
		}
		key := fence.Kind + "\x00" + fence.EventID
		if _, duplicate := seen[key]; duplicate {
			return errors.New("store: privacy recovery fence evidence contains a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// PrivacySubjectErasurePreparation is the independent, non-PII crash bridge
// between the PostgreSQL privacy fence rewrite and JetStream generation cutover.
// Its selectors and event metadata are the exact first-attempt snapshot reused by
// every retry; completion removes it only beside the projected operation row.
type PrivacySubjectErasurePreparation struct {
	PrivacySubjectErasure
	OperationID           string
	RequestBinding        string
	EventID               string
	RewriteOperationID    string
	TargetGeneration      string
	EventActor            *events.Actor
	RecoveryFences        []PrivacyRecoveryFenceDisposition
	SchedulerDispositions []SecretRotationSchedulePrivacyDisposition
	CreatedAt             time.Time
}

// #nosec G101 -- SQL column identifiers only; this constant contains no credential material.
const privacySubjectErasurePreparationColumns = `
	tenant_id::text, operation_id, request_binding, event_id,
	rewrite_operation_id, target_generation, subject_ref,
	requested_by_ref, reason, selectors, counts, event_actor, recovery_fences,
	scheduler_dispositions,
	erased_at, created_at`

func scanPrivacySubjectErasurePreparation(row pgx.Row) (PrivacySubjectErasurePreparation, error) {
	var (
		out                                        PrivacySubjectErasurePreparation
		selectors, counts, actor, fence, scheduler []byte
	)
	if err := row.Scan(&out.TenantID, &out.OperationID, &out.RequestBinding,
		&out.EventID, &out.RewriteOperationID, &out.TargetGeneration,
		&out.SubjectRef, &out.RequestedByRef, &out.Reason,
		&selectors, &counts, &actor, &fence, &scheduler,
		&out.ErasedAt, &out.CreatedAt); err != nil {
		return PrivacySubjectErasurePreparation{}, err
	}
	out.ErasedAt = out.ErasedAt.UTC()
	out.CreatedAt = out.CreatedAt.UTC()
	if err := json.Unmarshal(selectors, &out.Selectors); err != nil {
		return PrivacySubjectErasurePreparation{}, fmt.Errorf("store: decode privacy preparation selectors: %w", err)
	}
	if err := json.Unmarshal(counts, &out.Counts); err != nil {
		return PrivacySubjectErasurePreparation{}, fmt.Errorf("store: decode privacy preparation counts: %w", err)
	}
	if len(actor) != 0 {
		if err := json.Unmarshal(actor, &out.EventActor); err != nil {
			return PrivacySubjectErasurePreparation{}, fmt.Errorf("store: decode privacy preparation actor: %w", err)
		}
	}
	if err := json.Unmarshal(fence, &out.RecoveryFences); err != nil {
		return PrivacySubjectErasurePreparation{}, fmt.Errorf("store: decode privacy preparation recovery fences: %w", err)
	}
	if err := json.Unmarshal(scheduler, &out.SchedulerDispositions); err != nil {
		return PrivacySubjectErasurePreparation{}, fmt.Errorf("store: decode privacy preparation scheduler dispositions: %w", err)
	}
	if out.Counts == nil {
		out.Counts = map[string]int{}
	}
	if out.RecoveryFences == nil {
		out.RecoveryFences = []PrivacyRecoveryFenceDisposition{}
	}
	if out.SchedulerDispositions == nil {
		out.SchedulerDispositions = []SecretRotationSchedulePrivacyDisposition{}
	}
	if err := ValidateSecretRotationSchedulePrivacyEvidenceV3(
		out.Counts, out.SchedulerDispositions,
	); err != nil {
		return PrivacySubjectErasurePreparation{}, fmt.Errorf(
			"store: validate prepared scheduler privacy evidence: %w", err,
		)
	}
	return out, nil
}

// PreparePrivacySubjectErasure runs inside the caller's deployment-wide
// exclusive history-operation lease. On the first attempt it snapshots selectors
// before changing any row, then atomically pseudonymizes/revokes SQL approval
// authority and removes or rewrites every affected append-recovery fence. A retry
// returns the stored snapshot without selecting already-rewritten rows again.
func (s *Store) PreparePrivacySubjectErasure(
	ctx context.Context,
	tenantID, subject string,
	candidate PrivacySubjectErasurePreparation,
) (PrivacySubjectErasurePreparation, error) {
	return s.PreparePrivacySubjectErasureWithSchedulerResolver(
		ctx, tenantID, subject, candidate, nil,
	)
}

// PreparePrivacySubjectErasureWithSchedulerResolver is the production privacy
// preparation entrypoint. The resolver is invoked only when a selected scheduler
// tick requires its generic idempotency key or protected terminal response to be
// rewritten; that acknowledgment and all scheduler closures occur in this same
// SQL transaction before the canonical crash marker is inserted.
func (s *Store) PreparePrivacySubjectErasureWithSchedulerResolver(
	ctx context.Context,
	tenantID, subject string,
	candidate PrivacySubjectErasurePreparation,
	resolveSchedulerOuter SecretRotationSchedulePrivacyOuterResolver,
	resolveCertificateMetadata ...func(context.Context, pgx.Tx) error,
) (PrivacySubjectErasurePreparation, error) {
	if len(resolveCertificateMetadata) > 1 {
		return PrivacySubjectErasurePreparation{}, errors.New("store: privacy preparation accepts one certificate metadata resolver")
	}
	if tenantID == "" {
		return PrivacySubjectErasurePreparation{}, errors.New("store: privacy erasure preparation requires tenant id (AN-1)")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return PrivacySubjectErasurePreparation{}, errors.New("store: privacy erasure preparation requires subject")
	}
	expectedRef := privacy.SubjectRef(tenantID, subject)
	if candidate.TenantID != tenantID || candidate.SubjectRef != expectedRef ||
		candidate.OperationID == "" || candidate.RequestBinding == "" || candidate.EventID == "" ||
		candidate.RewriteOperationID == "" || candidate.TargetGeneration == "" ||
		candidate.ErasedAt.IsZero() {
		return PrivacySubjectErasurePreparation{}, errors.New("store: privacy erasure preparation identity is incomplete")
	}
	// This time becomes both PostgreSQL crash-bridge state and canonical event
	// time. Strip precision PostgreSQL cannot preserve before either copy exists.
	candidate.ErasedAt = candidate.ErasedAt.UTC().Truncate(time.Microsecond)
	for _, metadata := range []string{
		candidate.OperationID, candidate.RequestBinding, candidate.EventID,
		candidate.RewriteOperationID, candidate.TargetGeneration,
		candidate.RequestedByRef, candidate.Reason,
	} {
		if strings.Contains(metadata, subject) {
			return PrivacySubjectErasurePreparation{}, errors.New("store: privacy erasure preparation metadata contains raw subject")
		}
	}
	if err := validatePrivacyPreparationActor(tenantID, subject, candidate.EventActor); err != nil {
		return PrivacySubjectErasurePreparation{}, err
	}

	var canonical PrivacySubjectErasurePreparation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Serialize commands for one subject before inspecting an existing row. The
		// unique subject_ref constraint is the final guard; this lock gives callers
		// a deterministic conflict instead of doing work that later rolls back.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"privacy-subject-erasure-preparation\x1f"+tenantID+"\x1f"+expectedRef); err != nil {
			return fmt.Errorf("store: lock privacy erasure preparation: %w", err)
		}
		existing, err := scanPrivacySubjectErasurePreparation(tx.QueryRow(ctx,
			`SELECT `+privacySubjectErasurePreparationColumns+`
			   FROM privacy_subject_erasure_preparations
			  WHERE tenant_id = $1 AND subject_ref = $2
			  FOR UPDATE`, tenantID, expectedRef))
		if err == nil {
			if existing.OperationID != candidate.OperationID ||
				existing.RequestBinding != candidate.RequestBinding || existing.EventID != candidate.EventID ||
				existing.RewriteOperationID != candidate.RewriteOperationID ||
				existing.TargetGeneration != candidate.TargetGeneration {
				return fmt.Errorf("%w: subject already has another privacy erasure preparation", ErrIdempotencyConflict)
			}
			canonical = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var collision bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM privacy_subject_erasure_preparations
			 WHERE tenant_id = $1 AND (operation_id = $2 OR event_id = $3)
		)`, tenantID, candidate.OperationID, candidate.EventID).Scan(&collision); err != nil {
			return err
		}
		if collision {
			return fmt.Errorf("%w: privacy erasure operation identity is already prepared", ErrIdempotencyConflict)
		}
		// The signed target is staged before this transaction. Rebind only
		// already-completed certificate events while their actual old source is
		// frozen, atomically with the crash marker below. A standalone caller
		// cannot silently leave stale digests for a later canonical replay.
		if len(resolveCertificateMetadata) == 1 && resolveCertificateMetadata[0] != nil {
			if err := resolveCertificateMetadata[0](ctx, tx); err != nil {
				return err
			}
		} else {
			var existingReceipts bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_metadata_receipts WHERE tenant_id=$1)`, tenantID).Scan(&existingReceipts); err != nil {
				return err
			}
			if existingReceipts {
				return errors.New("store: privacy preparation requires the frozen-source certificate metadata resolver")
			}
		}

		var selected PrivacySubjectErasure
		if err := s.selectPrivacySubjectErasureTx(ctx, tx, tenantID, subject, &selected); err != nil {
			return err
		}
		if err := ValidatePrivacyErasureSelectorsV3(selected.Selectors); err != nil {
			return fmt.Errorf("store: validate non-PII privacy preparation selectors: %w", err)
		}
		selected.RequestedByRef = candidate.RequestedByRef
		selected.Reason = candidate.Reason
		selected.ErasedAt = candidate.ErasedAt.UTC()
		// A read-model snapshot is a physical JSON copy of this tenant's rows.
		// Delete it in this exact SQL preparation transaction, before the durable
		// marker is inserted, so a commit can never preserve the old blob while
		// claiming a successful erasure. The zero-or-one count is non-PII evidence
		// and is frozen in the preparation for every retry.
		snapshotRowsDeleted, err := deleteTenantSnapshotTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		selected.Counts["read_model_snapshots"] = snapshotRowsDeleted

		// These exact request/decision IDs were captured above. Rewrite them now,
		// while the raw subject is still transiently available, so a crash cannot
		// leave reusable warm authority and a later cold replay converges with the
		// already-rewritten source history.
		if err := pseudonymizePreparedOperationApprovalsTx(ctx, tx, tenantID,
			expectedRef, selected.Selectors.ReadModels); err != nil {
			return err
		}
		if err := pseudonymizeLegacyCodeSigningOperationKeysTx(
			ctx, tx, tenantID, selected.Selectors.CodeSigningOperationIDs,
		); err != nil {
			return err
		}
		applicationFences, err := s.prepareApplicationSecretRecoveryFencesTx(
			ctx, tx, tenantID, subject, expectedRef)
		if err != nil {
			return err
		}
		approvedFences, err := s.prepareApprovedTargetRecoveryFencesTx(ctx, tx, tenantID, subject)
		if err != nil {
			return err
		}
		recoveryFences := append(applicationFences, approvedFences...)
		sort.Slice(recoveryFences, func(i, j int) bool {
			if recoveryFences[i].Kind == recoveryFences[j].Kind {
				return recoveryFences[i].EventID < recoveryFences[j].EventID
			}
			return recoveryFences[i].Kind < recoveryFences[j].Kind
		})
		if err := ValidatePrivacyRecoveryFenceDispositionsV3(recoveryFences); err != nil {
			return fmt.Errorf("store: validate non-PII privacy recovery evidence: %w", err)
		}
		selected.Counts["application_secret_mutation_fences"] = countPrivacyRecoveryFences(
			recoveryFences, PrivacyRecoveryFenceApplicationSecret)
		selected.Counts["approved_target_event_fences"] = countPrivacyRecoveryFences(
			recoveryFences, PrivacyRecoveryFenceApprovedTarget)
		scheduler, err := s.PrepareSecretRotationSchedulePrivacyErasureTx(
			ctx, tx, tenantID, subject, expectedRef,
			candidate.OperationID, candidate.EventID, resolveSchedulerOuter,
		)
		if err != nil {
			return fmt.Errorf("store: prepare scheduler privacy receivers: %w", err)
		}
		selected.Counts["secret_rotation_schedule_ticks"] = scheduler.Ticks
		selected.Counts["secret_rotation_schedule_tick_rows"] = scheduler.TickRows
		selected.Counts["secret_rotation_schedule_commands"] = scheduler.Commands
		selected.Counts["secret_rotation_schedule_outer_resolutions"] = scheduler.OuterResolutions
		if err := ValidateSecretRotationSchedulePrivacyEvidenceV3(
			selected.Counts, scheduler.Dispositions,
		); err != nil {
			return fmt.Errorf("store: validate scheduler privacy evidence: %w", err)
		}
		if err := ValidatePrivacyErasureCountsV3(selected.Counts); err != nil {
			return fmt.Errorf("store: validate bounded privacy preparation counts: %w", err)
		}

		selectorsJSON, err := json.Marshal(selected.Selectors)
		if err != nil {
			return err
		}
		countsJSON, err := json.Marshal(selected.Counts)
		if err != nil {
			return err
		}
		fencesJSON, err := json.Marshal(recoveryFences)
		if err != nil {
			return err
		}
		schedulerJSON, err := json.Marshal(scheduler.Dispositions)
		if err != nil {
			return err
		}
		var actorJSON any
		if candidate.EventActor != nil {
			raw, err := json.Marshal(candidate.EventActor)
			if err != nil {
				return err
			}
			actorJSON = string(raw)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO privacy_subject_erasure_preparations
			(tenant_id, operation_id, request_binding, event_id,
			 rewrite_operation_id, target_generation, subject_ref,
			 requested_by_ref, reason, selectors, counts, event_actor, recovery_fences,
			 scheduler_dispositions, erased_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb,
			        $12::jsonb, $13::jsonb, $14::jsonb, $15)`,
			tenantID, candidate.OperationID, candidate.RequestBinding, candidate.EventID,
			candidate.RewriteOperationID, candidate.TargetGeneration, expectedRef,
			selected.RequestedByRef, selected.Reason, string(selectorsJSON),
			string(countsJSON), actorJSON, string(fencesJSON), string(schedulerJSON),
			selected.ErasedAt); err != nil {
			return err
		}
		canonical, err = scanPrivacySubjectErasurePreparation(tx.QueryRow(ctx,
			`SELECT `+privacySubjectErasurePreparationColumns+`
			   FROM privacy_subject_erasure_preparations
			  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, candidate.OperationID))
		return err
	})
	return canonical, err
}

func validatePrivacyPreparationActor(tenantID, subject string, actor *events.Actor) error {
	if actor == nil {
		return nil
	}
	if strings.TrimSpace(actor.Subject) == "" {
		return errors.New("store: privacy erasure preparation actor subject is empty")
	}
	raw, err := json.Marshal(actor)
	if err != nil {
		return err
	}
	if _, changed := events.PseudonymizeDataForSubject(raw, tenantID, subject); changed {
		return errors.New("store: privacy erasure preparation actor contains raw subject")
	}
	return nil
}

func countPrivacyRecoveryFences(fences []PrivacyRecoveryFenceDisposition, kind string) int {
	var count int
	for _, fence := range fences {
		if fence.Kind == kind {
			count++
		}
	}
	return count
}

// GetPrivacySubjectErasurePreparation resolves one active preparation under the
// tenant's RLS context. Missing rows use pgx.ErrNoRows like other store lookups.
func (s *Store) GetPrivacySubjectErasurePreparation(
	ctx context.Context,
	tenantID, operationID string,
) (PrivacySubjectErasurePreparation, error) {
	var out PrivacySubjectErasurePreparation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanPrivacySubjectErasurePreparation(tx.QueryRow(ctx,
			`SELECT `+privacySubjectErasurePreparationColumns+`
			   FROM privacy_subject_erasure_preparations
			  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID))
		return err
	})
	return out, err
}

// PrivacySubjectErasurePreparationActiveForGeneration proves whether one
// tenant's independently durable SQL preparation names an exact staged event
// generation. The event-log recovery coordinator calls it before activating a
// target after an ambiguous commit acknowledgment or process restart.
func (s *Store) PrivacySubjectErasurePreparationActiveForGeneration(
	ctx context.Context,
	tenantID, targetGeneration string,
) (bool, error) {
	if tenantID == "" || targetGeneration == "" {
		return false, errors.New("store: privacy preparation generation lookup requires tenant and generation")
	}
	var active bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM privacy_subject_erasure_preparations
			 WHERE tenant_id = $1 AND target_generation = $2
		)`, tenantID, targetGeneration).Scan(&active)
	})
	return active, err
}

// PrivacySubjectErasurePreparationKey is the minimum cross-tenant startup
// inventory. The full selectors, counts, actor, and fence dispositions are read
// only after re-entering that tenant's RLS context.
type PrivacySubjectErasurePreparationKey struct {
	TenantID    string
	OperationID string
}

// ListPrivacySubjectErasurePreparationKeysSystem inventories unfinished
// preparations before read-model restore. It intentionally returns only the
// tenant and opaque operation identities required to re-enter tenant RLS.
func (s *Store) ListPrivacySubjectErasurePreparationKeysSystem(
	ctx context.Context,
) ([]PrivacySubjectErasurePreparationKey, error) {
	//trstctl:system-query — cross-tenant startup recovery enumerates only tenant_id plus an opaque operation id, then reloads every preparation under that tenant's FORCE-RLS context; no subject reference, selector, actor, reason, fence id, or command payload crosses the system query (AN-1 exemption).
	rows, err := s.pool.Query(ctx, `SELECT tenant_id::text, operation_id
		FROM privacy_subject_erasure_preparations ORDER BY created_at, tenant_id, operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []PrivacySubjectErasurePreparationKey
	for rows.Next() {
		var key PrivacySubjectErasurePreparationKey
		if err := rows.Scan(&key.TenantID, &key.OperationID); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) hasPrivacySubjectErasurePreparation(
	ctx context.Context,
	tenantID string,
) (bool, error) {
	var active bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM privacy_subject_erasure_preparations WHERE tenant_id = $1
		)`, tenantID).Scan(&active)
	})
	return active, err
}

func hasPrivacySubjectErasurePreparationTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM privacy_subject_erasure_preparations WHERE tenant_id = $1
	)`, tenantID).Scan(&active)
	return active, err
}

// WithPrivacyRecoveryBarrier holds the shared deployment history-operation lock,
// then checks durable preparation state before recovery may read or publish a
// fence. A live rewrite blocks at the shared lock; a crashed rewrite releases the
// lock but remains fail-closed because its preparation row survives.
func (s *Store) WithPrivacyRecoveryBarrier(
	ctx context.Context,
	tenantID, label string,
	fn func(context.Context) error,
) error {
	if tenantID == "" {
		return errors.New("store: privacy recovery barrier requires tenant id (AN-1)")
	}
	if fn == nil {
		return errors.New("store: privacy recovery barrier callback is nil")
	}
	return NewHistoryRewriteCoordinator(s).withLock(
		ctx, HistoryRewriteOperationAdvisoryLockKey, true, label,
		func(barrierCtx context.Context) error {
			active, err := s.hasPrivacySubjectErasurePreparation(barrierCtx, tenantID)
			if err != nil {
				return err
			}
			if active {
				return ErrPrivacySubjectErasurePreparationActive
			}
			return fn(barrierCtx)
		},
	)
}

// WithPrivacyTenantProjectionRepeatableRead is the short transaction boundary
// for privacy-sensitive durable receivers. Lock order is deliberate: the shared
// history-operation grant and unfinished-preparation check happen before the
// owner transaction takes the backup fence or any receiver row lock. The caller
// must keep fn bounded to PostgreSQL work; external I/O belongs after this helper
// returns so one connector cannot retain a deployment-wide history grant.
func (s *Store) WithPrivacyTenantProjectionRepeatableRead(
	ctx context.Context,
	tenantID, label string,
	fn func(pgx.Tx) error,
) error {
	if fn == nil {
		return errors.New("store: privacy tenant projection callback is nil")
	}
	return s.WithPrivacyRecoveryBarrier(ctx, tenantID, label, func(barrierCtx context.Context) error {
		return s.WithTenantProjectionRepeatableRead(barrierCtx, tenantID, fn)
	})
}

// AssertNoPrivacySubjectErasurePreparations is a system-scope guard for atomic
// read-model replacement. Replaying a raw pre-cutover generation while SQL is
// already prepared would resurrect erased authority, so rebuild/snapshot restore
// must wait for deterministic completion.
func (s *Store) AssertNoPrivacySubjectErasurePreparations(ctx context.Context) error {
	var active bool
	if err := s.pool.QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: atomic rebuild/snapshot replacement must stop if ANY tenant has an unfinished privacy history cutover; returns one boolean and no tenant, subject reference, selector, or command data (AN-1 exemption).
		`SELECT EXISTS (SELECT 1 FROM privacy_subject_erasure_preparations)`).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrPrivacySubjectErasurePreparationActive
	}
	return nil
}

// WithPrivacyReadModelReplacementBarrier prevents a full rebuild or snapshot
// replacement from crossing the SQL-prepared/history-not-completed window. The
// shared operation grant closes the live race; the durable table check closes the
// same window after a crashed writer has released its PostgreSQL session lock.
func (s *Store) WithPrivacyReadModelReplacementBarrier(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if fn == nil {
		return errors.New("store: privacy read-model replacement callback is nil")
	}
	if lease, ok := ctx.Value(privacyReadModelBarrierContextKey{}).(*privacyReadModelBarrierLease); ok &&
		lease.acquire(s) {
		defer lease.release()
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		// Repeat the durable check for the nested public operation. The shared
		// grant prevents a live preparation from entering, while this check also
		// keeps an already-crashed marker fail-closed.
		if err := s.AssertNoPrivacySubjectErasurePreparations(ctx); err != nil {
			return err
		}
		return fn(ctx)
	}
	return NewHistoryRewriteCoordinator(s).withLock(
		ctx, HistoryRewriteOperationAdvisoryLockKey, true,
		"privacy read-model replacement barrier", func(barrierCtx context.Context) error {
			lease := newPrivacyReadModelBarrierLease(s)
			defer lease.revokeAndWait()
			barrierCtx = context.WithValue(
				barrierCtx, privacyReadModelBarrierContextKey{}, lease,
			)
			if err := s.AssertNoPrivacySubjectErasurePreparations(barrierCtx); err != nil {
				return err
			}
			return fn(barrierCtx)
		},
	)
}

func pseudonymizePreparedOperationApprovalsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subjectRef string,
	selectors []PrivacyReadModelSelector,
) error {
	placeholder := privacy.Placeholder(subjectRef)
	requestIDs := readModelIDs(selectors, "operation_approval_requests")
	if len(requestIDs) != 0 {
		directRequesterIDs, err := operationApprovalRequesterIDsMatchingSubjectRef(
			ctx, tx, tenantID, subjectRef, requestIDs,
		)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE operation_approval_requests
			SET resource_kind = $3, resource_id = $3, resource_name = $3,
			    action = $3,
			    requester = CASE WHEN id::text = ANY($4::text[]) THEN $3 ELSE requester END,
			    from_state = $3, to_state = $3,
			    reason = '', evidence_refs = '[]'::jsonb,
			    status = CASE WHEN status IN ('pending', 'approved') THEN 'superseded' ELSE status END
			WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
			tenantID, requestIDs, placeholder, directRequesterIDs)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != int64(len(requestIDs)) {
			return fmt.Errorf("%w: selected operation approval request disappeared", ErrIdempotencyConflict)
		}
	}

	decisionIDs := readModelIDs(selectors, "operation_approval_decisions")
	if len(decisionIDs) == 0 {
		return nil
	}
	directApproverIDs, err := operationApprovalDecisionIDsMatchingSubjectRef(
		ctx, tx, tenantID, subjectRef, decisionIDs,
	)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE operation_approval_requests r
		SET status = 'superseded'
		WHERE r.tenant_id = $1 AND r.status IN ('pending', 'approved')
		  AND EXISTS (
		        SELECT 1 FROM operation_approval_decisions d
		         WHERE d.tenant_id = r.tenant_id AND d.request_id = r.id
		           AND d.event_id::text = ANY($2::text[])
		      )`, tenantID, decisionIDs); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE operation_approval_decisions
		SET approver = CASE WHEN event_id::text = ANY($4::text[]) THEN $3 ELSE approver END,
		    reason = ''
		WHERE tenant_id = $1 AND event_id::text = ANY($2::text[])`,
		tenantID, decisionIDs, placeholder, directApproverIDs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(decisionIDs)) {
		return fmt.Errorf("%w: selected operation approval decision disappeared", ErrIdempotencyConflict)
	}
	return nil
}

func (s *Store) prepareApplicationSecretRecoveryFencesTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subject, subjectRef string,
) ([]PrivacyRecoveryFenceDisposition, error) {
	type fenceRow struct {
		name, operation, eventID, eventType, requesterRef, actorRef string
		schema                                                      int
		eventTime                                                   *time.Time
		approval, actor, payload                                    []byte
		payloadDigest                                               string
	}
	rows, err := tx.Query(ctx, `SELECT secret_name, operation, event_id::text,
		event_type, schema_version, event_time, approval, actor, command_payload,
		payload_sha256, coalesce(requester_ref, ''), coalesce(actor_subject_ref, '')
		FROM application_secret_mutation_fences
		WHERE tenant_id = $1 ORDER BY secret_name FOR UPDATE`, tenantID)
	if err != nil {
		return nil, err
	}
	var pending []fenceRow
	for rows.Next() {
		var row fenceRow
		if err := rows.Scan(&row.name, &row.operation, &row.eventID,
			&row.eventType, &row.schema, &row.eventTime, &row.approval,
			&row.actor, &row.payload, &row.payloadDigest,
			&row.requesterRef, &row.actorRef); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	dispositions := make([]PrivacyRecoveryFenceDisposition, 0)
	for _, row := range pending {
		if !json.Valid(row.payload) {
			return nil, fmt.Errorf("store: application-secret fence %s payload is not JSON", row.eventID)
		}
		if crypto.SHA256Hex(row.payload) != row.payloadDigest {
			return nil, fmt.Errorf("store: application-secret fence %s payload digest mismatch before privacy preparation", row.eventID)
		}
		var before struct {
			Name   string `json:"name"`
			Action string `json:"action"`
		}
		if err := json.Unmarshal(row.payload, &before); err != nil {
			return nil, err
		}
		if before.Name != row.name || before.Action != row.operation {
			return nil, fmt.Errorf("%w: application-secret fence payload identity differs", ErrIdempotencyConflict)
		}
		rewrittenPayload, rewrittenSchema, payloadChanged, err :=
			events.PseudonymizeEventDataForSubjectVersioned(
				row.payload, tenantID, subject, row.eventType, row.schema,
			)
		if err != nil {
			return nil, fmt.Errorf("store: pseudonymize application-secret fence %s payload: %w", row.eventID, err)
		}
		actorValue, actorChanged, err := pseudonymizeApplicationSecretRecoveryActor(row.actor, tenantID, subject)
		if err != nil {
			return nil, fmt.Errorf("store: pseudonymize application-secret fence %s actor: %w", row.eventID, err)
		}
		affected := payloadChanged || actorChanged ||
			row.requesterRef == subjectRef || row.actorRef == subjectRef
		if !affected {
			continue
		}
		// A schema transition is an explicit command-authority disposition, never
		// a coordinate rename. The replacement history generation now owns either
		// an inert name tombstone or a local-only sync-erased command. Delete the
		// SQL recovery copy even after finalization: retaining the old v2 ciphertext
		// would let restart append a raw or wrong-AAD command after cutover.
		if row.eventTime == nil || rewrittenSchema != row.schema {
			tag, err := tx.Exec(ctx, `DELETE FROM application_secret_mutation_fences
				WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
				tenantID, row.name, row.eventID)
			if err != nil {
				return nil, err
			}
			if tag.RowsAffected() != 1 {
				return nil, fmt.Errorf("%w: application-secret preparation fence disappeared", ErrIdempotencyConflict)
			}
			dispositions = append(dispositions, PrivacyRecoveryFenceDisposition{
				Kind: PrivacyRecoveryFenceApplicationSecret, EventID: row.eventID,
				Disposition: PrivacyRecoveryFenceDeleted,
			})
			continue
		}
		var after struct {
			Name   string `json:"name"`
			Action string `json:"action"`
		}
		if err := json.Unmarshal(rewrittenPayload, &after); err != nil {
			return nil, err
		}
		if after.Name != row.name || after.Action != row.operation {
			return nil, fmt.Errorf("%w: application-secret privacy rewrite changed an AAD-bound fence coordinate", ErrIdempotencyConflict)
		}
		var actorRef any
		if row.actorRef != "" && row.actorRef != subjectRef {
			actorRef = row.actorRef
		}
		var requesterRef any
		if row.requesterRef != "" && row.requesterRef != subjectRef {
			requesterRef = row.requesterRef
		}
		tag, err := tx.Exec(ctx, `UPDATE application_secret_mutation_fences
			SET command_payload = $4, payload_sha256 = $5, actor = $6::jsonb,
			    requester_sealed = CASE WHEN requester_ref = $7 THEN NULL ELSE requester_sealed END,
			    requester_ref = $8, actor_subject_ref = $9
			WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
			tenantID, row.name, row.eventID, rewrittenPayload,
			crypto.SHA256Hex(rewrittenPayload), actorValue,
			subjectRef, requesterRef, actorRef)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, fmt.Errorf("%w: application-secret preparation fence disappeared", ErrIdempotencyConflict)
		}
		dispositions = append(dispositions, PrivacyRecoveryFenceDisposition{
			Kind: PrivacyRecoveryFenceApplicationSecret, EventID: row.eventID,
			Disposition: PrivacyRecoveryFencePseudonymized,
		})
	}
	return dispositions, nil
}

func (s *Store) prepareApprovedTargetRecoveryFencesTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subject string,
) ([]PrivacyRecoveryFenceDisposition, error) {
	type fenceRow struct {
		targetKind, commandKey, eventID, eventType string
		approvalRequestID, approvalIntentDigest    string
		schema                                     int
		eventTime                                  time.Time
		actor, payload, approval                   []byte
		payloadDigest, semantic                    string
	}
	rows, err := tx.Query(ctx, `SELECT target_kind, command_key, event_id::text,
		event_type, schema_version, event_time, event_actor, event_payload, approval,
		approval_request_id::text, approval_intent_digest, payload_sha256, semantic_sha256
		FROM approved_target_event_fences
		WHERE tenant_id = $1 ORDER BY target_kind, command_key FOR UPDATE`, tenantID)
	if err != nil {
		return nil, err
	}
	var pending []fenceRow
	for rows.Next() {
		var row fenceRow
		if err := rows.Scan(&row.targetKind, &row.commandKey, &row.eventID,
			&row.eventType, &row.schema, &row.eventTime, &row.actor, &row.payload,
			&row.approval, &row.approvalRequestID, &row.approvalIntentDigest,
			&row.payloadDigest, &row.semantic); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	dispositions := make([]PrivacyRecoveryFenceDisposition, 0)
	for _, row := range pending {
		if crypto.SHA256Hex(row.payload) != row.payloadDigest {
			return nil, fmt.Errorf("store: approved target fence %s payload digest mismatch before privacy preparation", row.eventID)
		}
		rewrittenPayload, payloadChanged, err := events.PseudonymizeEventDataForSubject(
			row.payload, tenantID, subject, row.eventType, row.schema,
		)
		if err != nil {
			return nil, fmt.Errorf("store: pseudonymize approved target fence %s payload: %w", row.eventID, err)
		}
		rewrittenApproval, approvalChanged := events.PseudonymizeDataForSubject(row.approval, tenantID, subject)
		actorValue, rewrittenActor, actorChanged, err := pseudonymizeRecoveryActor(
			row.actor, tenantID, subject,
		)
		if err != nil {
			return nil, fmt.Errorf("store: pseudonymize approved target fence %s actor: %w", row.eventID, err)
		}
		if !payloadChanged && !approvalChanged && !actorChanged {
			continue
		}
		semantic := row.semantic
		if row.targetKind == ApprovedTargetCodeSigningCommand && row.schema == 2 {
			semantic, err = rewriteLegacyApprovedCodeSigningFenceSemantic(legacyApprovedCodeSigningFenceRewrite{
				TenantID: tenantID, CommandKey: row.commandKey,
				EventID: row.eventID, EventType: row.eventType,
				SchemaVersion: row.schema, EventTime: row.eventTime,
				ApprovalRequestID:    row.approvalRequestID,
				ApprovalIntentDigest: row.approvalIntentDigest,
				OriginalActor:        row.actor, OriginalPayload: row.payload,
				RewrittenActor: rewrittenActor, RewrittenPayload: rewrittenPayload,
				StoredSemantic: row.semantic,
			})
			if err != nil {
				return nil, fmt.Errorf("store: rewrite legacy approved code-signing preparation fence %s semantic: %w", row.eventID, err)
			}
		}
		var approvalValue any
		if len(rewrittenApproval) != 0 {
			approvalValue = string(rewrittenApproval)
		}
		tag, err := tx.Exec(ctx, `UPDATE approved_target_event_fences
			SET event_actor = $4::jsonb, event_payload = $5, payload_sha256 = $6,
			    approval = $7::jsonb, semantic_sha256 = $8, updated_at = now()
			WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
			tenantID, row.targetKind, row.commandKey, actorValue, rewrittenPayload,
			crypto.SHA256Hex(rewrittenPayload), approvalValue, semantic)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, fmt.Errorf("%w: approved target preparation fence disappeared", ErrIdempotencyConflict)
		}
		dispositions = append(dispositions, PrivacyRecoveryFenceDisposition{
			Kind: PrivacyRecoveryFenceApprovedTarget, EventID: row.eventID,
			Disposition: PrivacyRecoveryFencePseudonymized,
		})
	}
	return dispositions, nil
}

func pseudonymizeRecoveryActor(
	raw []byte,
	tenantID, subject string,
) (any, []byte, bool, error) {
	if len(raw) == 0 {
		return nil, nil, false, nil
	}
	var actor events.Actor
	if err := json.Unmarshal(raw, &actor); err != nil {
		return nil, nil, false, err
	}
	if strings.TrimSpace(actor.Subject) == "" {
		return nil, nil, false, errors.New("recovery actor subject is empty")
	}
	rewritten, changed := events.PseudonymizeActorForSubject(&actor, tenantID, subject)
	encoded, err := json.Marshal(rewritten)
	if err != nil {
		return nil, nil, false, err
	}
	return string(encoded), encoded, changed, nil
}

func pseudonymizeApplicationSecretRecoveryActor(
	raw []byte,
	tenantID, subject string,
) (any, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	var actor events.Actor
	if err := json.Unmarshal(raw, &actor); err != nil {
		return nil, false, err
	}
	rewritten, changed, err := pseudonymizeApplicationSecretActor(&actor, tenantID, subject)
	if err != nil {
		return nil, false, err
	}
	encoded, err := marshalApplicationSecretActor(rewritten)
	if err != nil {
		return nil, false, err
	}
	return string(encoded), changed, nil
}
