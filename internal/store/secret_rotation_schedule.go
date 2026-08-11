// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/rotationcommand"
)

var (
	// ErrSecretRotationScheduleDueEdgeStale means another terminal projection
	// already advanced or disabled the schedule selected by an older scan.
	ErrSecretRotationScheduleDueEdgeStale = errors.New("store: secret rotation schedule due edge is stale")
	// ErrSecretRotationScheduleCommandConflict means retained command authority
	// disagrees with the deterministic tuple presented by a retry. Continuing
	// could rotate a different credential under an accepted command identity.
	ErrSecretRotationScheduleCommandConflict = errors.New("store: secret rotation schedule command conflicts with retained authority")
	// ErrSecretRotationScheduleScanLeaseConflict means a scheduler tried to
	// advance or release a tenant cursor without owning its live lease.
	ErrSecretRotationScheduleScanLeaseConflict = errors.New("store: secret rotation schedule scan lease conflicts with retained authority")
)

// SecretRotationSchedule is a tenant-owned cadence for durable connector-backed
// application-secret rotation. Historical rows may name static providers, but
// the served scheduler terminally disables them without invoking provider code.
// It stores references and run metadata only, never credential values.
type SecretRotationSchedule struct {
	ID       string
	TenantID string
	// IdentityVersion and tenant registration fields are populated on immutable
	// scheduler snapshots. The mutable schedule projection itself leaves them
	// zero because one aggregate tick supplies the lifecycle authority.
	IdentityVersion                 int
	TenantRegistrationEventID       string
	TenantRegistrationEventSequence uint64
	Name                            string
	Provider                        string
	Key                             string
	OldRef                          string
	IntervalSeconds                 int
	// ConfigEventSequence is the immutable event revision of the configuration
	// tuple. Zero is reserved for rows projected before migration 0155.
	ConfigEventSequence uint64
	Enabled             bool
	NextRunAt           time.Time
	LastRunID           *string
	LastRunAt           *time.Time
	LastRunStatus       string
	LastNewRef          string
	LastError           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// SecretRotationScheduleRun is the projected result of one scheduled rotation
// tick. Status is metadata such as completed, rolled_back, or failed.
type SecretRotationScheduleRun struct {
	TenantID                        string
	IdentityVersion                 int
	TenantRegistrationEventID       string
	TenantRegistrationEventSequence uint64
	ScheduleID                      string
	RunID                           string
	SchemaVersion                   int
	DueAt                           time.Time
	Provider                        string
	Key                             string
	OldRef                          string
	IntervalSeconds                 int
	ConfigEventSequence             uint64
	CommandKey                      string
	RequestBinding                  string
	Status                          string
	NewRef                          string
	Error                           string
	RanAt                           time.Time
	EventID                         string
	EventType                       string
	EventSequence                   uint64
	EventDigest                     string
	// TickIdempotencyKey, TickOrdinal, and LeaseToken are operational claim
	// authority used before append. They are deliberately absent from the
	// immutable domain event because a crashed row may be carried into a newer
	// aggregate tick without changing its deterministic due-edge identity.
	TickIdempotencyKey string
	TickOrdinal        int
	LeaseToken         string
}

// SecretRotationScheduleCommandClaimState tells the scheduler whether a child
// receiver was created now, recovered after an earlier lease ended, is still
// live elsewhere, or already has a terminal SQL receipt. Only recovery may pay
// the bounded one-time event-ID scan needed to close an append-ACK crash gap.
type SecretRotationScheduleCommandClaimState string

const (
	SecretRotationScheduleCommandCreated   SecretRotationScheduleCommandClaimState = "created"
	SecretRotationScheduleCommandRecovered SecretRotationScheduleCommandClaimState = "recovered"
	SecretRotationScheduleCommandBusy      SecretRotationScheduleCommandClaimState = "busy"
	SecretRotationScheduleCommandTerminal  SecretRotationScheduleCommandClaimState = "terminal"
)

// SecretRotationScheduleCommand is the durable receiver for one exact schedule
// due edge. It contains only references and command digests, never credential
// material. Status=claimed is resumable; every other status is a terminal receipt
// projected from the deterministic secret.rotation_schedule.ran event.
type SecretRotationScheduleCommand struct {
	TenantID                        string
	IdentityVersion                 int
	TenantRegistrationEventID       string
	TenantRegistrationEventSequence uint64
	ScheduleID                      string
	RunID                           string
	DueAt                           time.Time
	Provider                        string
	Key                             string
	OldRef                          string
	IntervalSeconds                 int
	ConfigEventSequence             uint64
	TickIdempotencyKey              string
	TickOrdinal                     int
	CommandKey                      string
	RequestBinding                  string
	TerminalEventID                 string
	PreparedStatus                  string
	PreparedNewRef                  string
	PreparedError                   string
	PreparedEventDigest             string
	PreparedAt                      *time.Time
	TerminalEventType               string
	TerminalEventSequence           *int64
	TerminalEventDigest             string
	TerminalEventFromEvent          *bool
	PrivacyRewriteVersion           int
	PrivacySubjectRef               string
	PrivacyOperationID              string
	PrivacyEventID                  string
	Status                          string
	NewRef                          string
	Error                           string
	LeaseToken                      string
	LeaseUntil                      *time.Time
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
	TerminalAt                      *time.Time
	// ClaimState is returned only by ClaimSecretRotationScheduleCommand. It is
	// transient process state, not a database column.
	ClaimState SecretRotationScheduleCommandClaimState
}

// SecretRotationScheduleScanCursor is the durable per-tenant position in the
// UUID-ordered schedule ring. It is operational PostgreSQL authority, not a
// rebuildable event projection. Generation is monotonic diagnostic evidence;
// the lease serializes live replicas while expiry permits crash recovery.
type SecretRotationScheduleScanCursor struct {
	TenantID          string
	AfterScheduleID   string
	ActiveTickKey     string
	ActiveTickBinding string
	LeaseToken        string
	LeaseUntil        *time.Time
	LeaseGeneration   int64
	Generation        int64
	UpdatedAt         time.Time
}

// ApplySecretRotationScheduleUpsertedTx projects a
// secret.rotation_schedule.upserted event.
func (s *Store) ApplySecretRotationScheduleUpsertedTx(ctx context.Context, tx pgx.Tx, sched SecretRotationSchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_rotation_schedules
		        (id, tenant_id, name, provider, secret_key, old_ref, interval_seconds,
		         config_event_sequence, enabled, next_run_at, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET name = EXCLUDED.name,
		          provider = EXCLUDED.provider,
		          secret_key = EXCLUDED.secret_key,
		          old_ref = EXCLUDED.old_ref,
		          interval_seconds = EXCLUDED.interval_seconds,
		          config_event_sequence = EXCLUDED.config_event_sequence,
		          enabled = EXCLUDED.enabled,
		          next_run_at = EXCLUDED.next_run_at,
		          updated_at = EXCLUDED.updated_at
		    WHERE secret_rotation_schedules.config_event_sequence <= EXCLUDED.config_event_sequence`,
		sched.ID, sched.TenantID, sched.Name, sched.Provider, sched.Key, sched.OldRef,
		sched.IntervalSeconds, sched.ConfigEventSequence, sched.Enabled, sched.NextRunAt,
		sched.CreatedAt, sched.UpdatedAt)
	return err
}

// ApplySecretRotationScheduleRunTx projects a scheduled rotation outcome and
// advances the next due time. Only explicit outcome states that prove the
// successor committed promote its reference. In particular, retire_pending means
// a static successor is already live and delivery_failed means a connector's local
// canonical version committed before terminal delivery failure. A generic failed
// status never promotes merely because a producer supplied a non-empty new_ref.
func (s *Store) ApplySecretRotationScheduleRunTx(ctx context.Context, tx pgx.Tx, run SecretRotationScheduleRun) error {
	if run.SchemaVersion <= 1 {
		// Version 1 predates the closed scheduler-error contract and may contain
		// provider-controlled text. Preserve the immutable event, but project only
		// its stable terminal class. Newer event versions must already be closed.
		run.Error = CanonicalSecretRotationScheduleError(run.Status, run.Error)
	} else if !IsCanonicalSecretRotationScheduleError(run.Status, run.Error) {
		return fmt.Errorf("%w: terminal run error is outside the closed scheduler vocabulary", ErrSecretRotationScheduleCommandConflict)
	}
	if err := lockTenantLifecycleSharedTx(ctx, tx, run.TenantID); err != nil {
		return err
	}
	registration, err := lockLiveTenantRegistrationSnapshotAfterLifecycleTx(ctx, tx, run.TenantID)
	if errors.Is(err, ErrApplicationSecretTenantEpochMismatch) {
		// A retained run for an offboarded tenant is immutable history, not live
		// projection authority.
		return nil
	}
	if err != nil {
		return err
	}
	if run.EventSequence < registration.EventSeq {
		// A late/replayed pre-registration event is inert after the same tenant UUID
		// is registered again.
		return nil
	}
	if run.SchemaVersion == rotationcommand.EventSchemaVersion &&
		run.TenantRegistrationEventSequence != registration.EventSeq {
		return nil
	}
	var command SecretRotationScheduleCommand
	err = scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
		`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
		        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
		        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
		        tick_idempotency_key, tick_ordinal,
		        command_key, request_binding,
		        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
		        prepared_event_digest, prepared_at,
		        terminal_event_type, terminal_event_sequence,
		        terminal_event_digest, terminal_event_from_event,
		        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
		        status, new_ref, error, lease_token,
		        lease_until, created_at, updated_at, terminal_at
		   FROM secret_rotation_schedule_commands
		  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
		  FOR UPDATE`, run.TenantID, run.ScheduleID, run.RunID), &command)
	if errors.Is(err, pgx.ErrNoRows) {
		if run.SchemaVersion >= 2 {
			// Verified retention may remove an older terminal SQL receiver. The v2
			// event carries the original command tuple, so a cold rebuild still uses
			// the exact due edge rather than an unrelated producer wall clock.
			if err := validateBoundSecretRotationScheduleRun(run); err != nil {
				return err
			}
			return applyBoundSecretRotationScheduleRunTx(ctx, tx, run)
		}
		// Compatibility for immutable events emitted before migration 0155 only.
		// Those v1 payloads had no exact due-edge tuple, so event time is the only
		// monotonic authority available for that historical data.
		return applyLegacySecretRotationScheduleRunTx(ctx, tx, run)
	}
	if err != nil {
		return err
	}
	if err := validateBoundSecretRotationScheduleRun(run); err != nil {
		return err
	}
	if run.IdentityVersion != command.IdentityVersion ||
		run.TenantRegistrationEventID != command.TenantRegistrationEventID ||
		run.TenantRegistrationEventSequence != command.TenantRegistrationEventSequence ||
		!run.DueAt.Equal(command.DueAt) || run.Provider != command.Provider || run.Key != command.Key ||
		run.OldRef != command.OldRef || run.IntervalSeconds != command.IntervalSeconds ||
		run.ConfigEventSequence != command.ConfigEventSequence || run.CommandKey != command.CommandKey ||
		run.RequestBinding != command.RequestBinding || run.EventID != command.TerminalEventID {
		return fmt.Errorf("%w: terminal event due-edge tuple differs from command authority", ErrSecretRotationScheduleCommandConflict)
	}
	if err := validateSecretRotationSchedulePreparedIntent(command, run); err != nil {
		return err
	}
	alreadyTerminal := command.Status != "claimed"
	if alreadyTerminal {
		if command.Status == run.Status && command.NewRef == run.NewRef && command.Error == run.Error &&
			command.TerminalEventType == run.EventType && command.TerminalEventSequence != nil &&
			*command.TerminalEventSequence == int64(run.EventSequence) &&
			command.TerminalEventDigest == run.EventDigest && command.TerminalEventFromEvent != nil &&
			*command.TerminalEventFromEvent && command.TerminalAt != nil &&
			command.TerminalAt.Truncate(time.Microsecond).Equal(run.RanAt.Truncate(time.Microsecond)) {
			// The receiver is independent PostgreSQL state and intentionally
			// survives a read-model rebuild. Its exact receipt is already done,
			// but the rebuilt schedule projection still needs this event below.
		} else {
			return fmt.Errorf("%w: run %s already ended as %s", ErrSecretRotationScheduleCommandConflict, run.RunID, command.Status)
		}
	}
	if !alreadyTerminal {
		tag, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_commands
		    SET status = $4, new_ref = $5, error = $6,
		        lease_token = '', lease_until = NULL,
		        terminal_event_type = $8, terminal_event_sequence = $9,
		        terminal_event_digest = $10, terminal_event_from_event = true,
		        terminal_at = $7::timestamptz, updated_at = $7::timestamptz
		  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
		    AND status = 'claimed'
		    AND prepared_status = $4 AND prepared_new_ref = $5 AND prepared_error = $6
		    AND prepared_at = $7::timestamptz AND prepared_event_digest = $10`,
			run.TenantID, run.ScheduleID, run.RunID, run.Status, run.NewRef, run.Error, run.RanAt,
			run.EventType, int64(run.EventSequence), run.EventDigest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: claimed terminal command update matched %d rows", ErrSecretRotationScheduleCommandConflict, tag.RowsAffected())
		}
	}

	return applyBoundSecretRotationScheduleRunTx(ctx, tx, run)
}

func validateBoundSecretRotationScheduleRun(run SecretRotationScheduleRun) error {
	validIdentity := false
	switch run.SchemaVersion {
	case rotationcommand.LegacyBoundEventSchemaVersion:
		validIdentity = run.IdentityVersion == 2 &&
			rotationcommand.LegacyMatches(run.TenantID, run.ScheduleID, run.RunID,
				run.DueAt, run.CommandKey, run.EventID)
	case rotationcommand.EventSchemaVersion:
		validIdentity = run.IdentityVersion == SecretRotationScheduleIdentityVersion &&
			validSecretRotationScheduleTenantRegistration(
				run.TenantRegistrationEventID, run.TenantRegistrationEventSequence) &&
			rotationcommand.Matches(run.TenantID, run.TenantRegistrationEventSequence,
				run.ScheduleID, run.RunID, run.DueAt, run.CommandKey, run.EventID)
	}
	if !validIdentity || !secretRotationScheduleTerminalStatus(run.Status) ||
		run.Provider == "" || run.Key == "" || run.OldRef == "" || run.IntervalSeconds <= 0 ||
		run.ConfigEventSequence == 0 || run.RequestBinding == "" ||
		run.EventType != "secret.rotation_schedule.ran" || run.EventSequence == 0 || len(run.EventDigest) != 64 {
		return fmt.Errorf("%w: terminal run lacks exact lifecycle-bound due-edge event authority", ErrSecretRotationScheduleCommandConflict)
	}
	return nil
}

// applyBoundSecretRotationScheduleRunTx uses the immutable v2 due edge as the
// schedule CAS and cadence basis. Event wall time remains display/audit metadata;
// it cannot make a clock-skewed replay skip or shift a successor edge.
func applyBoundSecretRotationScheduleRunTx(ctx context.Context, tx pgx.Tx, run SecretRotationScheduleRun) error {
	tag, err := tx.Exec(ctx,
		`UPDATE secret_rotation_schedules
			    SET old_ref = CASE
			            WHEN $5 <> '' AND $4 IN (
			                'completed', 'queued', 'retire_pending', 'delivery_failed'
			            ) THEN $5
		            ELSE old_ref
		        END,
		        enabled = CASE WHEN $4 = 'unsupported' THEN false ELSE enabled END,
		        next_run_at = $8::timestamptz + (interval_seconds * interval '1 second'),
		        last_run_id = $3::uuid,
		        last_run_at = $7::timestamptz,
		        last_run_status = $4,
		        last_new_ref = $5,
		        last_error = $6,
		        updated_at = $7::timestamptz
		  WHERE tenant_id = $1 AND id = $2
		    AND next_run_at = $8::timestamptz
		    AND provider = $9 AND secret_key = $10 AND old_ref = $11
		    AND interval_seconds = $12 AND config_event_sequence = $13`,
		run.TenantID, run.ScheduleID, run.RunID, run.Status, run.NewRef, run.Error, run.RanAt,
		run.DueAt, run.Provider, run.Key, run.OldRef, run.IntervalSeconds, run.ConfigEventSequence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return verifyBoundSecretRotationScheduleRunNoopTx(ctx, tx, run)
}

// verifyBoundSecretRotationScheduleRunNoopTx distinguishes an idempotent or
// provably superseded replay from authority drift. A zero-row CAS is not success
// merely because SQL returned no error: without this proof, the surrounding
// transaction must roll back any claimed->terminal command update.
func verifyBoundSecretRotationScheduleRunNoopTx(ctx context.Context, tx pgx.Tx, run SecretRotationScheduleRun) error {
	var (
		provider, key, oldRef, lastStatus, lastNewRef, lastError string
		intervalSeconds                                          int
		configEventSequence                                      uint64
		nextRunAt                                                time.Time
		lastRunID                                                *string
		lastRunAt                                                *time.Time
	)
	if err := tx.QueryRow(ctx,
		`SELECT provider, secret_key, old_ref, interval_seconds, config_event_sequence, next_run_at,
		        last_run_id::text, last_run_at, last_run_status, last_new_ref, last_error
		   FROM secret_rotation_schedules
		  WHERE tenant_id = $1 AND id = $2
		  FOR UPDATE`, run.TenantID, run.ScheduleID).
		Scan(&provider, &key, &oldRef, &intervalSeconds, &configEventSequence, &nextRunAt,
			&lastRunID, &lastRunAt, &lastStatus, &lastNewRef, &lastError); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: exact schedule revision is missing", ErrSecretRotationScheduleCommandConflict)
		}
		return err
	}
	if configEventSequence > run.ConfigEventSequence {
		// A later event-derived configuration owns the live row. The immutable
		// terminal command/event remains authoritative, but this older cadence may
		// not overwrite the newer projection.
		return nil
	}
	if provider != run.Provider || key != run.Key || intervalSeconds <= 0 || lastRunID == nil || lastRunAt == nil {
		return fmt.Errorf("%w: terminal event missed its exact schedule tuple", ErrSecretRotationScheduleCommandConflict)
	}
	lastDueAt := nextRunAt.Add(-time.Duration(intervalSeconds) * time.Second)
	if lastDueAt.Equal(run.DueAt) && *lastRunID == run.RunID &&
		lastStatus == run.Status && lastNewRef == run.NewRef && lastError == run.Error &&
		lastRunAt.Truncate(time.Microsecond).Equal(run.RanAt.Truncate(time.Microsecond)) &&
		oldRef == secretRotationScheduleSuccessorRef(run.Status, run.OldRef, run.NewRef) {
		return nil
	}
	if lastDueAt.After(run.DueAt) &&
		*lastRunID == secretRotationScheduleRunIDForSchema(run, lastDueAt) &&
		secretRotationScheduleTerminalStatus(lastStatus) {
		return nil
	}
	return fmt.Errorf("%w: terminal event missed its exact due-edge CAS", ErrSecretRotationScheduleCommandConflict)
}

func secretRotationScheduleRunIDForSchema(run SecretRotationScheduleRun, dueAt time.Time) string {
	if run.SchemaVersion == rotationcommand.EventSchemaVersion {
		return rotationcommand.RunID(run.TenantID, run.TenantRegistrationEventSequence, run.ScheduleID, dueAt)
	}
	return rotationcommand.LegacyRunID(run.TenantID, run.ScheduleID, dueAt)
}

func secretRotationScheduleSuccessorRef(status, oldRef, newRef string) string {
	if newRef != "" {
		switch status {
		case "completed", "queued", "retire_pending", "delivery_failed":
			return newRef
		}
	}
	return oldRef
}

func applyLegacySecretRotationScheduleRunTx(ctx context.Context, tx pgx.Tx, run SecretRotationScheduleRun) error {
	if !secretRotationScheduleTerminalStatus(run.Status) {
		return fmt.Errorf("%w: legacy status %q is not terminal", ErrSecretRotationScheduleCommandConflict, run.Status)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_rotation_schedules
		    SET old_ref = CASE
		            WHEN $5 <> '' AND $4 IN (
		                'completed', 'queued', 'retire_pending', 'delivery_failed'
		            ) THEN $5
		            ELSE old_ref
		        END,
		        enabled = CASE WHEN $4 = 'unsupported' THEN false ELSE enabled END,
		        next_run_at = $7::timestamptz + (interval_seconds * interval '1 second'),
		        last_run_id = $3::uuid,
		        last_run_at = $7::timestamptz,
		        last_run_status = $4,
		        last_new_ref = $5,
		        last_error = $6,
		        updated_at = $7::timestamptz
		  WHERE tenant_id = $1 AND id = $2
		    AND (last_run_at IS NULL OR last_run_at < $7::timestamptz OR
		         (last_run_at = $7::timestamptz AND last_run_id = $3::uuid))`,
		run.TenantID, run.ScheduleID, run.RunID, run.Status, run.NewRef, run.Error, run.RanAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM secret_rotation_schedules WHERE tenant_id = $1 AND id = $2
			)`, run.TenantID, run.ScheduleID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
	}
	return nil
}

func secretRotationScheduleTerminalStatus(status string) bool {
	switch status {
	case "completed", "queued", "failed", "rolled_back", "rollback_failed", "retire_pending", "delivery_failed", "unsupported":
		return true
	default:
		return false
	}
}

// ClaimSecretRotationScheduleCommand durably binds and leases one exact due
// edge. The active aggregate tick and its immutable ordinal are locked before
// the child command. Only a brand-new command then locks the live schedule: an
// exact revision may begin work, a strictly newer revision makes the frozen row
// stale without an effect, and missing or same-revision drift fails closed.
// Once a command exists, later configuration cannot invalidate its terminal
// event; crash recovery follows the command's frozen tuple instead.
func (s *Store) ClaimSecretRotationScheduleCommand(
	ctx context.Context,
	command SecretRotationScheduleCommand,
	leaseToken string,
	leaseDuration time.Duration,
) (SecretRotationScheduleCommand, bool, error) {
	var out SecretRotationScheduleCommand
	if leaseToken == "" || leaseDuration <= 0 || command.Provider == "" || command.Key == "" || command.OldRef == "" || command.RequestBinding == "" ||
		command.IntervalSeconds <= 0 || command.ConfigEventSequence == 0 || command.TickIdempotencyKey == "" || command.TickOrdinal <= 0 || command.TickOrdinal > 500 ||
		command.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		!validSecretRotationScheduleTenantRegistration(command.TenantRegistrationEventID, command.TenantRegistrationEventSequence) ||
		!rotationcommand.Matches(command.TenantID, command.TenantRegistrationEventSequence, command.ScheduleID, command.RunID,
			command.DueAt, command.CommandKey, command.TerminalEventID) {
		return out, false, fmt.Errorf("%w: command lacks one exact deterministic due-edge tuple", ErrSecretRotationScheduleCommandConflict)
	}
	acquired := false
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, command.TenantID, "secret rotation scheduler child claim", func(tx pgx.Tx) error {
			if err := lockAndValidateSecretRotationScheduleTickChildTx(ctx, tx, command, leaseToken); err != nil {
				return err
			}
			err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
				`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
			        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        tick_idempotency_key, tick_ordinal,
			        command_key, request_binding,
			        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			        prepared_event_digest, prepared_at,
			        terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			        status, new_ref, error, lease_token,
			        lease_until, created_at, updated_at, terminal_at
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
			  FOR UPDATE`, command.TenantID, command.ScheduleID, command.RunID), &out)
			if err == nil {
				if err := validateSecretRotationScheduleCommandDueEdge(out, command); err != nil {
					return err
				}
				if out.Status != "claimed" {
					out.ClaimState = SecretRotationScheduleCommandTerminal
					return nil
				}
				err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
					`UPDATE secret_rotation_schedule_commands
				    SET tick_idempotency_key = $6,
				        tick_ordinal = $7,
				        lease_token = $4,
				        lease_until = clock_timestamp() + make_interval(secs => $5::double precision),
				        updated_at = clock_timestamp()
				  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
				    AND status = 'claimed'
				    AND (lease_token = '' OR lease_token = $4 OR lease_until <= clock_timestamp())
				  RETURNING tenant_id::text, identity_version, tenant_registration_event_id,
				            tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
				            provider, secret_key, old_ref, interval_seconds, config_event_sequence,
				            tick_idempotency_key, tick_ordinal,
				            command_key, request_binding,
			            terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			            prepared_event_digest, prepared_at,
			            terminal_event_type, terminal_event_sequence,
				            terminal_event_digest, terminal_event_from_event,
				            privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
				            status, new_ref, error, lease_token,
				            lease_until, created_at, updated_at, terminal_at`,
					command.TenantID, command.ScheduleID, command.RunID, leaseToken,
					leaseDuration.Seconds(), command.TickIdempotencyKey, command.TickOrdinal), &out)
				if errors.Is(err, pgx.ErrNoRows) {
					out.ClaimState = SecretRotationScheduleCommandBusy
					return nil
				}
				if err != nil {
					return err
				}
				out.ClaimState = SecretRotationScheduleCommandRecovered
				acquired = true
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}

			live, err := lockSecretRotationScheduleForCommandTx(ctx, tx, command.TenantID, command.ScheduleID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("%w: exact live schedule revision is missing", ErrSecretRotationScheduleCommandConflict)
				}
				return err
			}
			if live.ConfigEventSequence > command.ConfigEventSequence {
				return fmt.Errorf("%w: frozen schedule revision %d was superseded by revision %d",
					ErrSecretRotationScheduleDueEdgeStale, command.ConfigEventSequence, live.ConfigEventSequence)
			}
			live.IdentityVersion = command.IdentityVersion
			live.TenantRegistrationEventID = command.TenantRegistrationEventID
			live.TenantRegistrationEventSequence = command.TenantRegistrationEventSequence
			if live.ConfigEventSequence != command.ConfigEventSequence || !live.Enabled ||
				!sameSecretRotationScheduleSnapshot(live, SecretRotationSchedule{
					ID: command.ScheduleID, TenantID: command.TenantID,
					IdentityVersion:                 command.IdentityVersion,
					TenantRegistrationEventID:       command.TenantRegistrationEventID,
					TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
					Provider:                        command.Provider,
					Key:                             command.Key, OldRef: command.OldRef, IntervalSeconds: command.IntervalSeconds,
					ConfigEventSequence: command.ConfigEventSequence, Enabled: true, NextRunAt: command.DueAt,
				}) {
				return fmt.Errorf("%w: live schedule differs from its frozen configuration revision", ErrSecretRotationScheduleCommandConflict)
			}
			tag, err := tx.Exec(ctx,
				`INSERT INTO secret_rotation_schedule_commands
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         schedule_id, run_id, due_at, provider, secret_key,
			         old_ref, interval_seconds, config_event_sequence,
			         tick_idempotency_key, tick_ordinal,
			         command_key, request_binding, terminal_event_id,
			         lease_token, lease_until, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6::uuid, $7, $8, $9, $10, $11, $12, $13, $14,
			         $15, $16, $17,
			         $18,
			         clock_timestamp() + make_interval(secs => $19::double precision),
			         clock_timestamp(), clock_timestamp())
			 ON CONFLICT DO NOTHING`,
				command.TenantID, command.IdentityVersion, command.TenantRegistrationEventID,
				command.TenantRegistrationEventSequence,
				command.ScheduleID, command.RunID, command.DueAt,
				command.Provider, command.Key, command.OldRef, command.IntervalSeconds,
				command.ConfigEventSequence, command.TickIdempotencyKey, command.TickOrdinal,
				command.CommandKey, command.RequestBinding,
				command.TerminalEventID, leaseToken, leaseDuration.Seconds())
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				if err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
					`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
				        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
				        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
				        tick_idempotency_key, tick_ordinal,
				        command_key, request_binding,
			        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			        prepared_event_digest, prepared_at,
			        terminal_event_type, terminal_event_sequence,
				        terminal_event_digest, terminal_event_from_event,
				        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
				        status, new_ref, error, lease_token,
				        lease_until, created_at, updated_at, terminal_at
				   FROM secret_rotation_schedule_commands
				  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid`,
					command.TenantID, command.ScheduleID, command.RunID), &out); err != nil {
					return err
				}
				out.ClaimState = SecretRotationScheduleCommandCreated
				acquired = true
				return nil
			}
			if err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
				`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
			        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        tick_idempotency_key, tick_ordinal,
			        command_key, request_binding,
			        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			        prepared_event_digest, prepared_at,
			        terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			        status, new_ref, error, lease_token,
			        lease_until, created_at, updated_at, terminal_at
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND identity_version = $2
			    AND tenant_registration_event_id = $3
			    AND tenant_registration_event_sequence = $4
			    AND schedule_id = $5 AND due_at = $6
			  FOR UPDATE`, command.TenantID, command.IdentityVersion,
				command.TenantRegistrationEventID, command.TenantRegistrationEventSequence,
				command.ScheduleID, command.DueAt), &out); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleCommandDueEdge(out, command); err != nil {
				return err
			}
			if out.Status == "claimed" {
				out.ClaimState = SecretRotationScheduleCommandBusy
			} else {
				out.ClaimState = SecretRotationScheduleCommandTerminal
			}
			return nil
		})
	return out, acquired, err
}

func lockAndValidateSecretRotationScheduleTickChildTx(
	ctx context.Context,
	tx pgx.Tx,
	command SecretRotationScheduleCommand,
	leaseToken string,
) error {
	if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, command.TenantID,
		command.IdentityVersion, command.TenantRegistrationEventID,
		command.TenantRegistrationEventSequence); err != nil {
		return err
	}
	cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, command.TenantID)
	if err != nil {
		return err
	}
	var tick SecretRotationScheduleTick
	if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
		secretRotationScheduleTickSelect+`
		 WHERE tenant_id = $1 AND idempotency_key = $2
		 FOR UPDATE`, command.TenantID, command.TickIdempotencyKey), &tick); err != nil {
		return fmt.Errorf("%w: load active aggregate tick: %v", ErrSecretRotationScheduleCommandConflict, err)
	}
	if !active || cursor.ActiveTickKey != tick.IdempotencyKey ||
		cursor.ActiveTickBinding != tick.RequestBinding || cursor.LeaseToken != tick.OwnerToken ||
		cursor.LeaseGeneration != tick.OwnerGeneration || tick.Phase != "row_started" ||
		tick.CurrentSchedule == nil || tick.CurrentCommandLeaseToken != leaseToken ||
		command.TickOrdinal != tick.Scanned+1 ||
		command.IdentityVersion != tick.IdentityVersion ||
		command.TenantRegistrationEventID != tick.TenantRegistrationEventID ||
		command.TenantRegistrationEventSequence != tick.TenantRegistrationEventSequence ||
		!sameSecretRotationScheduleSnapshot(*tick.CurrentSchedule, SecretRotationSchedule{
			ID: command.ScheduleID, TenantID: command.TenantID,
			IdentityVersion:                 command.IdentityVersion,
			TenantRegistrationEventID:       command.TenantRegistrationEventID,
			TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
			Provider:                        command.Provider,
			Key:                             command.Key, OldRef: command.OldRef, IntervalSeconds: command.IntervalSeconds,
			ConfigEventSequence: command.ConfigEventSequence, Enabled: true, NextRunAt: command.DueAt,
		}) {
		return fmt.Errorf("%w: child command is outside live aggregate authority", ErrSecretRotationScheduleCommandConflict)
	}
	if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, tick); err != nil {
		return err
	}
	snapshot, err := getSecretRotationScheduleTickRowTx(
		ctx, tx, command.TenantID, command.TickIdempotencyKey, command.TickOrdinal)
	if err != nil || !sameSecretRotationScheduleSnapshot(snapshot, *tick.CurrentSchedule) {
		return fmt.Errorf("%w: command differs from immutable tick ordinal: %v", ErrSecretRotationScheduleCommandConflict, err)
	}
	return nil
}

func lockSecretRotationScheduleForCommandTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, scheduleID string,
) (SecretRotationSchedule, error) {
	var schedule SecretRotationSchedule
	err := tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, provider, secret_key, old_ref,
		        interval_seconds, config_event_sequence, enabled, next_run_at
		   FROM secret_rotation_schedules
		  WHERE tenant_id = $1 AND id = $2
		  FOR UPDATE`, tenantID, scheduleID).Scan(
		&schedule.ID, &schedule.TenantID, &schedule.Provider, &schedule.Key, &schedule.OldRef,
		&schedule.IntervalSeconds, &schedule.ConfigEventSequence, &schedule.Enabled, &schedule.NextRunAt)
	return schedule, err
}

// PrepareSecretRotationScheduleCommandTerminal freezes the exact terminal
// outcome before the deterministic event is appended. If the process dies after
// the provider effect, recovery can append this retained intent without running
// that effect again. The transaction revalidates the live aggregate child lease
// before it locks the command, preserving cursor -> tick -> snapshot -> command
// order under the privacy and backup fences.
func (s *Store) PrepareSecretRotationScheduleCommandTerminal(
	ctx context.Context,
	run SecretRotationScheduleRun,
) (SecretRotationScheduleCommand, error) {
	var out SecretRotationScheduleCommand
	if run.TickIdempotencyKey == "" || run.TickOrdinal <= 0 || run.TickOrdinal > 500 || run.LeaseToken == "" ||
		!secretRotationScheduleTerminalStatus(run.Status) || len(run.EventDigest) != 64 ||
		!IsCanonicalSecretRotationScheduleError(run.Status, run.Error) ||
		run.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		!validSecretRotationScheduleTenantRegistration(run.TenantRegistrationEventID, run.TenantRegistrationEventSequence) ||
		!rotationcommand.Matches(run.TenantID, run.TenantRegistrationEventSequence, run.ScheduleID,
			run.RunID, run.DueAt, run.CommandKey, run.EventID) {
		return out, fmt.Errorf("%w: terminal intent lacks exact aggregate and event authority", ErrSecretRotationScheduleCommandConflict)
	}
	want := SecretRotationScheduleCommand{
		TenantID: run.TenantID, IdentityVersion: run.IdentityVersion,
		TenantRegistrationEventID:       run.TenantRegistrationEventID,
		TenantRegistrationEventSequence: run.TenantRegistrationEventSequence,
		ScheduleID:                      run.ScheduleID, RunID: run.RunID, DueAt: run.DueAt,
		Provider: run.Provider, Key: run.Key, OldRef: run.OldRef,
		IntervalSeconds: run.IntervalSeconds, ConfigEventSequence: run.ConfigEventSequence,
		TickIdempotencyKey: run.TickIdempotencyKey, TickOrdinal: run.TickOrdinal,
		CommandKey: run.CommandKey, RequestBinding: run.RequestBinding, TerminalEventID: run.EventID,
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, run.TenantID, "secret rotation scheduler terminal intent", func(tx pgx.Tx) error {
			if err := lockAndValidateSecretRotationScheduleTickChildTx(ctx, tx, want, run.LeaseToken); err != nil {
				return err
			}
			if err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
				`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
			        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        tick_idempotency_key, tick_ordinal,
			        command_key, request_binding,
			        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			        prepared_event_digest, prepared_at,
			        terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			        status, new_ref, error, lease_token,
			        lease_until, created_at, updated_at, terminal_at
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
			  FOR UPDATE`, run.TenantID, run.ScheduleID, run.RunID), &out); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleCommandDueEdge(out, want); err != nil {
				return err
			}
			if out.Status != "claimed" {
				return validateSecretRotationSchedulePreparedIntent(out, run)
			}
			if out.LeaseToken != run.LeaseToken || out.LeaseUntil == nil {
				return fmt.Errorf("%w: terminal intent lease is not owned", ErrSecretRotationScheduleCommandConflict)
			}
			if out.PreparedStatus != "" {
				return validateSecretRotationSchedulePreparedIntent(out, run)
			}
			var requestedAt *time.Time
			if !run.RanAt.IsZero() {
				at := run.RanAt
				requestedAt = &at
			}
			if err := scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
				`UPDATE secret_rotation_schedule_commands
			    SET prepared_status = $5, prepared_new_ref = $6,
			        prepared_error = $7, prepared_event_digest = $8,
			        prepared_at = coalesce($9::timestamptz, clock_timestamp()),
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
			    AND status = 'claimed' AND lease_token = $4
			    AND prepared_status = '' AND prepared_at IS NULL
			  RETURNING tenant_id::text, identity_version, tenant_registration_event_id,
			            tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			            provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			            tick_idempotency_key, tick_ordinal,
			            command_key, request_binding,
			            terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
			            prepared_event_digest, prepared_at,
			            terminal_event_type, terminal_event_sequence,
			            terminal_event_digest, terminal_event_from_event,
			            privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			            status, new_ref, error, lease_token,
			            lease_until, created_at, updated_at, terminal_at`,
				run.TenantID, run.ScheduleID, run.RunID, run.LeaseToken,
				run.Status, run.NewRef, run.Error, run.EventDigest, requestedAt), &out); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("%w: terminal intent CAS lost command authority", ErrSecretRotationScheduleCommandConflict)
				}
				return err
			}
			return validateSecretRotationSchedulePreparedIntent(out, run)
		})
	return out, err
}

func validateSecretRotationSchedulePreparedIntent(
	command SecretRotationScheduleCommand,
	run SecretRotationScheduleRun,
) error {
	if command.PreparedAt == nil || command.PreparedStatus != run.Status ||
		command.PreparedNewRef != run.NewRef || command.PreparedError != run.Error ||
		command.PreparedEventDigest != run.EventDigest ||
		(!run.RanAt.IsZero() && !command.PreparedAt.Truncate(time.Microsecond).Equal(run.RanAt.Truncate(time.Microsecond))) {
		return fmt.Errorf("%w: retained terminal intent differs", ErrSecretRotationScheduleCommandConflict)
	}
	if command.Status != "claimed" {
		if command.Status != command.PreparedStatus || command.NewRef != command.PreparedNewRef ||
			command.Error != command.PreparedError || command.TerminalAt == nil ||
			!command.TerminalAt.Truncate(time.Microsecond).Equal(command.PreparedAt.Truncate(time.Microsecond)) ||
			command.TerminalEventDigest != command.PreparedEventDigest {
			return fmt.Errorf("%w: terminal receipt differs from its prepared intent", ErrSecretRotationScheduleCommandConflict)
		}
	}
	return nil
}

// ReleaseSecretRotationScheduleCommandLease makes a known retryable or
// ambiguous row immediately resumable without changing its due edge. A crash
// needs no release: lease expiry provides the bounded recovery path. A stale
// token fails closed; only an already-terminal receipt is a safe no-op.
func (s *Store) ReleaseSecretRotationScheduleCommandLease(ctx context.Context, tenantID, scheduleID, runID, leaseToken string) error {
	if leaseToken == "" {
		return fmt.Errorf("%w: empty lease token cannot release a claimed command", ErrSecretRotationScheduleCommandConflict)
	}
	return s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tenantID, "secret rotation scheduler child release", func(tx pgx.Tx) error {
			registration, err := s.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_commands
			    SET lease_token = '', lease_until = NULL, updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
			    AND identity_version = 3
			    AND tenant_registration_event_sequence = $5
			    AND status = 'claimed' AND lease_token = $4`,
				tenantID, scheduleID, runID, leaseToken, registration.EventSeq)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				return nil
			}
			if tag.RowsAffected() != 0 {
				return fmt.Errorf("%w: release changed %d command rows", ErrSecretRotationScheduleCommandConflict, tag.RowsAffected())
			}

			// A projector may have terminalized the exact command while release was
			// waiting for its row lock. The table constraint proves every non-claimed
			// status carries a complete retained terminal-event receipt, so that race
			// is the only safe no-op. Missing rows, already-released claims, and stale
			// tokens have no such proof and must fail closed.
			var status string
			err = tx.QueryRow(ctx,
				`SELECT status
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
			    AND identity_version = 3
			    AND tenant_registration_event_sequence = $4
			  FOR UPDATE`, tenantID, scheduleID, runID, registration.EventSeq).Scan(&status)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: command to release does not exist", ErrSecretRotationScheduleCommandConflict)
			}
			if err != nil {
				return err
			}
			if secretRotationScheduleTerminalStatus(status) {
				return nil
			}
			return fmt.Errorf("%w: lease token no longer owns claimed command", ErrSecretRotationScheduleCommandConflict)
		})
}

// GetSecretRotationScheduleCommand loads durable authority for reconciliation.
func (s *Store) GetSecretRotationScheduleCommand(ctx context.Context, tenantID, scheduleID, runID string) (SecretRotationScheduleCommand, error) {
	var out SecretRotationScheduleCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
			`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
			        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        tick_idempotency_key, tick_ordinal,
			        command_key, request_binding,
		        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
		        prepared_event_digest, prepared_at,
		        terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			        status, new_ref, error, lease_token,
			        lease_until, created_at, updated_at, terminal_at
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid`,
			tenantID, scheduleID, runID), &out)
	})
	return out, err
}

// GetLatestSecretRotationScheduleCommand returns the newest current-lifecycle
// receiver for scheduler diagnostics and overlap tests. It is not authority for
// a purged due edge: direct reconciliation requires that edge's own command row
// and never scans the event log from this newer row.
func (s *Store) GetLatestSecretRotationScheduleCommand(ctx context.Context, tenantID, scheduleID string) (SecretRotationScheduleCommand, error) {
	var out SecretRotationScheduleCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationScheduleCommand(tx.QueryRow(ctx,
			`SELECT tenant_id::text, identity_version, tenant_registration_event_id,
			        tenant_registration_event_sequence, schedule_id::text, run_id::text, due_at,
			        provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        tick_idempotency_key, tick_ordinal,
			        command_key, request_binding,
		        terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
		        prepared_event_digest, prepared_at,
		        terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
			        status, new_ref, error, lease_token,
			        lease_until, created_at, updated_at, terminal_at
			   FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2
			    AND (
			        (identity_version = 3 AND tenant_registration_event_sequence = (
			            SELECT event_seq FROM tenants WHERE tenant_id = $1
			        ))
			        OR
			        (identity_version = 2 AND terminal_event_sequence >= (
			            SELECT event_seq FROM tenants WHERE tenant_id = $1
			        ))
			    )
			  ORDER BY due_at DESC, run_id DESC
			  LIMIT 1`, tenantID, scheduleID), &out)
	})
	return out, err
}

// ListSecretRotationScheduleCommandGCCandidates returns terminal command
// receivers whose schedule has already moved beyond their exact due edge. The
// caller must still verify the retained immutable event named by each receipt;
// SQL alone cannot prove the event log still owns that evidence.
func (s *Store) ListSecretRotationScheduleCommandGCCandidates(
	ctx context.Context,
	tenantID string,
	limit int,
) ([]SecretRotationScheduleCommand, error) {
	if limit <= 0 {
		return nil, nil
	}
	var out []SecretRotationScheduleCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT c.tenant_id::text, c.identity_version, c.tenant_registration_event_id,
			        c.tenant_registration_event_sequence, c.schedule_id::text, c.run_id::text, c.due_at,
			        c.provider, c.secret_key, c.old_ref, c.interval_seconds, c.config_event_sequence,
			        c.tick_idempotency_key, c.tick_ordinal,
			        c.command_key, c.request_binding,
			        c.terminal_event_id, c.prepared_status, c.prepared_new_ref, c.prepared_error,
			        c.prepared_event_digest, c.prepared_at,
			        c.terminal_event_type, c.terminal_event_sequence,
			        c.terminal_event_digest, c.terminal_event_from_event,
			        c.privacy_rewrite_version, c.privacy_subject_ref, c.privacy_operation_id, c.privacy_event_id,
			        c.status, c.new_ref, c.error, c.lease_token,
			        c.lease_until, c.created_at, c.updated_at, c.terminal_at
			   FROM secret_rotation_schedule_commands c
			   JOIN secret_rotation_schedules s
			     ON s.tenant_id = c.tenant_id AND s.id = c.schedule_id
			  WHERE c.tenant_id = $1
			    AND c.identity_version = 3
			    AND c.tenant_registration_event_sequence = (
			        SELECT event_seq FROM tenants WHERE tenant_id = $1
			    )
			    AND c.status <> 'claimed'
			    AND c.terminal_event_from_event IS TRUE
			    AND s.next_run_at > c.due_at
			    AND EXISTS (
			        SELECT 1
			          FROM secret_rotation_schedule_commands newer
			         WHERE newer.tenant_id = c.tenant_id
			           AND newer.identity_version = c.identity_version
			           AND newer.tenant_registration_event_sequence = c.tenant_registration_event_sequence
			           AND newer.schedule_id = c.schedule_id
			           AND newer.due_at > c.due_at
			    )
			  ORDER BY c.terminal_at, c.run_id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var command SecretRotationScheduleCommand
			if err := scanSecretRotationScheduleCommand(rows, &command); err != nil {
				return err
			}
			out = append(out, command)
		}
		return rows.Err()
	})
	return out, err
}

// PurgeVerifiedSecretRotationScheduleCommand removes one terminal receiver only
// after its caller has matched the exact retained event. The owner-role DELETE
// repeats every durable receipt predicate and the advanced-due-edge predicate,
// so a concurrent lease/receipt/schedule change makes the purge a safe no-op.
// Claimed or ambiguous commands can never match.
func (s *Store) PurgeVerifiedSecretRotationScheduleCommand(
	ctx context.Context,
	command SecretRotationScheduleCommand,
) (bool, error) {
	if command.Status == "claimed" || command.TerminalEventSequence == nil || command.TerminalAt == nil ||
		command.PreparedAt == nil || command.TerminalEventFromEvent == nil || !*command.TerminalEventFromEvent {
		return false, fmt.Errorf("%w: only event-derived terminal commands may be purged", ErrSecretRotationScheduleCommandConflict)
	}
	deleted := false
	err := s.WithTenantProjection(ctx, command.TenantID, func(tx pgx.Tx) error {
		if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, command.TenantID,
			command.IdentityVersion, command.TenantRegistrationEventID,
			command.TenantRegistrationEventSequence); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM secret_rotation_schedule_commands c
			  USING secret_rotation_schedules s
			  WHERE c.tenant_id = $1 AND c.schedule_id = $2 AND c.run_id = $3::uuid
			    AND c.due_at = $4::timestamptz
			    AND c.status = $5 AND c.status <> 'claimed'
			    AND c.terminal_event_id = $6
			    AND c.terminal_event_type = $7
			    AND c.terminal_event_sequence = $8
			    AND c.terminal_event_digest = $9
			    AND c.provider = $10 AND c.secret_key = $11 AND c.old_ref = $12
			    AND c.interval_seconds = $13 AND c.config_event_sequence = $14
			    AND c.tick_idempotency_key = $15 AND c.tick_ordinal = $16
			    AND c.command_key = $17 AND c.request_binding = $18
			    AND c.terminal_at = $19::timestamptz
			    AND c.new_ref = $20 AND c.error = $21
			    AND c.prepared_status = $22 AND c.prepared_new_ref = $23
				    AND c.prepared_error = $24 AND c.prepared_event_digest = $25
				    AND c.prepared_at = $26::timestamptz
				    AND c.identity_version = $27
				    AND c.tenant_registration_event_id = $28
				    AND c.tenant_registration_event_sequence = $29
			    AND c.terminal_event_from_event IS TRUE
			    AND c.privacy_rewrite_version = 0
			    AND c.privacy_subject_ref = '' AND c.privacy_operation_id = '' AND c.privacy_event_id = ''
			    AND s.tenant_id = c.tenant_id AND s.id = c.schedule_id
			    AND s.next_run_at > c.due_at
			    AND EXISTS (
			        SELECT 1
			          FROM secret_rotation_schedule_commands newer
				         WHERE newer.tenant_id = c.tenant_id
				           AND newer.identity_version = c.identity_version
				           AND newer.tenant_registration_event_sequence = c.tenant_registration_event_sequence
				           AND newer.schedule_id = c.schedule_id
			           AND newer.due_at > c.due_at
			    )`,
			command.TenantID, command.ScheduleID, command.RunID, command.DueAt,
			command.Status, command.TerminalEventID, command.TerminalEventType,
			*command.TerminalEventSequence, command.TerminalEventDigest,
			command.Provider, command.Key, command.OldRef, command.IntervalSeconds,
			command.ConfigEventSequence, command.TickIdempotencyKey, command.TickOrdinal,
			command.CommandKey, command.RequestBinding, *command.TerminalAt,
			command.NewRef, command.Error, command.PreparedStatus, command.PreparedNewRef,
			command.PreparedError, command.PreparedEventDigest, *command.PreparedAt,
			command.IdentityVersion, command.TenantRegistrationEventID,
			command.TenantRegistrationEventSequence)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected() == 1
		return nil
	})
	return deleted, err
}

func validateSecretRotationScheduleCommandDueEdge(got, want SecretRotationScheduleCommand) error {
	if got.TenantID != want.TenantID || got.IdentityVersion != want.IdentityVersion ||
		got.TenantRegistrationEventID != want.TenantRegistrationEventID ||
		got.TenantRegistrationEventSequence != want.TenantRegistrationEventSequence ||
		got.ScheduleID != want.ScheduleID || got.RunID != want.RunID ||
		!got.DueAt.Equal(want.DueAt) || got.Provider != want.Provider || got.Key != want.Key ||
		got.OldRef != want.OldRef || got.IntervalSeconds != want.IntervalSeconds ||
		got.ConfigEventSequence != want.ConfigEventSequence || got.CommandKey != want.CommandKey ||
		got.RequestBinding != want.RequestBinding || got.TerminalEventID != want.TerminalEventID {
		return fmt.Errorf("%w: deterministic due-edge tuple differs", ErrSecretRotationScheduleCommandConflict)
	}
	return nil
}

func scanSecretRotationScheduleCommand(row rowScanner, command *SecretRotationScheduleCommand) error {
	return row.Scan(&command.TenantID, &command.IdentityVersion,
		&command.TenantRegistrationEventID, &command.TenantRegistrationEventSequence,
		&command.ScheduleID, &command.RunID, &command.DueAt,
		&command.Provider, &command.Key, &command.OldRef, &command.IntervalSeconds,
		&command.ConfigEventSequence, &command.TickIdempotencyKey, &command.TickOrdinal, &command.CommandKey,
		&command.RequestBinding, &command.TerminalEventID,
		&command.PreparedStatus, &command.PreparedNewRef, &command.PreparedError,
		&command.PreparedEventDigest, &command.PreparedAt, &command.TerminalEventType,
		&command.TerminalEventSequence, &command.TerminalEventDigest, &command.TerminalEventFromEvent,
		&command.PrivacyRewriteVersion, &command.PrivacySubjectRef,
		&command.PrivacyOperationID, &command.PrivacyEventID, &command.Status,
		&command.NewRef, &command.Error, &command.LeaseToken, &command.LeaseUntil,
		&command.CreatedAt, &command.UpdatedAt, &command.TerminalAt)
}

// GetSecretRotationScheduleScanCursor loads retained scheduler position for
// recovery diagnostics and tests. Ordinary scheduler code claims it instead.
func (s *Store) GetSecretRotationScheduleScanCursor(ctx context.Context, tenantID string) (SecretRotationScheduleScanCursor, error) {
	var out SecretRotationScheduleScanCursor
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationScheduleScanCursor(tx.QueryRow(ctx,
			`SELECT tenant_id::text, after_schedule_id::text,
			        active_tick_key, active_tick_binding, lease_token,
			        lease_until, lease_generation, generation, updated_at
			   FROM secret_rotation_schedule_scan_cursors
			  WHERE tenant_id = $1`, tenantID), &out)
	})
	return out, err
}

func scanSecretRotationScheduleScanCursor(row rowScanner, cursor *SecretRotationScheduleScanCursor) error {
	return row.Scan(&cursor.TenantID, &cursor.AfterScheduleID,
		&cursor.ActiveTickKey, &cursor.ActiveTickBinding, &cursor.LeaseToken,
		&cursor.LeaseUntil, &cursor.LeaseGeneration, &cursor.Generation, &cursor.UpdatedAt)
}

// ListSecretRotationSchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListSecretRotationSchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]SecretRotationSchedule, error) {
	var out []SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched SecretRotationSchedule
			if err := scanSecretRotationSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// ListDueSecretRotationSchedules loads the first page of enabled tenant schedules
// due no later than now, oldest due time first.
func (s *Store) ListDueSecretRotationSchedules(ctx context.Context, tenantID string, now time.Time, limit int) ([]SecretRotationSchedule, error) {
	return s.ListDueSecretRotationSchedulesPage(ctx, tenantID, now, time.Time{}, "", limit)
}

// ListDueSecretRotationSchedulesPage keyset-pages the due queue by its immutable
// scan tuple. A scheduler can therefore look past deferred oldest rows without an
// unbounded query or OFFSET races as earlier rows advance their next_run_at.
func (s *Store) ListDueSecretRotationSchedulesPage(
	ctx context.Context,
	tenantID string,
	now, afterNextRunAt time.Time,
	afterID string,
	limit int,
) ([]SecretRotationSchedule, error) {
	var out []SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND enabled AND next_run_at <= $2
			    AND (next_run_at > $3 OR (next_run_at = $3 AND id::text > $4))
			  ORDER BY next_run_at, id LIMIT $5`, tenantID, now, afterNextRunAt, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched SecretRotationSchedule
			if err := scanSecretRotationSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// ListDueSecretRotationSchedulesRingPage scans due rows in stable UUID order.
// An empty throughID is the unbounded tail after afterID. A non-empty throughID
// is the wrapped head, bounded inclusively by the cursor captured when the tick
// began. Together those two segments visit each schedule at most once per tick.
// Rows that become due after dueThrough are intentionally left for the next
// ring; a deleted cursor UUID remains a valid ordering boundary.
func (s *Store) ListDueSecretRotationSchedulesRingPage(
	ctx context.Context,
	tenantID string,
	dueThrough time.Time,
	afterID, throughID string,
	limit int,
) ([]SecretRotationSchedule, error) {
	if limit <= 0 {
		return nil, nil
	}
	if afterID == "" {
		afterID = ZeroUUID
	}
	var out []SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND enabled AND next_run_at <= $2
			    AND id > $3::uuid
			    AND ($4 = '' OR id <= NULLIF($4, '')::uuid)
			  ORDER BY id
			  LIMIT $5`, tenantID, dueThrough, afterID, throughID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched SecretRotationSchedule
			if err := scanSecretRotationSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// GetSecretRotationSchedule loads one tenant-scoped rotation schedule.
func (s *Store) GetSecretRotationSchedule(ctx context.Context, tenantID, id string) (SecretRotationSchedule, error) {
	var out SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationSchedule(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds, config_event_sequence,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

func scanSecretRotationSchedule(row rowScanner, sched *SecretRotationSchedule) error {
	if err := row.Scan(&sched.ID, &sched.TenantID, &sched.Name, &sched.Provider, &sched.Key,
		&sched.OldRef, &sched.IntervalSeconds, &sched.ConfigEventSequence, &sched.Enabled, &sched.NextRunAt,
		&sched.LastRunID, &sched.LastRunAt, &sched.LastRunStatus, &sched.LastNewRef,
		&sched.LastError, &sched.CreatedAt, &sched.UpdatedAt); err != nil {
		return err
	}
	// Existing installations can have v1 rows written before scheduler errors
	// became a closed vocabulary. Never let those bytes cross a store read seam,
	// even if a migration has not run yet or a restored snapshot predates it.
	sched.LastError = CanonicalSecretRotationScheduleError(sched.LastRunStatus, sched.LastError)
	return nil
}
