// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/rotationcommand"
)

const secretRotationScheduleStartupPageSize = 128

type secretRotationScheduleStartupOuter struct {
	Status         string
	RequestBinding string
	ResultCodec    string
	CreatedAt      time.Time
	CompletedAt    *time.Time
	HasResult      bool
}

type secretRotationScheduleStartupTenant struct {
	TenantID          string
	RequiresAuthority bool
}

type secretRotationScheduleStartupRegistration struct {
	EventID       string
	EventSequence uint64
}

type secretRotationScheduleStartupTickRow struct {
	Ordinal  int
	Schedule SecretRotationSchedule
}

// SecretRotationScheduleRegistrationResolver proves the exact immutable
// tenant.registered envelope that owns the current live tenant lifecycle. The
// startup validator invokes it while holding the tenant privacy barrier; the
// caller may therefore pin event history without reversing the global lock
// order.
type SecretRotationScheduleRegistrationResolver func(
	context.Context,
	string,
) (eventID string, eventSequence uint64, err error)

// ValidateSecretRotationScheduleStartupAuthority checks the independent
// PostgreSQL scheduler receivers before this process can advertise readiness.
// The system query inventories tenant UUIDs plus one current-version-presence
// bit only. Every receiver and receipt is then reloaded under that tenant's
// FORCE-RLS context, shared privacy barrier, lifecycle fence, backup fence, and
// one repeatable-read snapshot.
//
// Both inventories page in fixed-size batches. This keeps startup memory bounded
// without weakening the all-row check. Version-2 and prior-registration version-3
// rows remain inert history; only authority belonging to the live registration is
// allowed to participate in a cursor or block startup.
func (s *Store) ValidateSecretRotationScheduleStartupAuthority(
	ctx context.Context,
	resolveRegistration SecretRotationScheduleRegistrationResolver,
) error {
	afterTenantID := ""
	for {
		//trstctl:system-query — cross-tenant system startup enumerates only tenant UUIDs and current-version scheduler ownership; every payload, receipt, binding, and command reloads under that tenant's FORCE-RLS privacy barrier (AN-1 exemption).
		rows, err := s.pool.Query(ctx, `
			SELECT tenant_id::text, bool_or(requires_authority)
			  FROM (
			        SELECT tenant_id, false AS requires_authority
			          FROM secret_rotation_schedule_scan_cursors
			        UNION ALL
			        SELECT tenant_id, true AS requires_authority
			          FROM secret_rotation_schedule_ticks
			         WHERE identity_version = 3
			        UNION ALL
			        SELECT tenant_id, true AS requires_authority
			          FROM secret_rotation_schedule_commands
			         WHERE identity_version = 3
			        UNION ALL
			        SELECT tenant_id, true AS requires_authority
			          FROM idempotency_keys
			         WHERE left(key, length($1)) = $1
			       ) AS scheduler_tenants
			 WHERE tenant_id::text > $2
			 GROUP BY tenant_id
			 ORDER BY tenant_id::text
			 LIMIT $3`, rotationcommand.OuterKeyV3Prefix, afterTenantID,
			secretRotationScheduleStartupPageSize)
		if err != nil {
			return fmt.Errorf("store: inventory scheduler startup tenants: %w", err)
		}
		tenants := make([]secretRotationScheduleStartupTenant, 0, secretRotationScheduleStartupPageSize)
		for rows.Next() {
			var tenant secretRotationScheduleStartupTenant
			if err := rows.Scan(&tenant.TenantID, &tenant.RequiresAuthority); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan scheduler startup tenant: %w", err)
			}
			tenants = append(tenants, tenant)
		}
		rowsErr := rows.Err()
		rows.Close()
		if rowsErr != nil {
			return fmt.Errorf("store: enumerate scheduler startup tenants: %w", rowsErr)
		}
		if len(tenants) == 0 {
			return nil
		}
		for _, tenant := range tenants {
			err := s.WithPrivacyRecoveryBarrier(
				ctx, tenant.TenantID, "secret rotation scheduler startup validation",
				func(barrierCtx context.Context) error {
					var registration secretRotationScheduleStartupRegistration
					if tenant.RequiresAuthority {
						if resolveRegistration == nil {
							return fmt.Errorf("%w: exact live tenant registration resolver is unavailable",
								ErrSecretRotationScheduleTickConflict)
						}
						var err error
						registration.EventID, registration.EventSequence, err =
							resolveRegistration(barrierCtx, tenant.TenantID)
						if err != nil {
							return err
						}
						if !validSecretRotationScheduleTenantRegistration(
							registration.EventID, registration.EventSequence,
						) {
							return fmt.Errorf("%w: resolved live tenant registration is malformed",
								ErrSecretRotationScheduleTickConflict)
						}
					}
					return s.WithTenantProjectionRepeatableRead(
						barrierCtx, tenant.TenantID, func(tx pgx.Tx) error {
							return s.validateSecretRotationScheduleStartupTenantTx(
								barrierCtx, tx, tenant.TenantID, registration)
						})
				})
			if err != nil {
				return fmt.Errorf("store: validate scheduler startup authority for tenant %s: %w",
					tenant.TenantID, err)
			}
		}
		afterTenantID = tenants[len(tenants)-1].TenantID
		if len(tenants) < secretRotationScheduleStartupPageSize {
			return nil
		}
	}
}

func (s *Store) validateSecretRotationScheduleStartupTenantTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	expectedRegistration secretRotationScheduleStartupRegistration,
) error {
	registration, err := s.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID)
	if err != nil || !registration.Exists {
		return fmt.Errorf("%w: scheduler operational tenant has no live registration: %v",
			ErrSecretRotationScheduleTickConflict, err)
	}
	if expectedRegistration.EventSequence != 0 &&
		registration.EventSeq != expectedRegistration.EventSequence {
		return fmt.Errorf("%w: live tenant registration changed during startup validation",
			ErrSecretRotationScheduleTickConflict)
	}

	var cursor SecretRotationScheduleScanCursor
	cursorExists := true
	err = scanSecretRotationScheduleScanCursor(tx.QueryRow(ctx, `
		SELECT tenant_id::text, after_schedule_id::text,
		       active_tick_key, active_tick_binding, lease_token,
		       lease_until, lease_generation, generation, updated_at
		  FROM secret_rotation_schedule_scan_cursors
		 WHERE tenant_id = $1`, tenantID), &cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		cursorExists = false
	} else if err != nil {
		return err
	}

	if cursorExists && cursor.ActiveTickKey != "" {
		tick, exists, err := loadSecretRotationScheduleStartupTickTx(
			ctx, tx, tenantID, cursor.ActiveTickKey)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: scheduler cursor names a missing current-v3 tick",
				ErrSecretRotationScheduleTickConflict)
		}
		if tick.TenantRegistrationEventSequence != registration.EventSeq {
			return fmt.Errorf("%w: scheduler cursor names another tenant registration",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleStartupRegistration(
			expectedRegistration, tick.TenantRegistrationEventID,
			tick.TenantRegistrationEventSequence, ErrSecretRotationScheduleTickConflict,
		); err != nil {
			return err
		}
		if tick.Phase == "terminal" || tick.Phase == "privacy_erased" {
			return fmt.Errorf("%w: scheduler cursor names a closed tick",
				ErrSecretRotationScheduleTickConflict)
		}
		if cursor.ActiveTickBinding != tick.RequestBinding ||
			cursor.LeaseToken == "" || cursor.LeaseUntil == nil ||
			cursor.LeaseToken != tick.OwnerToken ||
			cursor.LeaseGeneration != tick.OwnerGeneration {
			return fmt.Errorf("%w: scheduler cursor and active tick owner disagree",
				ErrSecretRotationScheduleTickConflict)
		}
	}

	afterKey := ""
	for {
		keys, err := listSecretRotationScheduleStartupKeysTx(ctx, tx, tenantID, afterKey)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			break
		}
		for _, key := range keys {
			tick, tickExists, err := loadSecretRotationScheduleStartupTickTx(ctx, tx, tenantID, key)
			if err != nil {
				return err
			}
			if !tickExists {
				if !isSecretRotationScheduleDerivedOuterKey(key) {
					return fmt.Errorf("%w: scheduler startup inventory contains an unknown outer key",
						ErrSecretRotationScheduleTickConflict)
				}
				return fmt.Errorf("%w: derived scheduler outer key has no aggregate tick",
					ErrSecretRotationScheduleTickConflict)
			}
			if tick.TenantRegistrationEventSequence < registration.EventSeq {
				// A prior lifecycle cannot be claimed by the current producer. Keep it
				// as inert recovery/history evidence without interpreting old receipts.
				continue
			}
			if tick.TenantRegistrationEventSequence > registration.EventSeq {
				return fmt.Errorf("%w: scheduler tick belongs to a future tenant registration",
					ErrSecretRotationScheduleTickConflict)
			}
			if err := validateSecretRotationScheduleStartupRegistration(
				expectedRegistration, tick.TenantRegistrationEventID,
				tick.TenantRegistrationEventSequence, ErrSecretRotationScheduleTickConflict,
			); err != nil {
				return err
			}
			_, err = loadAndValidateSecretRotationScheduleStartupTickRowsTx(
				ctx, tx, tick, expectedRegistration)
			if err != nil {
				return err
			}
			outer, outerExists, err := loadSecretRotationScheduleStartupOuterTx(ctx, tx, tenantID, key)
			if err != nil {
				return err
			}
			if !outerExists {
				return fmt.Errorf("%w: current scheduler tick has no outer idempotency authority",
					ErrSecretRotationScheduleTickConflict)
			}
			if err := validateSecretRotationScheduleStartupAggregateTx(
				ctx, tx, cursor, cursorExists, outer, tick); err != nil {
				return err
			}
		}
		afterKey = keys[len(keys)-1]
		if len(keys) < secretRotationScheduleStartupPageSize {
			break
		}
	}

	afterRunID := ""
	for {
		commands, err := listSecretRotationScheduleStartupCommandsTx(
			ctx, tx, tenantID, afterRunID)
		if err != nil {
			return err
		}
		if len(commands) == 0 {
			break
		}
		for _, command := range commands {
			if command.TenantRegistrationEventSequence < registration.EventSeq {
				continue
			}
			if command.TenantRegistrationEventSequence > registration.EventSeq {
				return fmt.Errorf("%w: scheduler command belongs to a future tenant registration",
					ErrSecretRotationScheduleCommandConflict)
			}
			if err := validateSecretRotationScheduleStartupRegistration(
				expectedRegistration, command.TenantRegistrationEventID,
				command.TenantRegistrationEventSequence, ErrSecretRotationScheduleCommandConflict,
			); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleStartupCommand(command); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleStartupCommandRetainedTickTx(
				ctx, tx, command, expectedRegistration,
			); err != nil {
				return err
			}
		}
		afterRunID = commands[len(commands)-1].RunID
		if len(commands) < secretRotationScheduleStartupPageSize {
			break
		}
	}
	return nil
}

func validateSecretRotationScheduleStartupRegistration(
	expected secretRotationScheduleStartupRegistration,
	eventID string,
	eventSequence uint64,
	conflict error,
) error {
	if !validSecretRotationScheduleTenantRegistration(eventID, eventSequence) {
		return fmt.Errorf("%w: scheduler authority has a malformed tenant registration",
			conflict)
	}
	if expected.EventID == "" || expected.EventSequence == 0 {
		return fmt.Errorf("%w: exact live tenant registration authority is unavailable",
			conflict)
	}
	if eventID != expected.EventID || eventSequence != expected.EventSequence {
		return fmt.Errorf("%w: scheduler authority does not name the exact live tenant registration event",
			conflict)
	}
	return nil
}

func listSecretRotationScheduleStartupKeysTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, afterKey string,
) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT scheduler_key
		  FROM (
		        SELECT key AS scheduler_key
		          FROM idempotency_keys
		         WHERE tenant_id = $1 AND left(key, length($3)) = $3
		        UNION
		        SELECT idempotency_key AS scheduler_key
		          FROM secret_rotation_schedule_ticks
		         WHERE tenant_id = $1 AND identity_version = 3
		       ) AS scheduler_keys
		 WHERE scheduler_key > $2
		 ORDER BY scheduler_key
		 LIMIT $4`, tenantID, afterKey, rotationcommand.OuterKeyV3Prefix,
		secretRotationScheduleStartupPageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]string, 0, secretRotationScheduleStartupPageSize)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func loadSecretRotationScheduleStartupTickTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, key string,
) (SecretRotationScheduleTick, bool, error) {
	var tick SecretRotationScheduleTick
	err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
		secretRotationScheduleTickSelect+`
		 AND idempotency_key = $2 AND identity_version = 3`,
		tenantID, key), &tick)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretRotationScheduleTick{}, false, nil
	}
	return tick, err == nil, err
}

func loadAndValidateSecretRotationScheduleStartupTickRowsTx(
	ctx context.Context,
	tx pgx.Tx,
	tick SecretRotationScheduleTick,
	expectedRegistration secretRotationScheduleStartupRegistration,
) ([]secretRotationScheduleStartupTickRow, error) {
	if tick.SnapshotCount < 0 || tick.SnapshotCount > 500 {
		return nil, fmt.Errorf("%w: scheduler tick snapshot budget is outside its bounded range",
			ErrSecretRotationScheduleTickConflict)
	}
	rows, err := tx.Query(ctx, `
		SELECT ordinal, schedule_id::text, identity_version,
		       tenant_registration_event_id, tenant_registration_event_sequence,
		       due_at, provider, secret_key, old_ref,
		       interval_seconds, config_event_sequence
		  FROM secret_rotation_schedule_tick_rows
		 WHERE tenant_id = $1 AND idempotency_key = $2
		 ORDER BY ordinal`, tick.TenantID, tick.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	retained := make([]secretRotationScheduleStartupTickRow, 0, tick.SnapshotCount)
	for rows.Next() {
		var row secretRotationScheduleStartupTickRow
		row.Schedule.TenantID = tick.TenantID
		if err := rows.Scan(
			&row.Ordinal, &row.Schedule.ID, &row.Schedule.IdentityVersion,
			&row.Schedule.TenantRegistrationEventID,
			&row.Schedule.TenantRegistrationEventSequence,
			&row.Schedule.NextRunAt, &row.Schedule.Provider, &row.Schedule.Key,
			&row.Schedule.OldRef, &row.Schedule.IntervalSeconds,
			&row.Schedule.ConfigEventSequence,
		); err != nil {
			return nil, err
		}
		row.Schedule.Enabled = true
		retained = append(retained, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(retained) != tick.SnapshotCount || len(retained) > 500 {
		return nil, fmt.Errorf("%w: scheduler tick snapshot count is incomplete",
			ErrSecretRotationScheduleTickConflict)
	}
	for index, row := range retained {
		if row.Ordinal != index+1 ||
			row.Schedule.IdentityVersion != SecretRotationScheduleIdentityVersion ||
			row.Schedule.ID == "" || row.Schedule.NextRunAt.IsZero() ||
			row.Schedule.Provider == "" || row.Schedule.Key == "" ||
			row.Schedule.OldRef == "" || row.Schedule.IntervalSeconds <= 0 ||
			row.Schedule.NextRunAt.After(tick.DueThrough) {
			return nil, fmt.Errorf("%w: scheduler tick snapshot row %d is malformed",
				ErrSecretRotationScheduleTickConflict, row.Ordinal)
		}
		if err := validateSecretRotationScheduleStartupRegistration(
			expectedRegistration, row.Schedule.TenantRegistrationEventID,
			row.Schedule.TenantRegistrationEventSequence,
			ErrSecretRotationScheduleTickConflict,
		); err != nil {
			return nil, err
		}
		// Revision zero is an intentional pre-0155 migration marker. It is
		// snapshotted so the scheduler can return config_revision_unanchored,
		// but it can never create a child command. Positive revisions must be
		// events after this tenant.registered event.
		if row.Schedule.ConfigEventSequence != 0 &&
			row.Schedule.ConfigEventSequence <= expectedRegistration.EventSequence {
			return nil, fmt.Errorf("%w: scheduler tick snapshot configuration predates its registration",
				ErrSecretRotationScheduleTickConflict)
		}
	}
	return retained, nil
}

func validateSecretRotationScheduleStartupCommandRetainedTickTx(
	ctx context.Context,
	tx pgx.Tx,
	command SecretRotationScheduleCommand,
	expectedRegistration secretRotationScheduleStartupRegistration,
) error {
	var (
		identityVersion                 int
		tenantRegistrationEventID       string
		tenantRegistrationEventSequence uint64
	)
	err := tx.QueryRow(ctx, `
		SELECT identity_version, tenant_registration_event_id,
		       tenant_registration_event_sequence
		  FROM secret_rotation_schedule_ticks
		 WHERE tenant_id = $1 AND idempotency_key = $2`,
		command.TenantID, command.TickIdempotencyKey).Scan(
		&identityVersion, &tenantRegistrationEventID,
		&tenantRegistrationEventSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		// Terminal and claimed commands are independent receivers. The bounded
		// aggregate/idempotency sweeper may already have removed their tick.
		return nil
	}
	if err != nil {
		return err
	}
	if identityVersion != SecretRotationScheduleIdentityVersion {
		return fmt.Errorf("%w: current scheduler command names a legacy retained tick",
			ErrSecretRotationScheduleCommandConflict)
	}
	if err := validateSecretRotationScheduleStartupRegistration(
		expectedRegistration, tenantRegistrationEventID,
		tenantRegistrationEventSequence, ErrSecretRotationScheduleCommandConflict,
	); err != nil {
		return err
	}

	var row secretRotationScheduleStartupTickRow
	row.Schedule.TenantID = command.TenantID
	err = tx.QueryRow(ctx, `
		SELECT ordinal, schedule_id::text, identity_version,
		       tenant_registration_event_id, tenant_registration_event_sequence,
		       due_at, provider, secret_key, old_ref,
		       interval_seconds, config_event_sequence
		  FROM secret_rotation_schedule_tick_rows
		 WHERE tenant_id = $1 AND idempotency_key = $2 AND ordinal = $3`,
		command.TenantID, command.TickIdempotencyKey, command.TickOrdinal).Scan(
		&row.Ordinal, &row.Schedule.ID, &row.Schedule.IdentityVersion,
		&row.Schedule.TenantRegistrationEventID,
		&row.Schedule.TenantRegistrationEventSequence,
		&row.Schedule.NextRunAt, &row.Schedule.Provider, &row.Schedule.Key,
		&row.Schedule.OldRef, &row.Schedule.IntervalSeconds,
		&row.Schedule.ConfigEventSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: scheduler command names a missing retained tick ordinal",
			ErrSecretRotationScheduleCommandConflict)
	}
	if err != nil {
		return err
	}
	row.Schedule.Enabled = true
	schedule := row.Schedule
	if row.Ordinal != command.TickOrdinal ||
		schedule.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		schedule.ID != command.ScheduleID ||
		!schedule.NextRunAt.Equal(command.DueAt) || schedule.Provider != command.Provider ||
		schedule.Key != command.Key || schedule.OldRef != command.OldRef ||
		schedule.IntervalSeconds != command.IntervalSeconds ||
		schedule.ConfigEventSequence != command.ConfigEventSequence ||
		schedule.TenantRegistrationEventID != command.TenantRegistrationEventID ||
		schedule.TenantRegistrationEventSequence != command.TenantRegistrationEventSequence {
		return fmt.Errorf("%w: scheduler command differs from its exact retained tick ordinal",
			ErrSecretRotationScheduleCommandConflict)
	}
	return nil
}

func loadSecretRotationScheduleStartupOuterTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, key string,
) (secretRotationScheduleStartupOuter, bool, error) {
	var outer secretRotationScheduleStartupOuter
	err := tx.QueryRow(ctx, `
		SELECT status, request_binding, result_codec, created_at, completed_at,
		       result IS NOT NULL AND octet_length(result) > 0
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = $2`, tenantID, key).Scan(
		&outer.Status, &outer.RequestBinding, &outer.ResultCodec,
		&outer.CreatedAt, &outer.CompletedAt, &outer.HasResult)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretRotationScheduleStartupOuter{}, false, nil
	}
	return outer, err == nil, err
}

func validateSecretRotationScheduleStartupAggregateTx(
	ctx context.Context,
	tx pgx.Tx,
	cursor SecretRotationScheduleScanCursor,
	cursorExists bool,
	outer secretRotationScheduleStartupOuter,
	tick SecretRotationScheduleTick,
) error {
	if !isSecretRotationScheduleStartupOuterKey(
		tick.IdempotencyKey, tick.Phase == "privacy_erased",
	) {
		return fmt.Errorf("%w: current scheduler tick key is not a derived v3 authority",
			ErrSecretRotationScheduleTickConflict)
	}
	if outer.RequestBinding == "" || outer.RequestBinding != tick.RequestBinding ||
		!outer.CreatedAt.Equal(tick.DueThrough) {
		return fmt.Errorf("%w: scheduler outer key and tick authority disagree",
			ErrSecretRotationScheduleTickConflict)
	}
	switch outer.Status {
	case "bound":
		if outer.CompletedAt != nil || outer.HasResult {
			return fmt.Errorf("%w: bound scheduler outer key contains terminal result authority",
				ErrSecretRotationScheduleTickConflict)
		}
	case "completed":
		if outer.CompletedAt == nil || !outer.HasResult || outer.ResultCodec == "" {
			return fmt.Errorf("%w: completed scheduler outer key lacks protected result authority",
				ErrSecretRotationScheduleTickConflict)
		}
		if tick.Phase != "terminal" &&
			(tick.Phase != "privacy_erased" || tick.TerminalHTTPStatus == nil || len(tick.TerminalBody) == 0) {
			return fmt.Errorf("%w: completed scheduler outer key has a nonterminal tick",
				ErrSecretRotationScheduleTickConflict)
		}
	default:
		return fmt.Errorf("%w: scheduler outer key has unsupported status %q",
			ErrSecretRotationScheduleTickConflict, outer.Status)
	}
	if err := validateSecretRotationSchedulePrivacyStamp(
		tick.PrivacyRewriteVersion, tick.PrivacySubjectRef,
		tick.PrivacyOperationID, tick.PrivacyEventID); err != nil {
		return err
	}
	if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, tick); err != nil {
		return err
	}

	cursorNamesTick := cursorExists && cursor.ActiveTickKey == tick.IdempotencyKey
	switch tick.Phase {
	case "ready", "row_started":
		if !cursorExists || !cursorNamesTick || cursor.ActiveTickBinding != tick.RequestBinding ||
			cursor.LeaseToken == "" || cursor.LeaseUntil == nil ||
			cursor.LeaseToken != tick.OwnerToken ||
			cursor.LeaseGeneration != tick.OwnerGeneration {
			return fmt.Errorf("%w: nonterminal current-v3 tick has no exact cursor authority",
				ErrSecretRotationScheduleTickConflict)
		}
		if outer.Status != "bound" {
			return fmt.Errorf("%w: nonterminal current-v3 tick is not bound",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleTickReceipt(
			tick.Receipt, tick.Ran, tick.Scanned, 0); err != nil {
			return err
		}
	case "terminal":
		if !cursorExists {
			return fmt.Errorf("%w: terminal current-v3 tick has no retained cursor row",
				ErrSecretRotationScheduleTickConflict)
		}
		if cursorNamesTick {
			return fmt.Errorf("%w: scheduler cursor names a terminal tick",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleTickRetainedTerminal(tick); err != nil {
			return err
		}
	case "privacy_erased":
		if !cursorExists {
			return fmt.Errorf("%w: privacy-erased current-v3 tick has no retained cursor row",
				ErrSecretRotationScheduleTickConflict)
		}
		if cursorNamesTick {
			return fmt.Errorf("%w: scheduler cursor names a privacy-erased tick",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleStartupPrivacyTick(tick); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: scheduler tick has unsupported phase %q",
			ErrSecretRotationScheduleTickConflict, tick.Phase)
	}
	return nil
}

func validateSecretRotationScheduleStartupPrivacyTick(tick SecretRotationScheduleTick) error {
	if tick.PrivacyRewriteVersion != SecretRotationSchedulePrivacyRewriteVersion {
		return fmt.Errorf("%w: privacy-erased scheduler tick lacks a complete privacy stamp",
			ErrSecretRotationScheduleTickConflict)
	}
	receipt, err := decodeSecretRotationScheduleTickReceipt(tick.Receipt)
	if err != nil {
		return err
	}
	if receipt.Ran != tick.Ran || receipt.Scanned != tick.Scanned ||
		len(receipt.Runs) != tick.Ran || tick.Scanned < tick.Ran+len(receipt.Deferred) {
		return fmt.Errorf("%w: privacy-erased scheduler receipt disagrees with retained budgets",
			ErrSecretRotationScheduleTickConflict)
	}
	if tick.TerminalHTTPStatus == nil {
		if len(tick.TerminalBody) != 0 {
			return fmt.Errorf("%w: privacy-erased scheduler tick has partial terminal bytes",
				ErrSecretRotationScheduleTickConflict)
		}
		return nil
	}
	if *tick.TerminalHTTPStatus != 200 && *tick.TerminalHTTPStatus != 503 {
		return fmt.Errorf("%w: privacy-erased scheduler tick has unsupported terminal status",
			ErrSecretRotationScheduleTickConflict)
	}
	terminal, err := decodeSecretRotationScheduleTickReceipt(tick.TerminalBody)
	if err != nil {
		return err
	}
	if terminal.Ran != tick.Ran || terminal.Scanned != tick.Scanned ||
		len(terminal.Runs) != tick.Ran || tick.Scanned < tick.Ran+len(terminal.Deferred) ||
		!secretRotationScheduleTickJSONEqual(tick.Receipt, tick.TerminalBody) {
		return fmt.Errorf("%w: privacy-erased scheduler terminal bytes disagree with its receipt",
			ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func listSecretRotationScheduleStartupCommandsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, afterRunID string,
) ([]SecretRotationScheduleCommand, error) {
	// One statement rather than a column-list const concatenated with its
	// predicate. Split that way the SELECT prefix reads — to a reader and to the
	// AN-1 tenant-filter analyzer alike — as a repository query with no tenant
	// filter, because the filter lives somewhere else. It had a single call site,
	// so there was nothing to reuse by hoisting it.
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, identity_version,
       tenant_registration_event_id, tenant_registration_event_sequence,
       schedule_id::text, run_id::text, due_at,
       provider, secret_key, old_ref, interval_seconds, config_event_sequence,
       tick_idempotency_key, tick_ordinal, command_key, request_binding,
       terminal_event_id, prepared_status, prepared_new_ref, prepared_error,
       prepared_event_digest, prepared_at, terminal_event_type,
       terminal_event_sequence, terminal_event_digest, terminal_event_from_event,
       privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
       status, new_ref, error, lease_token, lease_until, created_at, updated_at, terminal_at
  FROM secret_rotation_schedule_commands
		 WHERE tenant_id = $1 AND identity_version = 3 AND run_id::text > $2
		 ORDER BY run_id::text
		 LIMIT $3`, tenantID, afterRunID, secretRotationScheduleStartupPageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	commands := make([]SecretRotationScheduleCommand, 0, secretRotationScheduleStartupPageSize)
	for rows.Next() {
		var command SecretRotationScheduleCommand
		if err := scanSecretRotationScheduleCommand(rows, &command); err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func validateSecretRotationScheduleStartupCommand(command SecretRotationScheduleCommand) error {
	if command.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		!validSecretRotationScheduleTenantRegistration(
			command.TenantRegistrationEventID, command.TenantRegistrationEventSequence) ||
		command.Provider == "" || command.Key == "" || command.OldRef == "" ||
		command.IntervalSeconds <= 0 || command.ConfigEventSequence == 0 ||
		command.TickIdempotencyKey == "" || command.TickOrdinal <= 0 ||
		command.TickOrdinal > 500 || command.RequestBinding == "" ||
		!rotationcommand.Matches(command.TenantID, command.TenantRegistrationEventSequence,
			command.ScheduleID, command.RunID, command.DueAt,
			command.CommandKey, command.TerminalEventID) {
		return fmt.Errorf("%w: retained scheduler command lacks its deterministic due-edge authority",
			ErrSecretRotationScheduleCommandConflict)
	}
	if !isSecretRotationScheduleStartupOuterKey(
		command.TickIdempotencyKey, command.Status == "privacy_erased",
	) {
		return fmt.Errorf("%w: current scheduler command names a non-derived aggregate authority",
			ErrSecretRotationScheduleCommandConflict)
	}
	if err := validateSecretRotationSchedulePrivacyStamp(
		command.PrivacyRewriteVersion, command.PrivacySubjectRef,
		command.PrivacyOperationID, command.PrivacyEventID); err != nil {
		return err
	}
	if (command.LeaseToken == "") != (command.LeaseUntil == nil) {
		return fmt.Errorf("%w: scheduler command lease is partially retained",
			ErrSecretRotationScheduleCommandConflict)
	}

	switch command.Status {
	case "privacy_erased":
		if command.PrivacyRewriteVersion != SecretRotationSchedulePrivacyRewriteVersion ||
			command.TerminalAt == nil || command.LeaseToken != "" || command.LeaseUntil != nil ||
			!IsCanonicalSecretRotationScheduleError(command.Status, command.Error) ||
			!IsCanonicalSecretRotationScheduleError(command.Status, command.PreparedError) ||
			command.PreparedStatus != "" || command.PreparedEventDigest != "" ||
			command.PreparedAt != nil || command.TerminalEventType != "" ||
			command.TerminalEventSequence != nil || command.TerminalEventDigest != "" ||
			command.TerminalEventFromEvent != nil {
			return fmt.Errorf("%w: privacy-erased scheduler command is not a closed tombstone",
				ErrSecretRotationScheduleCommandConflict)
		}
		return nil
	case "claimed":
		if command.TerminalAt != nil || command.TerminalEventType != "" ||
			command.TerminalEventSequence != nil || command.TerminalEventDigest != "" ||
			command.TerminalEventFromEvent != nil || command.NewRef != "" || command.Error != "" {
			return fmt.Errorf("%w: claimed scheduler command contains terminal receipt authority",
				ErrSecretRotationScheduleCommandConflict)
		}
		if command.PreparedStatus == "" {
			if command.PreparedNewRef != "" || command.PreparedError != "" ||
				command.PreparedEventDigest != "" || command.PreparedAt != nil {
				return fmt.Errorf("%w: claimed scheduler command has a partial terminal intent",
					ErrSecretRotationScheduleCommandConflict)
			}
			return nil
		}
		if !secretRotationScheduleTerminalStatus(command.PreparedStatus) ||
			command.PreparedAt == nil || !IsPrivacyReference(command.PreparedEventDigest) ||
			!IsCanonicalSecretRotationScheduleError(command.PreparedStatus, command.PreparedError) {
			return fmt.Errorf("%w: claimed scheduler command has malformed terminal intent",
				ErrSecretRotationScheduleCommandConflict)
		}
		return nil
	default:
		if !secretRotationScheduleTerminalStatus(command.Status) ||
			command.PreparedAt == nil || command.TerminalAt == nil ||
			command.TerminalEventSequence == nil || *command.TerminalEventSequence <= 0 ||
			command.TerminalEventType != "secret.rotation_schedule.ran" ||
			command.TerminalEventFromEvent == nil || !*command.TerminalEventFromEvent ||
			!IsPrivacyReference(command.TerminalEventDigest) ||
			command.LeaseToken != "" || command.LeaseUntil != nil ||
			!IsCanonicalSecretRotationScheduleError(command.Status, command.Error) {
			return fmt.Errorf("%w: terminal scheduler command has malformed event authority",
				ErrSecretRotationScheduleCommandConflict)
		}
		run := SecretRotationScheduleRun{
			TenantID: command.TenantID, IdentityVersion: command.IdentityVersion,
			TenantRegistrationEventID:       command.TenantRegistrationEventID,
			TenantRegistrationEventSequence: command.TenantRegistrationEventSequence,
			ScheduleID:                      command.ScheduleID, RunID: command.RunID,
			SchemaVersion: rotationcommand.EventSchemaVersion, DueAt: command.DueAt,
			Provider: command.Provider, Key: command.Key, OldRef: command.OldRef,
			IntervalSeconds: command.IntervalSeconds, ConfigEventSequence: command.ConfigEventSequence,
			CommandKey: command.CommandKey, RequestBinding: command.RequestBinding,
			Status: command.Status, NewRef: command.NewRef, Error: command.Error,
			RanAt: *command.TerminalAt, EventID: command.TerminalEventID,
			EventType:     command.TerminalEventType,
			EventSequence: uint64(*command.TerminalEventSequence),
			EventDigest:   command.TerminalEventDigest,
		}
		if err := validateBoundSecretRotationScheduleRun(run); err != nil {
			return err
		}
		if err := validateSecretRotationSchedulePreparedIntent(command, run); err != nil {
			return err
		}
		return nil
	}
}

func isSecretRotationScheduleDerivedOuterKey(key string) bool {
	return strings.HasPrefix(key, rotationcommand.OuterKeyV3Prefix) &&
		IsPrivacyReference(strings.TrimPrefix(key, rotationcommand.OuterKeyV3Prefix))
}

func isSecretRotationScheduleStartupOuterKey(key string, privacyErased bool) bool {
	if isSecretRotationScheduleDerivedOuterKey(key) {
		return true
	}
	const privacyPrefix = "privacy-scheduler:"
	return privacyErased && strings.HasPrefix(key, privacyPrefix) &&
		IsPrivacyReference(strings.TrimPrefix(key, privacyPrefix))
}
