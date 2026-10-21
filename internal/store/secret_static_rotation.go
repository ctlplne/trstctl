// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Static-provider rotation commands (A14/A15).
//
// A static rotation mints a long-lived credential at a configured provider,
// publishes it as the next version of an application secret, proves it works,
// and only then retires the predecessor. Each phase is an immutable event whose
// projection is one row here; the secret-integrations outbox drives the worker
// that performs provider calls, so a crash between two phases resumes from the
// persisted phase instead of repeating an external effect blindly (AN-5/AN-6).

const (
	SecretStaticRotationQueued         = "queued"
	SecretStaticRotationStaged         = "staged"
	SecretStaticRotationCutover        = "cutover"
	SecretStaticRotationVerified       = "verified"
	SecretStaticRotationCompleted      = "completed"
	SecretStaticRotationRolledBack     = "rolled_back"
	SecretStaticRotationRollbackFailed = "rollback_failed"
	SecretStaticRotationFailed         = "failed"
	SecretStaticRotationRetirePending  = "retire_pending"

	// SecretStaticRotationDestination is the outbox destination the worker
	// consumes; one row per command, keyed by the command's identity.
	SecretStaticRotationDestination = "secret.static-rotation"
)

var ErrSecretStaticRotationCommandNotFound = errors.New("store: static rotation command not found")

// SecretStaticRotationCommand is the projected state of one durable command.
type SecretStaticRotationCommand struct {
	TenantID             string
	ID                   string
	TenantEpoch          string
	Provider             string
	ProviderType         string
	Key                  string
	OldRef               string
	NewRef               string
	Phase                string
	ExpectedVersion      int
	ResultVersion        int
	RestoredVersion      int
	SealedNew            []byte
	SealedOld            []byte
	VerifyMode           string
	Error                string
	IdempotencyKeyDigest string
	RequestBinding       string
	ScheduleID           string
	OutboxID             int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
	TerminalAt           *time.Time
}

// Terminal reports whether the worker has nothing left to do for the command.
func (c SecretStaticRotationCommand) Terminal() bool {
	return SecretStaticRotationPhaseTerminal(c.Phase)
}

// SecretStaticRotationPhaseTerminal reports whether a phase ends the command.
func SecretStaticRotationPhaseTerminal(phase string) bool {
	switch phase {
	case SecretStaticRotationCompleted, SecretStaticRotationRolledBack, SecretStaticRotationRollbackFailed,
		SecretStaticRotationFailed, SecretStaticRotationRetirePending:
		return true
	}
	return false
}

// SecretStaticRotationAdvance is one projected phase transition. Sealed values
// are set only by the phase that produced them; nil leaves the column alone.
type SecretStaticRotationAdvance struct {
	TenantID        string
	ID              string
	TenantEpoch     string
	FromPhase       string
	Phase           string
	ProviderType    string
	NewRef          string
	SealedNew       []byte
	SealedOld       []byte
	ResultVersion   int
	RestoredVersion int
	VerifyMode      string
	Error           string
	At              time.Time
}

// SecretStaticRotationOutboxIdempotencyKey is the one outbox identity a command
// ever has.
func SecretStaticRotationOutboxIdempotencyKey(tenantEpoch, id string) string {
	return SecretStaticRotationDestination + ":" + tenantEpoch + ":" + id
}

// ApplySecretStaticRotationQueuedTx projects the queued event: the command row
// and its single outbox intent commit together. Replaying the event finds the
// same row and the same outbox identity and changes nothing.
func (s *Store) ApplySecretStaticRotationQueuedTx(ctx context.Context, tx pgx.Tx, cmd SecretStaticRotationCommand, outboxPayload []byte) error {
	if cmd.TenantID == "" || cmd.ID == "" || cmd.TenantEpoch == "" || cmd.Provider == "" || cmd.Key == "" ||
		cmd.OldRef == "" || len(cmd.IdempotencyKeyDigest) != 64 || len(cmd.RequestBinding) != 64 || cmd.CreatedAt.IsZero() {
		return errors.New("store: static rotation command is incomplete")
	}
	if err := s.ValidateApplicationSecretTenantEpochTx(ctx, tx, cmd.TenantID, cmd.TenantEpoch); err != nil {
		return err
	}
	var scheduleID any
	if cmd.ScheduleID != "" {
		scheduleID = cmd.ScheduleID
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_static_rotation_commands
		        (tenant_id, id, tenant_epoch, provider, secret_key, old_ref, phase, expected_version,
		         idempotency_key_digest, request_binding, schedule_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		cmd.TenantID, cmd.ID, cmd.TenantEpoch, cmd.Provider, cmd.Key, cmd.OldRef, SecretStaticRotationQueued,
		cmd.ExpectedVersion, cmd.IdempotencyKeyDigest, cmd.RequestBinding, scheduleID, cmd.CreatedAt.UTC()); err != nil {
		return err
	}
	outboxID, err := ensureSecretIntegrationOutboxTx(ctx, tx, cmd.TenantID, SecretStaticRotationDestination,
		"dynsecret.provider:"+cmd.Provider, SecretStaticRotationOutboxIdempotencyKey(cmd.TenantEpoch, cmd.ID), outboxPayload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE secret_static_rotation_commands SET outbox_id = $3
		  WHERE tenant_id = $1 AND id = $2 AND outbox_id IS NULL`, cmd.TenantID, cmd.ID, outboxID)
	return err
}

// ApplySecretStaticRotationAdvancedTx projects one phase transition. The update
// is fenced on the exact predecessor phase; a replay whose transition already
// applied is a no-op, and any other mismatch is a conflict rather than a silent
// overwrite.
func (s *Store) ApplySecretStaticRotationAdvancedTx(ctx context.Context, tx pgx.Tx, adv SecretStaticRotationAdvance) error {
	if adv.TenantID == "" || adv.ID == "" || adv.FromPhase == "" || adv.Phase == "" || adv.At.IsZero() {
		return errors.New("store: static rotation advance is incomplete")
	}
	var terminalAt any
	if SecretStaticRotationPhaseTerminal(adv.Phase) {
		terminalAt = adv.At.UTC()
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_static_rotation_commands
		    SET phase = $4,
		        provider_type = CASE WHEN $5 <> '' THEN $5 ELSE provider_type END,
		        new_ref = CASE WHEN $6 <> '' THEN $6 ELSE new_ref END,
		        sealed_new = COALESCE($7, sealed_new),
		        sealed_old = COALESCE($8, sealed_old),
		        result_version = CASE WHEN $9 > 0 THEN $9 ELSE result_version END,
		        restored_version = CASE WHEN $10 > 0 THEN $10 ELSE restored_version END,
		        verify_mode = CASE WHEN $11 <> '' THEN $11 ELSE verify_mode END,
		        error = $12,
		        updated_at = $13,
		        terminal_at = $14
		  WHERE tenant_id = $1 AND id = $2 AND phase = $3`,
		adv.TenantID, adv.ID, adv.FromPhase, adv.Phase, adv.ProviderType, adv.NewRef,
		adv.SealedNew, adv.SealedOld, adv.ResultVersion, adv.RestoredVersion, adv.VerifyMode,
		adv.Error, adv.At.UTC(), terminalAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var current string
	if err := tx.QueryRow(ctx,
		`SELECT phase FROM secret_static_rotation_commands WHERE tenant_id = $1 AND id = $2`,
		adv.TenantID, adv.ID).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretStaticRotationCommandNotFound
		}
		return err
	}
	if current == adv.Phase || secretStaticRotationPhaseRank(current) > secretStaticRotationPhaseRank(adv.Phase) {
		return nil // exact replay, or a later transition already projected
	}
	return fmt.Errorf("%w: static rotation command %s is in phase %q, transition expected %q",
		ErrIdempotencyConflict, adv.ID, current, adv.FromPhase)
}

func secretStaticRotationPhaseRank(phase string) int {
	switch phase {
	case SecretStaticRotationQueued:
		return 0
	case SecretStaticRotationStaged:
		return 1
	case SecretStaticRotationCutover:
		return 2
	case SecretStaticRotationVerified:
		return 3
	default:
		return 4 // every terminal phase
	}
}

const secretStaticRotationColumns = /* #nosec G101 -- SQL column list, no credential (CWE-798) */ `tenant_id::text, id::text, tenant_epoch, provider, provider_type, secret_key, old_ref, new_ref,
       phase, expected_version, result_version, restored_version, sealed_new, sealed_old, verify_mode, error,
       idempotency_key_digest, request_binding, coalesce(schedule_id::text, ''), coalesce(outbox_id, 0),
       created_at, updated_at, terminal_at`

func scanSecretStaticRotationCommand(row pgx.Row) (SecretStaticRotationCommand, error) {
	var c SecretStaticRotationCommand
	err := row.Scan(&c.TenantID, &c.ID, &c.TenantEpoch, &c.Provider, &c.ProviderType, &c.Key, &c.OldRef, &c.NewRef,
		&c.Phase, &c.ExpectedVersion, &c.ResultVersion, &c.RestoredVersion, &c.SealedNew, &c.SealedOld, &c.VerifyMode, &c.Error,
		&c.IdempotencyKeyDigest, &c.RequestBinding, &c.ScheduleID, &c.OutboxID,
		&c.CreatedAt, &c.UpdatedAt, &c.TerminalAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretStaticRotationCommand{}, ErrSecretStaticRotationCommandNotFound
	}
	return c, err
}

// GetSecretStaticRotationCommand loads one command with its sealed material.
func (s *Store) GetSecretStaticRotationCommand(ctx context.Context, tenantID, id string) (SecretStaticRotationCommand, error) {
	var out SecretStaticRotationCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanSecretStaticRotationCommand(tx.QueryRow(ctx,
			`SELECT `+secretStaticRotationColumns+` FROM secret_static_rotation_commands WHERE tenant_id = $1 AND id = $2`,
			tenantID, id))
		return err
	})
	return out, err
}

// LatestSecretStaticRotationCommandForKey returns the newest command for a
// secret, so a schedule can chain its predecessor and refuse to overlap an
// in-flight command.
func (s *Store) LatestSecretStaticRotationCommandForKey(ctx context.Context, tenantID, key string) (SecretStaticRotationCommand, bool, error) {
	var out SecretStaticRotationCommand
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanSecretStaticRotationCommand(tx.QueryRow(ctx,
			`SELECT `+secretStaticRotationColumns+` FROM secret_static_rotation_commands
			  WHERE tenant_id = $1 AND secret_key = $2 ORDER BY created_at DESC, id DESC LIMIT 1`,
			tenantID, key))
		if errors.Is(err, ErrSecretStaticRotationCommandNotFound) {
			return nil
		}
		found = err == nil
		return err
	})
	return out, found, err
}

// ListSecretStaticRotationCommandsPage lists commands newest first, optionally
// for one secret, with keyset paging on (created_at, id).
func (s *Store) ListSecretStaticRotationCommandsPage(ctx context.Context, tenantID, key, afterID string, limit int) ([]SecretStaticRotationCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []SecretStaticRotationCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+secretStaticRotationColumns+` FROM secret_static_rotation_commands c
			  WHERE c.tenant_id = $1
			    AND ($2 = '' OR c.secret_key = $2)
			    AND ($3 = '' OR (c.created_at, c.id) < (
			          SELECT p.created_at, p.id FROM secret_static_rotation_commands p
			           WHERE p.tenant_id = $1 AND p.id = $3::uuid))
			  ORDER BY c.created_at DESC, c.id DESC
			  LIMIT $4`, tenantID, key, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanSecretStaticRotationCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
