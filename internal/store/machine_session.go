// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// Machine-session read-model statuses. "expired" is a display state computed
// from expires_at by readers; the projection stores only active/revoked so the
// ledger needs no expiry worker (C-S3, DA-02).
const (
	MachineSessionStatusActive  = "active"
	MachineSessionStatusRevoked = "revoked"
)

// MachineSession is the event-sourced read-model row for one machine-login
// session (projection of secrets.session.started, secrets.session.revoked, and
// api_token.revoked for sessions with a linked bearer). Metadata only:
// no credential material is ever projected (AN-8).
type MachineSession struct {
	TenantID  string
	ID        string
	Principal string
	Method    string
	Scopes    []string
	Status    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	RevokedBy string
}

// ApplyMachineSessionStartedTx projects secrets.session.started. The first
// event owns the row: a duplicate replay cannot reopen a revoked session or
// replace its principal, method, scopes, or expiry.
func (s *Store) ApplyMachineSessionStartedTx(ctx context.Context, tx pgx.Tx, m MachineSession, eventSequence uint64) error {
	if eventSequence > 1<<63-1 {
		return errors.New("store: machine-session source sequence exceeds PostgreSQL bigint")
	}
	// A retained pre-offboard start can arrive after the offboard projection or
	// even after an explicit rehire. Serialize with the claim, then derive its
	// terminal state from the durable source sequence rather than current member
	// status. A pending claim denies every earlier session start.
	if err := s.LockTenantMemberSubjectTx(ctx, tx, m.TenantID, m.Principal); err != nil {
		return err
	}
	var offboardAt time.Time
	err := tx.QueryRow(ctx, `SELECT event_time FROM tenant_member_offboard_commands
		WHERE tenant_id = $1 AND subject_ref = $2
		  AND (status = 'pending' OR last_event_sequence >= $3::bigint)`,
		m.TenantID, privacy.SubjectRef(m.TenantID, m.Principal),
		strconv.FormatUint(eventSequence, 10)).Scan(&offboardAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		m.Status = MachineSessionStatusRevoked
		m.RevokedAt = &offboardAt
		m.RevokedBy = "member offboard"
	}
	if m.Scopes == nil {
		m.Scopes = []string{}
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO machine_sessions
		        (tenant_id, id, principal, method, scopes, status, issued_at, expires_at, revoked_at, revoked_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		m.TenantID, m.ID, m.Principal, m.Method, m.Scopes, m.Status, m.IssuedAt, m.ExpiresAt, m.RevokedAt, m.RevokedBy)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	// An exact duplicate is harmless, including after a later revocation.
	// A second start with the same ID but changed identity or lifetime is not
	// a replay and must not be silently accepted as the first writer.
	var same bool
	if err := tx.QueryRow(ctx,
		`SELECT principal = $3 AND method = $4 AND scopes = $5 AND
		        issued_at = $6 AND expires_at = $7
		   FROM machine_sessions WHERE tenant_id = $1 AND id = $2`,
		m.TenantID, m.ID, m.Principal, m.Method, m.Scopes, m.IssuedAt, m.ExpiresAt).Scan(&same); err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("store: machine session %s conflicts with its first start event", m.ID)
	}
	return nil
}

// ApplyMachineSessionRevokedTx projects secrets.session.revoked. Replays are
// idempotent: an already-revoked session keeps its original revocation facts.
func (s *Store) ApplyMachineSessionRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, revokedBy string, revokedAt time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE machine_sessions
		    SET status = $3,
		        revoked_at = coalesce(revoked_at, $4),
		        revoked_by = CASE WHEN revoked_by = '' THEN $5 ELSE revoked_by END
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, MachineSessionStatusRevoked, revokedAt, revokedBy)
	return err
}

// ApplyMachineSessionsRevokedForSubjectTx keeps the machine-session ledger in
// sync when member offboarding revokes every API bearer owned by that principal.
func (s *Store) ApplyMachineSessionsRevokedForSubjectTx(ctx context.Context, tx pgx.Tx, tenantID, subject, revokedBy string, revokedAt time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE machine_sessions
		    SET status = $3,
		        revoked_at = coalesce(revoked_at, $4),
		        revoked_by = CASE WHEN revoked_by = '' THEN $5 ELSE revoked_by END
		  WHERE tenant_id = $1 AND principal = $2 AND status = $6`,
		tenantID, subject, MachineSessionStatusRevoked, revokedAt, revokedBy, MachineSessionStatusActive)
	return err
}

// GetMachineSession returns one tenant-scoped machine-session ledger row.
func (s *Store) GetMachineSession(ctx context.Context, tenantID, id string) (MachineSession, error) {
	var out MachineSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, id, principal, method, scopes, status, issued_at, expires_at, revoked_at, revoked_by
			   FROM machine_sessions
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id)
		return scanMachineSession(row, &out)
	})
	return out, err
}

// ListMachineSessions lists tenant-scoped machine sessions newest-first.
func (s *Store) ListMachineSessions(ctx context.Context, tenantID string, limit int) ([]MachineSession, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var out []MachineSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id, principal, method, scopes, status, issued_at, expires_at, revoked_at, revoked_by
			   FROM machine_sessions
			  WHERE tenant_id = $1
			  ORDER BY issued_at DESC, id DESC
			  LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m MachineSession
			if err := scanMachineSession(rows, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

func scanMachineSession(row pgx.Row, out *MachineSession) error {
	return row.Scan(&out.TenantID, &out.ID, &out.Principal, &out.Method, &out.Scopes,
		&out.Status, &out.IssuedAt, &out.ExpiresAt, &out.RevokedAt, &out.RevokedBy)
}

// ApplyMachineAuthMethodOverrideTx projects secrets.auth_method.disabled/
// .enabled: the tenant-level overlay the login path consults. Replays are
// idempotent on (tenant_id, method_name); later source event sequence wins,
// even if an older historical event had a future wall-clock timestamp.
func (s *Store) ApplyMachineAuthMethodOverrideTx(ctx context.Context, tx pgx.Tx, tenantID, methodName string, disabled bool, updatedBy string, updatedAt time.Time, eventSequence uint64) error {
	if eventSequence == 0 || eventSequence > uint64(1<<63-1) {
		return errors.New("store: machine-auth method event requires a valid source sequence")
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO machine_auth_method_overrides
		        (tenant_id, method_name, disabled, updated_at, updated_by, last_event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6::bigint)
		 ON CONFLICT (tenant_id, method_name) DO UPDATE
		    SET disabled = EXCLUDED.disabled,
		        updated_at = EXCLUDED.updated_at,
		        updated_by = EXCLUDED.updated_by,
		        last_event_sequence = EXCLUDED.last_event_sequence
		  WHERE machine_auth_method_overrides.last_event_sequence < EXCLUDED.last_event_sequence`,
		tenantID, methodName, disabled, updatedAt, updatedBy, strconv.FormatUint(eventSequence, 10))
	return err
}

// DisabledMachineAuthMethods returns the tenant's disabled method names. The
// login path fails closed on read errors. The independent command row overlays
// the event read model: pending commands deny login; a completed latest command
// is authoritative during read-model replay and cold recovery.
func (s *Store) DisabledMachineAuthMethods(ctx context.Context, tenantID string) (map[string]bool, error) {
	out := map[string]bool{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT method_name
			   FROM machine_auth_method_overrides
			  WHERE tenant_id = $1 AND disabled`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			out[name] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		commands, err := tx.Query(ctx,
			`SELECT method_name, target_disabled, status
			   FROM machine_auth_method_commands
			  WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer commands.Close()
		for commands.Next() {
			var name, status string
			var targetDisabled bool
			if err := commands.Scan(&name, &targetDisabled, &status); err != nil {
				return err
			}
			if status != "pending" && status != "completed" {
				return errors.New("store: invalid machine-auth method command state")
			}
			if status == "pending" || targetDisabled {
				out[name] = true
			} else {
				delete(out, name)
			}
		}
		return commands.Err()
	})
	return out, err
}
