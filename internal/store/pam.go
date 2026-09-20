// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const PAMSessionStatusExpired = "expired"

// PAMSession is the event-sourced read-model row for one just-in-time privileged
// access session. It stores metadata and backend revoke handles only; response
// credentials are intentionally absent.
type PAMSession struct {
	TenantID       string
	ID             string
	TargetType     string
	TargetID       string
	Role           string
	Status         string
	Subject        string
	RequestedBy    string
	Reason         string
	AttestationID  string
	BackendRef     string
	SSHKeyID       string
	SSHSerial      uint64
	IdempotencyKey string
	Audit          json.RawMessage
	StartedAt      time.Time
	ExpiresAt      time.Time
	EndedAt        *time.Time
}

// ApplyPAMSessionStartedTx projects a pam.session.started event. Replays are
// idempotent on (tenant_id,id).
func (s *Store) ApplyPAMSessionStartedTx(ctx context.Context, tx pgx.Tx, p PAMSession) error {
	if p.Audit == nil {
		p.Audit = json.RawMessage(`{}`)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO pam_sessions
		        (tenant_id, id, target_type, target_id, role, status, subject,
		         requested_by, reason, attestation_id, backend_ref, ssh_key_id,
		         ssh_serial, idempotency_key, audit, started_at, expires_at, ended_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         $8, $9, $10, $11, $12,
		         $13, $14, $15::jsonb, $16, $17, $18)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET target_type = EXCLUDED.target_type,
		        target_id = EXCLUDED.target_id,
		        role = EXCLUDED.role,
		        status = EXCLUDED.status,
		        subject = EXCLUDED.subject,
		        requested_by = EXCLUDED.requested_by,
		        reason = EXCLUDED.reason,
		        attestation_id = EXCLUDED.attestation_id,
		        backend_ref = EXCLUDED.backend_ref,
		        ssh_key_id = EXCLUDED.ssh_key_id,
		        ssh_serial = EXCLUDED.ssh_serial,
		        idempotency_key = EXCLUDED.idempotency_key,
		        audit = EXCLUDED.audit,
		        started_at = EXCLUDED.started_at,
		        expires_at = EXCLUDED.expires_at,
		        ended_at = EXCLUDED.ended_at`,
		p.TenantID, p.ID, p.TargetType, p.TargetID, p.Role, p.Status, p.Subject,
		p.RequestedBy, p.Reason, p.AttestationID, p.BackendRef, p.SSHKeyID,
		int64(p.SSHSerial), p.IdempotencyKey, jsonbOrEmpty(p.Audit), p.StartedAt, p.ExpiresAt, p.EndedAt) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// ApplyPAMSessionExpiredTx projects pam.session.expired by closing the read model
// row. Replays are idempotent: an already-ended session keeps the same end time.
func (s *Store) ApplyPAMSessionExpiredTx(ctx context.Context, tx pgx.Tx, tenantID, id string, endedAt time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE pam_sessions
		    SET status = $3,
		        ended_at = coalesce(ended_at, $4)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, PAMSessionStatusExpired, endedAt)
	return err
}

// GetPAMSession returns one tenant-scoped PAM session metadata row.
func (s *Store) GetPAMSession(ctx context.Context, tenantID, id string) (PAMSession, error) {
	var out PAMSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
			        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
			        ssh_serial, idempotency_key, audit, started_at, expires_at, ended_at
			   FROM pam_sessions
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id)
		return scanPAMSession(row, &out)
	})
	return out, err
}

// ListPAMSessions lists tenant-scoped PAM sessions newest-first.
func (s *Store) ListPAMSessions(ctx context.Context, tenantID string, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []PAMSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
			        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
			        ssh_serial, idempotency_key, audit, started_at, expires_at, ended_at
			   FROM pam_sessions
			  WHERE tenant_id = $1
			  ORDER BY started_at DESC, id DESC
			  LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PAMSession
			if err := scanPAMSession(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// ListDuePAMSessions returns active sessions whose backend grant should be expired.
func (s *Store) ListDuePAMSessions(ctx context.Context, now time.Time, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant system expiry worker scans every tenant for active PAM sessions due to be closed; it returns no credential material, and each follow-up mutation appends a tenant_id-scoped pam.session.expired event.
		`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
		        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
		        ssh_serial, idempotency_key, audit, started_at, expires_at, ended_at
		   FROM pam_sessions
		  WHERE status = $1 AND expires_at <= $2
		  ORDER BY expires_at ASC, tenant_id, id
		  LIMIT $3`,
		"active", now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMSession
	for rows.Next() {
		var p PAMSession
		if err := scanPAMSession(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type pamScanner interface {
	Scan(...any) error
}

func scanPAMSession(row pamScanner, out *PAMSession) error {
	var serial int64
	if err := row.Scan(
		&out.TenantID, &out.ID, &out.TargetType, &out.TargetID, &out.Role, &out.Status,
		&out.Subject, &out.RequestedBy, &out.Reason, &out.AttestationID, &out.BackendRef, &out.SSHKeyID,
		&serial, &out.IdempotencyKey, &out.Audit, &out.StartedAt, &out.ExpiresAt, &out.EndedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return pgx.ErrNoRows
		}
		return err
	}
	if serial < 0 {
		return fmt.Errorf("store: pam session %s has negative ssh serial", out.ID)
	}
	out.SSHSerial = uint64(serial)
	return nil
}
