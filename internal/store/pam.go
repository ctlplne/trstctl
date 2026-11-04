// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	PAMSessionStatusExpired          = "expired"
	PAMSessionStatusRevoking         = "revoking"
	PAMSessionStatusRevoked          = "revoked"
	PAMSessionStatusRevocationFailed = "revocation_failed"
)

// PAMSession is the event-sourced read-model row for one just-in-time privileged
// access session. It stores metadata and backend revoke handles only; response
// credentials are intentionally absent.
type PAMSession struct {
	TenantID                 string
	ID                       string
	TargetType               string
	TargetID                 string
	Role                     string
	Status                   string
	Subject                  string
	RequestedBy              string
	Reason                   string
	AttestationID            string
	Attestation              json.RawMessage
	BackendRef               string
	SSHKeyID                 string
	SSHSerial                uint64
	IdempotencyKey           string
	Audit                    json.RawMessage
	StartedAt                time.Time
	ExpiresAt                time.Time
	EndedAt                  *time.Time
	RevocationRequestedBy    string
	RevocationReason         string
	RevocationRequestedAt    *time.Time
	RevocationIdempotencyKey string
	RevocationFailure        string
	RevocationFailedAt       *time.Time
	// ApprovalRequestID is the operation approval the activation consumed (G1).
	// Sessions projected before migration 0355 read "".
	ApprovalRequestID string
	// Delivery (A254) is "direct" (the requester received the credential) or
	// "gateway" (only the named gateway ever holds it). GatewayTicketDigest is
	// the SHA-256 of the one-time ticket the requester holds; the ticket itself
	// is never stored.
	Delivery            string
	GatewayAgentID      string
	GatewayTicketDigest string
	// SSHPrincipal (A254) is the login a gateway SSH session's certificate
	// names; the gateway's key is certified when it claims the session.
	SSHPrincipal string
	// GatewayEndedAt and GatewayEnded (A255) are the gateway's own report
	// that the session ended (deadline or recalled).
	GatewayEndedAt *time.Time
	GatewayEnded   string
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
		         ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
		         approval_request_id, delivery, gateway_agent_id, gateway_ticket_digest, ssh_principal)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         $8, $9, $10, $11, $12,
		         $13, $14, $15::jsonb, $16::jsonb, $17, $18, $19,
		         $20, $21, NULLIF($22,'')::uuid, $23, $24)
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
		        attestation = EXCLUDED.attestation,
		        started_at = EXCLUDED.started_at,
		        expires_at = EXCLUDED.expires_at,
		        ended_at = EXCLUDED.ended_at,
		        approval_request_id = EXCLUDED.approval_request_id,
		        delivery = EXCLUDED.delivery,
		        gateway_agent_id = EXCLUDED.gateway_agent_id,
		        gateway_ticket_digest = EXCLUDED.gateway_ticket_digest,
		        ssh_principal = EXCLUDED.ssh_principal`,
		p.TenantID, p.ID, p.TargetType, p.TargetID, p.Role, p.Status, p.Subject,
		p.RequestedBy, p.Reason, p.AttestationID, p.BackendRef, p.SSHKeyID,
		int64(p.SSHSerial), p.IdempotencyKey, jsonbOrEmpty(p.Audit), p.Attestation, p.StartedAt, p.ExpiresAt, p.EndedAt,
		p.ApprovalRequestID, pamDelivery(p.Delivery), p.GatewayAgentID, p.GatewayTicketDigest, p.SSHPrincipal) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// ApplyPAMSessionExpiredTx projects pam.session.expired by closing the read model
// row. Replays are idempotent: an already-ended session keeps the same end time.
func (s *Store) ApplyPAMSessionExpiredTx(ctx context.Context, tx pgx.Tx, tenantID, id string, endedAt time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE pam_sessions
		    SET status = $3,
		        ended_at = coalesce(ended_at, $4)
		  WHERE tenant_id = $1 AND id = $2 AND status = 'active'`,
		tenantID, id, PAMSessionStatusExpired, endedAt)
	return err
}

// These transitions project immutable events. A terminal state cannot be
// overwritten by a delayed worker or a replayed request.
func (s *Store) ApplyPAMSessionRevocationRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, id, actor, reason, key string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_sessions
	    SET status = $3, revocation_requested_by = $4,
	        revocation_reason = $5, revocation_requested_at = $6,
	        revocation_idempotency_key = $7, revocation_failure = '', revocation_failed_at = NULL
	  WHERE tenant_id = $1 AND id = $2 AND status IN ('active', 'revocation_failed')`,
		tenantID, id, PAMSessionStatusRevoking, actor, reason, at, key)
	return err
}

func (s *Store) ApplyPAMSessionRevocationFailedTx(ctx context.Context, tx pgx.Tx, tenantID, id, key, failure string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_sessions
	    SET status = $4, revocation_failure = $5, revocation_failed_at = $6
	  WHERE tenant_id = $1 AND id = $2 AND revocation_idempotency_key = $3 AND status = 'revoking'`,
		tenantID, id, key, PAMSessionStatusRevocationFailed, failure, at)
	return err
}

func (s *Store) ApplyPAMSessionRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, endedAt time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_sessions
	    SET status = $3, ended_at = coalesce(ended_at, $4)
	  WHERE tenant_id = $1 AND id = $2 AND status = 'revoking'`,
		tenantID, id, PAMSessionStatusRevoked, endedAt)
	return err
}

// GetPAMSession returns one tenant-scoped PAM session metadata row.
func (s *Store) GetPAMSession(ctx context.Context, tenantID, id string) (PAMSession, error) {
	var out PAMSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
			        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
			        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
			        revocation_requested_by, revocation_reason, revocation_requested_at,
		        revocation_idempotency_key, revocation_failure, revocation_failed_at,
		        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
		        gateway_ended_at, gateway_ended
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
			        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
			        revocation_requested_by, revocation_reason, revocation_requested_at,
		        revocation_idempotency_key, revocation_failure, revocation_failed_at,
		        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
		        gateway_ended_at, gateway_ended
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
		        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
		        revocation_requested_by, revocation_reason, revocation_requested_at,
		        revocation_idempotency_key, revocation_failure, revocation_failed_at,
		        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
		        gateway_ended_at, gateway_ended
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

// The system worker scans only revoking sessions. It never treats a queued
// external call as target completion.
func (s *Store) ListRevokingPAMSessions(ctx context.Context, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant PAM revocation worker scans only revoking metadata; follow-up calls and events use each row's tenant_id.
		`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
		        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
		        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
		        revocation_requested_by, revocation_reason, revocation_requested_at,
		        revocation_idempotency_key, revocation_failure, revocation_failed_at,
		        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
		        gateway_ended_at, gateway_ended
		   FROM pam_sessions WHERE status = 'revoking'
		  ORDER BY revocation_requested_at, tenant_id, id LIMIT $1`, limit)
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
		&serial, &out.IdempotencyKey, &out.Audit, &out.Attestation, &out.StartedAt, &out.ExpiresAt, &out.EndedAt,
		&out.RevocationRequestedBy, &out.RevocationReason, &out.RevocationRequestedAt,
		&out.RevocationIdempotencyKey, &out.RevocationFailure, &out.RevocationFailedAt,
		&out.Delivery, &out.GatewayAgentID, &out.GatewayTicketDigest, &out.SSHPrincipal, &out.GatewayEndedAt, &out.GatewayEnded,
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

// pamDelivery names a session's delivery; sessions projected before A254 were
// all direct.
func pamDelivery(d string) string {
	if d == "" {
		return "direct"
	}
	return d
}

// RecallPAMGatewayJob withdraws a gateway session's job (A254): its gateway's
// next lease extension is refused, so it closes the session's connections and
// wipes the credential. Recalling an already finished job changes nothing.
func (s *Store) RecallPAMGatewayJob(ctx context.Context, tenantID, sessionID, destination, idempotencyKey string, at time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox
		    SET status = $5, agent_recalled_at = COALESCE(agent_recalled_at, $4), last_error = 'session revoked',
		        worker_id = NULL, lease_until = NULL
		  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3
		    AND status IN ('pending', 'processing') AND delivered_at IS NULL AND claim_completed_at IS NULL`,
			tenantID, destination, idempotencyKey, at.UTC(), OutboxStatusCancelled)
		return err
	})
}

// ListActiveGatewayPAMSessions lists active gateway-delivered sessions across
// tenants, for the expiry worker's job check.
func (s *Store) ListActiveGatewayPAMSessions(ctx context.Context, now time.Time, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var out []PAMSession
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — the PAM expiry worker checks every tenant's active gateway sessions for a queued job, as it lists due sessions across tenants (ListDuePAMSessions); each job is then queued under its own tenant's RLS context.
		`SELECT tenant_id::text, id::text, target_type, target_id, expires_at,
		        COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal
		   FROM pam_sessions
		  WHERE delivery = 'gateway' AND status = 'active' AND expires_at > $1
		  ORDER BY expires_at, id
		  LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p PAMSession
		if err := rows.Scan(&p.TenantID, &p.ID, &p.TargetType, &p.TargetID, &p.ExpiresAt, &p.GatewayAgentID, &p.GatewayTicketDigest, &p.SSHPrincipal); err != nil {
			return nil, err
		}
		p.Delivery = "gateway"
		out = append(out, p)
	}
	return out, rows.Err()
}

// ApplyPAMSessionGatewayEndedTx projects pam.session.gateway_ended: the
// first report of the session's end is kept.
func (s *Store) ApplyPAMSessionGatewayEndedTx(ctx context.Context, tx pgx.Tx, tenantID, id, ended string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_sessions SET gateway_ended_at = $3, gateway_ended = $4
	  WHERE tenant_id = $1 AND id = $2 AND gateway_ended_at IS NULL`, tenantID, id, at, ended)
	return err
}
