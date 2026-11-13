// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The operations ledger (A245) reads every rotation, delivery, secret
// rotation and approval from the projections that already record them, with
// the evidence a normalized state needs: the outbox command behind it, whether
// that command is stranded or quarantined, and whether an endpoint was seen
// presenting the certificate it carried. A245-L1 adds host and relay agent
// jobs (their outbox command and the agent's signed receipt), access and
// machine session revocations, managed-key operations and SSH certificate
// revocations. It writes nothing.

// OperationLedgerRow is one operation as its own source records it.
type OperationLedgerRow struct {
	// Source is certificate_rotation, connector_delivery, secret_rotation,
	// approval, agent_job, access_session_revocation,
	// machine_session_revocation, managed_key_operation or
	// ssh_certificate_revocation.
	Source      string
	ID          string
	SubjectKind string
	SubjectID   string
	SubjectName string
	// Status is the source's own status or phase.
	Status string
	Detail string
	// Origin says what asked for it (a trigger and reason, a schedule, a
	// requester); Target names a delivery's destination; RollbackRef the
	// predecessor a rollback would restore.
	Origin      string
	Target      string
	RollbackRef string
	Fingerprint string
	// ReadBack reports a connector readback (a verified receipt) of
	// Fingerprint for the same identity.
	ReadBack           bool
	OutboxID           *int64
	OutboxStatus       string
	OutboxAttempts     int
	OutboxLeaseExpired bool
	Quarantined        bool
	// ObservedVantage names the newest clean endpoint verification that saw
	// Fingerprint served; empty when none did.
	ObservedVantage string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Key is the row's stable ledger id.
func (r OperationLedgerRow) Key() string { return r.Source + ":" + r.ID }

// OperationLedgerCursor resumes a newest-first page after the row it names.
type OperationLedgerCursor struct {
	UpdatedAt time.Time
	Key       string
}

// ListOperationLedgerRows returns up to limit operations, newest first, after
// the cursor. Each source contributes at most limit rows, so the read stays
// bounded however large one source grows.
func (s *Store) ListOperationLedgerRows(ctx context.Context, tenantID string, after *OperationLedgerCursor, limit int) ([]OperationLedgerRow, error) {
	return s.operationLedgerRows(ctx, tenantID, after, limit, "", "")
}

// GetOperationLedgerRow reads one operation by its source and id.
func (s *Store) GetOperationLedgerRow(ctx context.Context, tenantID, source, id string) (OperationLedgerRow, error) {
	rows, err := s.operationLedgerRows(ctx, tenantID, nil, 1, source, id)
	if err != nil {
		return OperationLedgerRow{}, err
	}
	if len(rows) == 0 {
		return OperationLedgerRow{}, pgx.ErrNoRows
	}
	return rows[0], nil
}

// A source whose id is a uuid casts the requested id only when it has the
// shape of one: an agent job's, a machine session's or a managed-key
// operation's id is not, and a cast the planner folds would fail the query.
func (s *Store) operationLedgerRows(ctx context.Context, tenantID string, after *OperationLedgerCursor, limit int, source, id string) ([]OperationLedgerRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var afterAt *time.Time
	afterKey := ""
	if after != nil {
		at := after.UpdatedAt
		afterAt, afterKey = &at, after.Key
	}
	var out []OperationLedgerRow
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH page AS (
			  (SELECT 'certificate_rotation' AS source, r.id::text AS id, coalesce(i.kind, '') AS subject_kind,
			          r.identity_id::text AS subject_id, coalesce(i.name, '') AS subject_name, r.status,
			          coalesce(r.error, '') AS detail, trim(both ': ' from r.trigger || ': ' || r.reason) AS origin, '' AS target,
			          r.rollback_ref, coalesce(r.successor_fingerprint, '') AS fingerprint,
			          r.identity_id AS identity_uuid, r.outbox_id, r.created_at, r.updated_at
			     FROM lifecycle_rotation_runs r
			     LEFT JOIN identities i ON i.tenant_id = r.tenant_id AND i.id = r.identity_id
			    WHERE r.tenant_id = $1 AND $5 IN ('', 'certificate_rotation') AND (nullif($6, '') IS NULL OR r.id = CASE WHEN $6 ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN $6::uuid END)
			      AND ($2::timestamptz IS NULL OR (r.updated_at, 'certificate_rotation:' || r.id::text) < ($2, $3))
			    ORDER BY r.updated_at DESC, r.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'connector_delivery', d.id::text, coalesce(i.kind, ''), coalesce(d.identity_id::text, ''),
			          coalesce(i.name, d.target), d.status, d.detail, d.reason, d.target, d.rollback_ref, d.fingerprint,
			          d.identity_id, d.outbox_id, d.created_at, d.updated_at
			     FROM connector_delivery_receipts d
			     LEFT JOIN identities i ON i.tenant_id = d.tenant_id AND i.id = d.identity_id
			    WHERE d.tenant_id = $1 AND $5 IN ('', 'connector_delivery') AND (nullif($6, '') IS NULL OR d.id = CASE WHEN $6 ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN $6::uuid END)
			      AND ($2::timestamptz IS NULL OR (d.updated_at, 'connector_delivery:' || d.id::text) < ($2, $3))
			    ORDER BY d.updated_at DESC, d.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'secret_rotation', c.id::text, 'secret', '', c.secret_key, c.phase, coalesce(c.error, ''),
			          CASE WHEN c.schedule_id IS NULL THEN 'manual rotation' ELSE 'scheduled rotation' END, c.provider, '', '',
			          NULL::uuid, nullif(c.outbox_id, 0), c.created_at, c.updated_at
			     FROM secret_static_rotation_commands c
			    WHERE c.tenant_id = $1 AND $5 IN ('', 'secret_rotation') AND (nullif($6, '') IS NULL OR c.id = CASE WHEN $6 ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN $6::uuid END)
			      AND ($2::timestamptz IS NULL OR (c.updated_at, 'secret_rotation:' || c.id::text) < ($2, $3))
			    ORDER BY c.updated_at DESC, c.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'approval', a.id::text, a.resource_kind, a.resource_id, a.resource_name, a.status, a.action,
			          'requested by ' || a.requester || coalesce(nullif(': ' || a.reason, ': '), ''), '', '', '',
			          NULL::uuid, NULL::bigint, a.created_at, a.updated_at
			     FROM operation_approval_requests a
			    WHERE a.tenant_id = $1 AND (a.status <> 'consumed' OR $6 <> '') AND $5 IN ('', 'approval')
			      AND (nullif($6, '') IS NULL OR a.id = CASE WHEN $6 ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN $6::uuid END)
			      AND ($2::timestamptz IS NULL OR (a.updated_at, 'approval:' || a.id::text) < ($2, $3))
			    ORDER BY a.updated_at DESC, a.id DESC LIMIT $4)
			  UNION ALL
			  -- A245-L1: a host or relay agent job is its outbox command; its
			  -- state is the agent's newest signed receipt, else the claim and
			  -- the command. A delivery's job is already a connector_delivery.
			  (SELECT 'agent_job', o.id::text, 'agent_job', coalesce(o.claimed_by_agent_id::text, ''),
			          coalesce(nullif(rc.agent, ''), o.claimed_by_agent_id::text, o.required_agent_role || ' agent'),
			          CASE WHEN rc.outcome IS NOT NULL THEN 'receipt_' || rc.outcome
			               WHEN o.status = 'failed' THEN 'dead_lettered'
			               WHEN o.agent_recalled_at IS NOT NULL THEN 'recalled'
			               WHEN rj.reason IS NOT NULL THEN 'receipt_rejected'
			               WHEN o.claimed_by_agent_id IS NOT NULL AND o.claim_completed_at IS NULL THEN 'claimed'
			               WHEN o.claim_completed_at IS NOT NULL THEN 'completed'
			               ELSE o.status END,
			          coalesce(nullif(rj.reason, ''), o.last_error, ''), 'agent job: ' || o.destination, o.destination, '', '',
			          NULL::uuid, o.id, o.created_at,
			          coalesce(o.agent_recalled_at, o.claim_completed_at, o.delivered_at, o.created_at) AS updated_at
			     FROM outbox o
			     LEFT JOIN LATERAL (SELECT r.outcome, r.agent FROM agent_job_receipts r
			                         WHERE r.tenant_id = o.tenant_id AND r.job_id = o.id AND r.state = 'verified'
			                         ORDER BY r.attempt DESC, r.observed_at DESC LIMIT 1) rc ON true
			     LEFT JOIN LATERAL (SELECT r.reason FROM agent_job_receipts r
			                         WHERE r.tenant_id = o.tenant_id AND r.job_id = o.id AND r.state = 'rejected'
			                         ORDER BY r.attempt DESC, r.observed_at DESC LIMIT 1) rj ON true
			    WHERE o.tenant_id = $1 AND $5 IN ('', 'agent_job') AND (nullif($6, '') IS NULL OR o.id::text = $6)
			      AND (o.required_agent_role IN ('host', 'network') OR o.claimed_by_agent_id IS NOT NULL)
			      AND NOT EXISTS (SELECT 1 FROM connector_delivery_receipts d WHERE d.tenant_id = o.tenant_id AND d.outbox_id = o.id)
			      AND ($2::timestamptz IS NULL OR (coalesce(o.agent_recalled_at, o.claim_completed_at, o.delivered_at, o.created_at),
			           'agent_job:' || o.id::text) < ($2, $3))
			    ORDER BY updated_at DESC, 'agent_job:' || o.id::text DESC LIMIT $4)
			  UNION ALL
			  -- A245-L1: an access session someone ended; a gateway session's
			  -- end is acknowledged only when its gateway reports it.
			  (SELECT 'access_session_revocation', s.id::text, 'access_session', s.id::text,
			          s.subject || ' on ' || s.target_type || ':' || s.target_id,
			          CASE WHEN s.status = 'revoked' AND s.delivery = 'gateway' AND s.gateway_ended_at IS NULL THEN 'revoked_unacknowledged'
			               ELSE s.status END,
			          coalesce(nullif(s.revocation_failure, ''), s.revocation_reason),
			          'revoked by ' || coalesce(nullif(s.revocation_requested_by, ''), 'the system'), s.target_type || ':' || s.target_id, '', '',
			          NULL::uuid, NULL::bigint, coalesce(s.revocation_requested_at, s.started_at),
			          coalesce(s.gateway_ended_at, s.revocation_failed_at, s.ended_at, s.revocation_requested_at, s.started_at) AS updated_at
			     FROM pam_sessions s
			    WHERE s.tenant_id = $1 AND $5 IN ('', 'access_session_revocation') AND (nullif($6, '') IS NULL OR s.id::text = $6)
			      AND (s.revocation_requested_at IS NOT NULL OR s.status IN ('revoking', 'revoked', 'revocation_failed'))
			      AND ($2::timestamptz IS NULL OR (coalesce(s.gateway_ended_at, s.revocation_failed_at, s.ended_at, s.revocation_requested_at, s.started_at),
			           'access_session_revocation:' || s.id::text) < ($2, $3))
			    ORDER BY updated_at DESC, 'access_session_revocation:' || s.id::text DESC LIMIT $4)
			  UNION ALL
			  -- A245-L1: a machine session someone ended.
			  (SELECT 'machine_session_revocation', m.id, 'machine_session', m.id, m.principal || ' (' || m.method || ')', m.status,
			          '', 'revoked by ' || coalesce(nullif(m.revoked_by, ''), 'the system'), m.method, '', '',
			          NULL::uuid, NULL::bigint, m.issued_at, m.revoked_at AS updated_at
			     FROM machine_sessions m
			    WHERE m.tenant_id = $1 AND m.status = 'revoked' AND m.revoked_at IS NOT NULL
			      AND $5 IN ('', 'machine_session_revocation') AND (nullif($6, '') IS NULL OR m.id = $6)
			      AND ($2::timestamptz IS NULL OR (m.revoked_at, 'machine_session_revocation:' || m.id) < ($2, $3))
			    ORDER BY m.revoked_at DESC, 'machine_session_revocation:' || m.id DESC LIMIT $4)
			  UNION ALL
			  -- A245-L1: a managed-key operation at its provider; origin names
			  -- the action asked for.
			  (SELECT 'managed_key_operation', k.operation_id, 'managed_key', coalesce(nullif(k.result_key_id, ''), k.key_id),
			          k.provider || ':' || coalesce(nullif(coalesce(nullif(k.result_key_id, ''), k.key_id), ''), k.algorithm),
			          k.status, coalesce(k.last_error, ''), 'requested ' || k.action, k.provider, '', '',
			          NULL::uuid, k.outbox_id, k.created_at, k.updated_at
			     FROM managed_key_operations k
			    WHERE k.tenant_id = $1 AND $5 IN ('', 'managed_key_operation') AND (nullif($6, '') IS NULL OR k.operation_id = $6)
			      AND ($2::timestamptz IS NULL OR (k.updated_at, 'managed_key_operation:' || k.operation_id) < ($2, $3))
			    ORDER BY k.updated_at DESC, 'managed_key_operation:' || k.operation_id DESC LIMIT $4)
			  UNION ALL
			  -- A245-L1 part 2: an SSH certificate revocation, by serial, key
			  -- ID or both; the key ID itself is never kept. Whether the
			  -- served KRL lists it and the hosts enforce it is read live.
			  (SELECT 'ssh_certificate_revocation', c.event_id, 'ssh_certificate', '',
			          CASE WHEN c.serial <> '' AND c.by_key_id THEN 'serial ' || c.serial || ' and a key ID'
			               WHEN c.serial <> '' THEN 'serial ' || c.serial ELSE 'a key ID' END,
			          'revoked', c.reason, 'revoked by ' || coalesce(nullif(c.revoked_by, ''), 'the system'), '', '', '',
			          NULL::uuid, NULL::bigint, c.revoked_at, c.revoked_at AS updated_at
			     FROM ssh_certificate_revocations c
			    WHERE c.tenant_id = $1 AND $5 IN ('', 'ssh_certificate_revocation') AND (nullif($6, '') IS NULL OR c.event_id = $6)
			      AND ($2::timestamptz IS NULL OR (c.revoked_at, 'ssh_certificate_revocation:' || c.event_id) < ($2, $3))
			    ORDER BY c.revoked_at DESC, 'ssh_certificate_revocation:' || c.event_id DESC LIMIT $4)
			)
			SELECT p.source, p.id, p.subject_kind, p.subject_id, p.subject_name, p.status, p.detail,
			       p.origin, p.target, p.rollback_ref, p.fingerprint,
			       p.fingerprint <> '' AND p.identity_uuid IS NOT NULL AND EXISTS (
			         SELECT 1 FROM connector_delivery_receipts v
			          WHERE v.tenant_id = $1 AND v.identity_id = p.identity_uuid
			            AND v.fingerprint = p.fingerprint AND v.status = 'verified'),
			       p.outbox_id, coalesce(o.status, ''), coalesce(o.attempts, 0),
			       coalesce(o.status = 'processing' AND o.lease_until IS NOT NULL AND o.lease_until < now(), false),
			       p.outbox_id IS NOT NULL AND EXISTS (
			         SELECT 1 FROM outbox_reconciliation_conflicts q
			          WHERE q.tenant_id = $1 AND q.existing_outbox_id = p.outbox_id AND q.status = 'quarantined'),
			       coalesce((SELECT ev.vantage FROM endpoint_verifications ev
			                  WHERE ev.tenant_id = $1 AND p.fingerprint <> '' AND ev.observed_fingerprint = p.fingerprint
			                    AND ev.reached AND ev.mismatch = ''
			                  ORDER BY ev.last_checked_at DESC LIMIT 1), ''),
			       p.created_at, p.updated_at
			  FROM page p
			  LEFT JOIN outbox o ON o.tenant_id = $1 AND o.id = p.outbox_id
			 ORDER BY p.updated_at DESC, p.source || ':' || p.id DESC
			 LIMIT $4`, tenantID, afterAt, afterKey, limit, source, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r OperationLedgerRow
			if err := rows.Scan(&r.Source, &r.ID, &r.SubjectKind, &r.SubjectID, &r.SubjectName, &r.Status, &r.Detail,
				&r.Origin, &r.Target, &r.RollbackRef, &r.Fingerprint, &r.ReadBack, &r.OutboxID, &r.OutboxStatus, &r.OutboxAttempts, &r.OutboxLeaseExpired,
				&r.Quarantined, &r.ObservedVantage, &r.CreatedAt, &r.UpdatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ConsumedApprovalFor returns the newest approval consumed for a resource at or
// before the given time: the authority an operation on it ran under.
func (s *Store) ConsumedApprovalFor(ctx context.Context, tenantID, resourceID string, before time.Time) (OperationApprovalRequest, bool, error) {
	var out OperationApprovalRequest
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
			WHERE r.tenant_id = $1 AND r.resource_id = $2 AND r.status = 'consumed' AND r.consumed_at <= $3
			ORDER BY r.consumed_at DESC, r.id DESC LIMIT 1`, tenantID, resourceID, before)
		request, err := scanOperationApproval(row)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		out, found = request, true
		return nil
	})
	return out, found, err
}
