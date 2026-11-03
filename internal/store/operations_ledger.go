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
// presenting the certificate it carried. It writes nothing.

// OperationLedgerRow is one operation as its own source records it.
type OperationLedgerRow struct {
	// Source is certificate_rotation, connector_delivery, secret_rotation or
	// approval.
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
			    WHERE r.tenant_id = $1 AND $5 IN ('', 'certificate_rotation') AND (nullif($6, '') IS NULL OR r.id = nullif($6, '')::uuid)
			      AND ($2::timestamptz IS NULL OR (r.updated_at, 'certificate_rotation:' || r.id::text) < ($2, $3))
			    ORDER BY r.updated_at DESC, r.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'connector_delivery', d.id::text, coalesce(i.kind, ''), coalesce(d.identity_id::text, ''),
			          coalesce(i.name, d.target), d.status, d.detail, d.reason, d.target, d.rollback_ref, d.fingerprint,
			          d.identity_id, d.outbox_id, d.created_at, d.updated_at
			     FROM connector_delivery_receipts d
			     LEFT JOIN identities i ON i.tenant_id = d.tenant_id AND i.id = d.identity_id
			    WHERE d.tenant_id = $1 AND $5 IN ('', 'connector_delivery') AND (nullif($6, '') IS NULL OR d.id = nullif($6, '')::uuid)
			      AND ($2::timestamptz IS NULL OR (d.updated_at, 'connector_delivery:' || d.id::text) < ($2, $3))
			    ORDER BY d.updated_at DESC, d.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'secret_rotation', c.id::text, 'secret', '', c.secret_key, c.phase, coalesce(c.error, ''),
			          CASE WHEN c.schedule_id IS NULL THEN 'manual rotation' ELSE 'scheduled rotation' END, c.provider, '', '',
			          NULL::uuid, nullif(c.outbox_id, 0), c.created_at, c.updated_at
			     FROM secret_static_rotation_commands c
			    WHERE c.tenant_id = $1 AND $5 IN ('', 'secret_rotation') AND (nullif($6, '') IS NULL OR c.id = nullif($6, '')::uuid)
			      AND ($2::timestamptz IS NULL OR (c.updated_at, 'secret_rotation:' || c.id::text) < ($2, $3))
			    ORDER BY c.updated_at DESC, c.id DESC LIMIT $4)
			  UNION ALL
			  (SELECT 'approval', a.id::text, a.resource_kind, a.resource_id, a.resource_name, a.status, a.action,
			          'requested by ' || a.requester || coalesce(nullif(': ' || a.reason, ': '), ''), '', '', '',
			          NULL::uuid, NULL::bigint, a.created_at, a.updated_at
			     FROM operation_approval_requests a
			    WHERE a.tenant_id = $1 AND (a.status <> 'consumed' OR $6 <> '') AND $5 IN ('', 'approval')
			      AND (nullif($6, '') IS NULL OR a.id = nullif($6, '')::uuid)
			      AND ($2::timestamptz IS NULL OR (a.updated_at, 'approval:' || a.id::text) < ($2, $3))
			    ORDER BY a.updated_at DESC, a.id DESC LIMIT $4)
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
