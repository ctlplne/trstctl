// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The certificate inventory's delivery evidence (A244): for each identity,
// the certificate its latest completed delivery carried, whether that
// certificate is still the identity's active one, and whether anything saw
// an endpoint serve it — the connector reading it back, or an endpoint
// verification from a local or relay vantage.

// InventoryEvidence is one identity's delivery evidence.
type InventoryEvidence struct {
	Fingerprint string
	// ReceiptStatus is the delivery's: delivered, verified (read back) or
	// rolled_back.
	ReceiptStatus string
	DeliveredAt   time.Time
	// Active reports that the delivered certificate is still active: no
	// renewal superseded it and nothing revoked it.
	Active bool
	// ObservedVantage and ObservedAt name the newest clean endpoint
	// verification that saw the certificate served; empty when none did.
	ObservedVantage string
	ObservedAt      *time.Time
}

// IdentityInventoryEvidence returns the delivery evidence for each identity in
// ids that has a completed delivery.
func (s *Store) IdentityInventoryEvidence(ctx context.Context, tenantID string, ids []string) (map[string]InventoryEvidence, error) {
	out := map[string]InventoryEvidence{}
	if len(ids) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (r.identity_id)
			       r.identity_id::text, r.fingerprint, r.status, r.updated_at,
			       coalesce(c.status = 'active', false),
			       coalesce(v.vantage, ''), v.last_checked_at
			  FROM connector_delivery_receipts r
			  LEFT JOIN certificates c ON c.tenant_id = r.tenant_id AND c.fingerprint = r.fingerprint
			  LEFT JOIN LATERAL (
			        SELECT vantage, last_checked_at FROM endpoint_verifications ev
			         WHERE ev.tenant_id = r.tenant_id AND ev.observed_fingerprint = r.fingerprint
			           AND ev.reached AND ev.mismatch = ''
			         ORDER BY ev.last_checked_at DESC LIMIT 1) v ON true
			 WHERE r.tenant_id = $1 AND r.identity_id = ANY($2::uuid[]) AND r.fingerprint <> ''
			   AND ((r.destination IN ('connector.deploy', 'endpoint.renew') AND r.status IN ('delivered', 'verified'))
			     OR (r.destination = 'connector.rollback' AND r.status = 'rolled_back'))
			 ORDER BY r.identity_id, r.updated_at DESC, r.id DESC`, tenantID, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id string
				e  InventoryEvidence
			)
			if err := rows.Scan(&id, &e.Fingerprint, &e.ReceiptStatus, &e.DeliveredAt, &e.Active, &e.ObservedVantage, &e.ObservedAt); err != nil {
				return err
			}
			out[id] = e
		}
		return rows.Err()
	})
	return out, err
}

// IdentityApprovals lists an identity's newest operation approvals, any
// status.
func (s *Store) IdentityApprovals(ctx context.Context, tenantID, identityID string, limit int) ([]OperationApprovalRequest, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	var out []OperationApprovalRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
			WHERE r.tenant_id = $1 AND r.resource_kind = 'identity' AND r.resource_id = $2
			ORDER BY r.created_at DESC, r.id DESC LIMIT $3`, tenantID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			request, err := scanOperationApproval(rows)
			if err != nil {
				return err
			}
			out = append(out, request)
		}
		return rows.Err()
	})
	return out, err
}
