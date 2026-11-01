// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Access review outcomes (Q1). A revoke decision records what trstctl did to
// the reviewed credential; the item closes only when the credential is
// observed revoked, never on the request alone.
const (
	// NHIReviewRevocationRequested: trstctl asked the credential's own revoke path.
	NHIReviewRevocationRequested = "requested"
	// NHIReviewRevocationManual: trstctl cannot revoke this kind itself; an
	// operator revokes it through its own revocation.
	NHIReviewRevocationManual = "manual"
	// NHIReviewRevocationFailed: the revoke path refused; the detail says why.
	NHIReviewRevocationFailed = "failed"
	// NHIReviewRevocationClosed: the credential was observed revoked.
	NHIReviewRevocationClosed = "closed"
)

// ApplyNHIReviewRevocationRecordedTx records what trstctl did about a revoke
// decision. A closed item never reopens.
func (s *Store) ApplyNHIReviewRevocationRecordedTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID, itemID, status, detail string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE nhi_access_review_items
		    SET revocation_status = $4, revocation_detail = $5,
		        revocation_requested_at = COALESCE(revocation_requested_at, $6), updated_at = $6
		  WHERE tenant_id = $1 AND campaign_id = $2 AND item_id = $3
		    AND status = 'revoked' AND revocation_status <> 'closed'`,
		tenantID, campaignID, itemID, status, detail, at)
	return err
}

// ApplyNHIReviewItemClosedTx closes a revoke decision on the evidence that the
// reviewed credential is revoked.
func (s *Store) ApplyNHIReviewItemClosedTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID, itemID, evidence string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE nhi_access_review_items
		    SET revocation_status = 'closed', closing_evidence = $4,
		        closed_at = COALESCE(closed_at, $5), updated_at = $5
		  WHERE tenant_id = $1 AND campaign_id = $2 AND item_id = $3
		    AND status = 'revoked' AND revocation_status <> 'closed'`,
		tenantID, campaignID, itemID, evidence, at)
	return err
}

// TenantsWithNHIReviewItemsAwaitingClosure enumerates tenants holding a revoke
// decision that has not closed, so the leader's reconcile can visit each under
// its own RLS context.
func (s *Store) TenantsWithNHIReviewItemsAwaitingClosure(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an access-review revoke decision that has not closed so the leader-only reconcile can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM nhi_access_review_items
		  WHERE status = 'revoked' AND revocation_status <> 'closed' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// ListNHIReviewItemsAwaitingClosure returns the tenant's revoke decisions that
// have not closed, oldest decision first.
func (s *Store) ListNHIReviewItemsAwaitingClosure(ctx context.Context, tenantID string, limit int) ([]NHIReviewItem, error) {
	var out []NHIReviewItem
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+nhiReviewItemColumns+`
			   FROM nhi_access_review_items
			  WHERE tenant_id = $1 AND status = 'revoked' AND revocation_status <> 'closed'
			  ORDER BY decided_at, item_id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanNHIReviewItem(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}
