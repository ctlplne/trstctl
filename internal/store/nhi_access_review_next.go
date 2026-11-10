// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Next reviews (Q1-L7). A keep decision records when its credential is next
// reviewed; once that date passes, the leader's review reconcile opens a
// campaign that reviews the credential again. Each item of that campaign
// carries an evidence ref naming the certified item it reviews again, and
// projecting the campaign clears that item's pending next review date, in the
// same transaction, so the date is acted on exactly once.

// NHIReviewSchedulerSubject is the requester of a campaign the review
// reconcile opens; only its campaigns' next-review links are honored.
const NHIReviewSchedulerSubject = "trstctl:access-review-reconcile"

// nhiReviewNextReviewOfPrefix opens the evidence ref that links an item of a
// next review to the certified item it reviews again.
const nhiReviewNextReviewOfPrefix = "next-review-of:"

// NHIReviewNextReviewOf is the evidence ref linking an item to the certified
// item (campaignID, itemID) it reviews again.
func NHIReviewNextReviewOf(campaignID, itemID string) string {
	return nhiReviewNextReviewOfPrefix + campaignID + "/" + itemID
}

// IsNHIReviewNextReviewRef reports whether ref is a next-review link. A
// campaign a person starts may not carry one.
func IsNHIReviewNextReviewRef(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), nhiReviewNextReviewOfPrefix)
}

// parseNHIReviewNextReviewOf reads a next-review link; both ids are UUIDs.
func parseNHIReviewNextReviewOf(ref string) (string, string, bool) {
	rest, ok := strings.CutPrefix(ref, nhiReviewNextReviewOfPrefix)
	if !ok {
		return "", "", false
	}
	campaignID, itemID, ok := strings.Cut(rest, "/")
	if !ok {
		return "", "", false
	}
	if _, err := uuid.Parse(campaignID); err != nil {
		return "", "", false
	}
	if _, err := uuid.Parse(itemID); err != nil {
		return "", "", false
	}
	return campaignID, itemID, true
}

// clearNextReviewsOpenedByTx clears the pending next review date of each
// certified item a scheduler campaign's items link to.
func clearNextReviewsOpenedByTx(ctx context.Context, tx pgx.Tx, c NHIReviewCampaign, items []NHIReviewItem) error {
	if c.RequestedBy != NHIReviewSchedulerSubject {
		return nil
	}
	for _, item := range items {
		for _, ref := range item.EvidenceRefs {
			campaignID, itemID, ok := parseNHIReviewNextReviewOf(ref)
			if !ok {
				continue
			}
			if _, err := tx.Exec(ctx,
				`UPDATE nhi_access_review_items SET next_review_at = NULL, updated_at = $4
				  WHERE tenant_id = $1 AND campaign_id = $2 AND item_id = $3 AND status = 'certified'`,
				c.TenantID, campaignID, itemID, c.CreatedAt); err != nil {
				return err
			}
		}
	}
	return nil
}

// TenantsWithNHIReviewsDue enumerates the tenants holding a certified item
// whose next review date has passed.
func (s *Store) TenantsWithNHIReviewsDue(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold a certified access-review item whose next review is due so the leader-only reconcile can open each tenant's next review under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM nhi_access_review_items
		  WHERE status = 'certified' AND next_review_at IS NOT NULL AND next_review_at <= $1 ORDER BY 1`, now)
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

// ListNHIReviewItemsDueForNextReview returns the tenant's certified items
// whose next review date has passed, earliest first.
func (s *Store) ListNHIReviewItemsDueForNextReview(ctx context.Context, tenantID string, now time.Time, limit int) ([]NHIReviewItem, error) {
	var out []NHIReviewItem
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+nhiReviewItemColumns+`
			   FROM nhi_access_review_items
			  WHERE tenant_id = $1 AND status = 'certified' AND next_review_at IS NOT NULL AND next_review_at <= $2
			  ORDER BY next_review_at, campaign_id, item_id
			  LIMIT $3`, tenantID, now, limit)
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
