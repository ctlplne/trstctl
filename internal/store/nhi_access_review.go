// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrNHIReviewItemAlreadyDecided = errors.New("nhi access review item already decided")

// NHIReviewCampaign is an IGA-style certification/access-review campaign for
// non-human identities. It is a projection of nhi.access_review.* events.
type NHIReviewCampaign struct {
	ID              string
	TenantID        string
	Name            string
	Scope           string
	ReviewerSubject string
	RequestedBy     string
	Status          string
	DueAt           *time.Time
	ItemCount       int
	PendingCount    int
	CertifiedCount  int
	RevokedCount    int
	ExceptionCount  int
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CompletedAt     *time.Time
	Items           []NHIReviewItem
}

// NHIReviewItem is one non-secret NHI/resource/entitlement fact under review.
type NHIReviewItem struct {
	TenantID             string
	CampaignID           string
	ItemID               string
	NHIID                string
	NHIKind              string
	DisplayName          string
	OwnerRef             string
	Resource             string
	Entitlement          string
	Risk                 string
	EvidenceRefs         []string
	Status               string
	DecisionBy           string
	DecisionReason       string
	DecisionEvidenceRefs []string
	DecidedAt            *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// NHIReviewDecision is a reviewer decision for one campaign item.
type NHIReviewDecision struct {
	CampaignID           string
	ItemID               string
	Decision             string
	ReviewerSubject      string
	Reason               string
	DecisionEvidenceRefs []string
	DecidedAt            time.Time
}

// ApplyNHIReviewCampaignStartedTx projects a campaign-started event. Replays are
// deterministic: event time supplies created_at/updated_at and item rows are
// keyed by (tenant, campaign, item).
func (s *Store) ApplyNHIReviewCampaignStartedTx(ctx context.Context, tx pgx.Tx, c NHIReviewCampaign, items []NHIReviewItem) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO nhi_access_review_campaigns
		        (tenant_id, id, name, scope, reviewer_subject, requested_by, status, due_at,
		         item_count, pending_count, certified_count, revoked_count, exception_count,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, 'open', $7,
		         $8, $8, 0, 0, 0, $9, $9)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		c.TenantID, c.ID, c.Name, c.Scope, c.ReviewerSubject, c.RequestedBy, c.DueAt, len(items), c.CreatedAt)
	if err != nil {
		return err
	}
	for _, item := range items {
		refs := item.EvidenceRefs
		if refs == nil {
			refs = []string{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO nhi_access_review_items
			        (tenant_id, campaign_id, item_id, nhi_id, nhi_kind, display_name, owner_ref,
			         resource, entitlement, risk, evidence_refs, status, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', $12, $12)
			 ON CONFLICT (tenant_id, campaign_id, item_id) DO NOTHING`,
			item.TenantID, item.CampaignID, item.ItemID, item.NHIID, item.NHIKind, item.DisplayName,
			item.OwnerRef, item.Resource, item.Entitlement, item.Risk, refs, c.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

// ApplyNHIReviewItemDecidedTx projects a reviewer decision. A second decision
// with a different event is rejected; an idempotent HTTP replay returns the first
// result before reaching this projector.
func (s *Store) ApplyNHIReviewItemDecidedTx(ctx context.Context, tx pgx.Tx, tenantID string, d NHIReviewDecision) error {
	refs := d.DecisionEvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	tag, err := tx.Exec(ctx,
		`UPDATE nhi_access_review_items
		    SET status = $4,
		        decision_by = $5,
		        decision_reason = $6,
		        decision_evidence_refs = $7,
		        decided_at = $8,
		        updated_at = $8
		  WHERE tenant_id = $1
		    AND campaign_id = $2
		    AND item_id = $3
		    AND status = 'pending'`,
		tenantID, d.CampaignID, d.ItemID, d.Decision, d.ReviewerSubject, d.Reason, refs, d.DecidedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var status string
		err := tx.QueryRow(ctx,
			`SELECT status
			   FROM nhi_access_review_items
			  WHERE tenant_id = $1
			    AND campaign_id = $2
			    AND item_id = $3`,
			tenantID, d.CampaignID, d.ItemID).Scan(&status)
		if err == pgx.ErrNoRows {
			return err
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: item %s is %s", ErrNHIReviewItemAlreadyDecided, d.ItemID, status)
	}
	_, err = tx.Exec(ctx,
		`WITH counts AS (
		    SELECT count(*)::integer AS item_count,
		           count(*) FILTER (WHERE status = 'pending')::integer AS pending_count,
		           count(*) FILTER (WHERE status = 'certified')::integer AS certified_count,
		           count(*) FILTER (WHERE status = 'revoked')::integer AS revoked_count,
		           count(*) FILTER (WHERE status = 'exception')::integer AS exception_count
		      FROM nhi_access_review_items
		     WHERE tenant_id = $1
		       AND campaign_id = $2
		)
		UPDATE nhi_access_review_campaigns c
		   SET item_count = counts.item_count,
		       pending_count = counts.pending_count,
		       certified_count = counts.certified_count,
		       revoked_count = counts.revoked_count,
		       exception_count = counts.exception_count,
		       status = CASE WHEN counts.pending_count = 0 THEN 'completed' ELSE 'open' END,
		       completed_at = CASE WHEN counts.pending_count = 0 THEN COALESCE(c.completed_at, $3) ELSE c.completed_at END,
		       updated_at = $3
		  FROM counts
		 WHERE c.tenant_id = $1
		   AND c.id = $2`,
		tenantID, d.CampaignID, d.DecidedAt)
	return err
}

// GetNHIReviewCampaign loads a campaign and its items under tenant RLS.
func (s *Store) GetNHIReviewCampaign(ctx context.Context, tenantID, id string) (NHIReviewCampaign, error) {
	var out NHIReviewCampaign
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		c, err := scanNHIReviewCampaign(tx.QueryRow(ctx,
			`SELECT tenant_id::text, id::text, name, scope, reviewer_subject, requested_by, status,
			        due_at, item_count, pending_count, certified_count, revoked_count, exception_count,
			        created_at, updated_at, completed_at
			   FROM nhi_access_review_campaigns
			  WHERE tenant_id = $1
			    AND id = $2`,
			tenantID, id))
		if err != nil {
			return err
		}
		items, err := s.listNHIReviewItemsTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		c.Items = items
		out = c
		return nil
	})
	return out, err
}

// ListNHIReviewCampaignsPage lists campaign headers with stable UUID keyset pagination.
func (s *Store) ListNHIReviewCampaignsPage(ctx context.Context, tenantID, after string, limit int) ([]NHIReviewCampaign, error) {
	if after == "" {
		after = ZeroUUID
	}
	var out []NHIReviewCampaign
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, name, scope, reviewer_subject, requested_by, status,
			        due_at, item_count, pending_count, certified_count, revoked_count, exception_count,
			        created_at, updated_at, completed_at
			   FROM nhi_access_review_campaigns
			  WHERE tenant_id = $1
			    AND id > $2
			  ORDER BY id
			  LIMIT $3`,
			tenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanNHIReviewCampaign(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) listNHIReviewItemsTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID string) ([]NHIReviewItem, error) {
	rows, err := tx.Query(ctx,
		`SELECT tenant_id::text, campaign_id::text, item_id::text, nhi_id, nhi_kind, display_name,
		        owner_ref, resource, entitlement, risk, evidence_refs, status, decision_by,
		        decision_reason, decision_evidence_refs, decided_at, created_at, updated_at
		   FROM nhi_access_review_items
		  WHERE tenant_id = $1
		    AND campaign_id = $2
		  ORDER BY created_at, item_id`,
		tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NHIReviewItem
	for rows.Next() {
		item, err := scanNHIReviewItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanNHIReviewCampaign(row pgx.Row) (NHIReviewCampaign, error) {
	var c NHIReviewCampaign
	err := row.Scan(&c.TenantID, &c.ID, &c.Name, &c.Scope, &c.ReviewerSubject, &c.RequestedBy, &c.Status,
		&c.DueAt, &c.ItemCount, &c.PendingCount, &c.CertifiedCount, &c.RevokedCount, &c.ExceptionCount,
		&c.CreatedAt, &c.UpdatedAt, &c.CompletedAt)
	return c, err
}

func scanNHIReviewItem(row pgx.Row) (NHIReviewItem, error) {
	var item NHIReviewItem
	err := row.Scan(&item.TenantID, &item.CampaignID, &item.ItemID, &item.NHIID, &item.NHIKind,
		&item.DisplayName, &item.OwnerRef, &item.Resource, &item.Entitlement, &item.Risk,
		&item.EvidenceRefs, &item.Status, &item.DecisionBy, &item.DecisionReason,
		&item.DecisionEvidenceRefs, &item.DecidedAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}
