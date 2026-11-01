// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Access review outcomes (Q1): what trstctl did about a revoke decision, and
// the evidence that closed it.
const (
	EventNHIAccessReviewItemRevocationRecorded = "nhi.access_review.item.revocation_recorded"
	EventNHIAccessReviewItemClosed             = "nhi.access_review.item.closed"
)

// NHIAccessReviewItemRevocationRecorded is what trstctl did to the reviewed
// credential: requested its revoke, left it to an operator (manual), or failed.
type NHIAccessReviewItemRevocationRecorded struct {
	CampaignID string `json:"campaign_id"`
	ItemID     string `json:"item_id"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
}

// NHIAccessReviewItemClosed is the evidence that the reviewed credential is
// revoked.
type NHIAccessReviewItemClosed struct {
	CampaignID string `json:"campaign_id"`
	ItemID     string `json:"item_id"`
	Evidence   string `json:"evidence"`
}

func (p *Projector) applyNHIReviewRevocationRecorded(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var pl NHIAccessReviewItemRevocationRecorded
	if err := decode(e, &pl); err != nil {
		return err
	}
	switch pl.Status {
	case store.NHIReviewRevocationRequested, store.NHIReviewRevocationManual, store.NHIReviewRevocationFailed:
	default:
		return fmt.Errorf("projections: %s has an unknown status %q", e.Type, pl.Status)
	}
	if pl.CampaignID == "" || pl.ItemID == "" {
		return fmt.Errorf("projections: %s requires campaign_id and item_id", e.Type)
	}
	return p.store.ApplyNHIReviewRevocationRecordedTx(ctx, tx, e.TenantID, pl.CampaignID, pl.ItemID, pl.Status, pl.Detail, e.Time)
}

func (p *Projector) applyNHIReviewItemClosed(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var pl NHIAccessReviewItemClosed
	if err := decode(e, &pl); err != nil {
		return err
	}
	if pl.CampaignID == "" || pl.ItemID == "" || pl.Evidence == "" {
		return fmt.Errorf("projections: %s requires campaign_id, item_id and evidence", e.Type)
	}
	return p.store.ApplyNHIReviewItemClosedTx(ctx, tx, e.TenantID, pl.CampaignID, pl.ItemID, pl.Evidence, e.Time)
}
