// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordNHIReviewRevocation records what trstctl did about a revoke decision
// (Q1): requested the credential's own revoke, left it to an operator, or
// failed with the reason.
func (o *Orchestrator) RecordNHIReviewRevocation(ctx context.Context, tenantID, campaignID, itemID, status, detail string) (store.NHIReviewCampaign, error) {
	return o.appendNHIReviewOutcome(ctx, tenantID, campaignID, projections.EventNHIAccessReviewItemRevocationRecorded,
		projections.NHIAccessReviewItemRevocationRecorded{CampaignID: campaignID, ItemID: itemID, Status: status, Detail: trimBounded(detail, 500)})
}

// CloseNHIReviewItem closes a revoke decision on the evidence that the reviewed
// credential is revoked.
func (o *Orchestrator) CloseNHIReviewItem(ctx context.Context, tenantID, campaignID, itemID, evidence string) (store.NHIReviewCampaign, error) {
	return o.appendNHIReviewOutcome(ctx, tenantID, campaignID, projections.EventNHIAccessReviewItemClosed,
		projections.NHIAccessReviewItemClosed{CampaignID: campaignID, ItemID: itemID, Evidence: trimBounded(evidence, 500)})
}

func (o *Orchestrator) appendNHIReviewOutcome(ctx context.Context, tenantID, campaignID, eventType string, payload any) (store.NHIReviewCampaign, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	if err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		return store.NHIReviewCampaign{}, err
	}
	return o.store.GetNHIReviewCampaign(ctx, tenantID, campaignID)
}
