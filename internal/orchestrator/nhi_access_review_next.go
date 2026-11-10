// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// nhiNextReviewNamespace makes a next review's campaign, item and event ids
// deterministic from the items it reviews again, so a retried pass appends the
// same event (the log suppresses the duplicate) and projects the same rows.
var nhiNextReviewNamespace = uuid.MustParse("4c2b9d1e-7a36-5f0e-9b8d-2e61a0c4f7d3")

// OpenDueNHINextReviews opens the next review of the tenant's certified items
// whose next review date has passed (Q1-L7): one campaign per campaign they
// were certified in, "Next review: <name>", with the same scope and reviewer
// and the same time to decide, and one pending item per credential carrying
// the same facts and a link to the item it reviews again. Projecting it clears
// those items' pending dates. The caller's actor must be the review reconcile
// (store.NHIReviewSchedulerSubject). It returns how many items it opened.
func (o *Orchestrator) OpenDueNHINextReviews(ctx context.Context, tenantID string, now time.Time) (int, error) {
	actor, ok := events.ActorFromContext(ctx)
	if !ok || actor.Subject != store.NHIReviewSchedulerSubject {
		return 0, fmt.Errorf("orchestrator: only the access review reconcile opens next reviews")
	}
	due, err := o.store.ListNHIReviewItemsDueForNextReview(ctx, tenantID, now, MaxNHIReviewCampaignItems)
	if err != nil {
		return 0, err
	}
	byCampaign := map[string][]store.NHIReviewItem{}
	var order []string
	for _, item := range due {
		if _, seen := byCampaign[item.CampaignID]; !seen {
			order = append(order, item.CampaignID)
		}
		byCampaign[item.CampaignID] = append(byCampaign[item.CampaignID], item)
	}
	opened := 0
	for _, campaignID := range order {
		previous, err := o.store.GetNHIReviewCampaign(ctx, tenantID, campaignID)
		if err != nil {
			return opened, err
		}
		payload := nextNHIReviewCampaign(tenantID, previous, byCampaign[campaignID], now)
		data, err := json.Marshal(payload)
		if err != nil {
			return opened, err
		}
		eventID := uuid.NewSHA1(nhiNextReviewNamespace, []byte(tenantID+"/event/"+payload.ID)).String()
		if err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			ev, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventNHIAccessReviewCampaignStarted, TenantID: tenantID, Data: data})
			if err != nil {
				return err
			}
			return o.proj.ApplyTx(ctx, tx, ev)
		}); err != nil {
			return opened, err
		}
		opened += len(payload.Items)
	}
	return opened, nil
}

// nextNHIReviewCampaign is the campaign that reviews due again.
func nextNHIReviewCampaign(tenantID string, previous store.NHIReviewCampaign, due []store.NHIReviewItem, now time.Time) projections.NHIAccessReviewCampaignStarted {
	ids := make([]string, 0, len(due))
	for _, item := range due {
		ids = append(ids, item.ItemID)
	}
	sort.Strings(ids)
	campaignID := uuid.NewSHA1(nhiNextReviewNamespace, []byte(tenantID+"/campaign/"+previous.ID+"/"+strings.Join(ids, ","))).String()
	var dueAt *time.Time
	if previous.DueAt != nil && previous.DueAt.After(previous.CreatedAt) {
		at := now.Add(previous.DueAt.Sub(previous.CreatedAt)).UTC()
		dueAt = &at
	}
	reviewer := previous.ReviewerSubject
	items := make([]projections.NHIAccessReviewItem, 0, len(due))
	for _, item := range due {
		refs := item.EvidenceRefs
		if len(refs) > 19 {
			refs = refs[:19]
		}
		refs = append(append([]string(nil), refs...), store.NHIReviewNextReviewOf(item.CampaignID, item.ItemID))
		items = append(items, projections.NHIAccessReviewItem{
			ItemID: uuid.NewSHA1(nhiNextReviewNamespace, []byte(campaignID+"/item/"+item.ItemID)).String(),
			NHIID:  item.NHIID, NHIKind: item.NHIKind, DisplayName: item.DisplayName, OwnerRef: item.OwnerRef,
			Resource: item.Resource, Entitlement: item.Entitlement, Risk: item.Risk, EvidenceRefs: refs,
		})
	}
	return projections.NHIAccessReviewCampaignStarted{
		ID: campaignID, Name: trimBounded("Next review: "+previous.Name, 160), Scope: previous.Scope,
		ReviewerSubject: reviewer, RequestedBy: store.NHIReviewSchedulerSubject, DueAt: dueAt, Items: items,
	}
}
