// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const MaxNHIReviewCampaignItems = 100

// NHIReviewCampaignStartRequest is metadata-only. It names NHIs, resources,
// entitlements, and evidence references; it never carries credential values.
type NHIReviewCampaignStartRequest struct {
	ID              string                 `json:"id,omitempty"`
	Name            string                 `json:"name"`
	Scope           string                 `json:"scope,omitempty"`
	ReviewerSubject string                 `json:"reviewer_subject,omitempty"`
	DueAt           *time.Time             `json:"due_at,omitempty"`
	Items           []NHIReviewItemRequest `json:"items"`
}

// NHIReviewItemRequest is one campaign item to certify.
type NHIReviewItemRequest struct {
	ItemID       string   `json:"item_id,omitempty"`
	NHIID        string   `json:"nhi_id"`
	NHIKind      string   `json:"nhi_kind"`
	DisplayName  string   `json:"display_name,omitempty"`
	OwnerRef     string   `json:"owner_ref,omitempty"`
	Resource     string   `json:"resource"`
	Entitlement  string   `json:"entitlement"`
	Risk         string   `json:"risk,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// NHIReviewDecisionRequest records the human certification/access-review result.
type NHIReviewDecisionRequest struct {
	Decision             string   `json:"decision"`
	ReviewerSubject      string   `json:"reviewer_subject,omitempty"`
	Reason               string   `json:"reason,omitempty"`
	DecisionEvidenceRefs []string `json:"decision_evidence_refs,omitempty"`
}

func (o *Orchestrator) StartNHIReviewCampaign(ctx context.Context, tenantID string, in NHIReviewCampaignStartRequest) (store.NHIReviewCampaign, error) {
	payload, err := normalizeNHIReviewCampaign(ctx, in)
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	evData, err := json.Marshal(payload)
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	var ev events.Event
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		ev, err = o.log.Append(ctx, events.Event{Type: projections.EventNHIAccessReviewCampaignStarted, TenantID: tenantID, Data: evData})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		return store.NHIReviewCampaign{}, err
	}
	return o.store.GetNHIReviewCampaign(ctx, tenantID, payload.ID)
}

func (o *Orchestrator) DecideNHIReviewItem(ctx context.Context, tenantID, campaignID, itemID string, in NHIReviewDecisionRequest) (store.NHIReviewCampaign, error) {
	campaign, err := o.store.GetNHIReviewCampaign(ctx, tenantID, strings.TrimSpace(campaignID))
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	item, ok := findNHIReviewItem(campaign.Items, strings.TrimSpace(itemID))
	if !ok {
		return store.NHIReviewCampaign{}, pgx.ErrNoRows
	}
	if item.Status != "pending" {
		return store.NHIReviewCampaign{}, fmt.Errorf("%w: item %s is %s", store.ErrNHIReviewItemAlreadyDecided, item.ItemID, item.Status)
	}
	payload, err := normalizeNHIReviewDecision(ctx, campaign.ID, item.ItemID, in)
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	evData, err := json.Marshal(payload)
	if err != nil {
		return store.NHIReviewCampaign{}, err
	}
	var ev events.Event
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		ev, err = o.log.Append(ctx, events.Event{Type: projections.EventNHIAccessReviewItemDecided, TenantID: tenantID, Data: evData})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		return store.NHIReviewCampaign{}, err
	}
	return o.store.GetNHIReviewCampaign(ctx, tenantID, campaign.ID)
}

func normalizeNHIReviewCampaign(ctx context.Context, in NHIReviewCampaignStartRequest) (projections.NHIAccessReviewCampaignStarted, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	} else if _, err := uuid.Parse(id); err != nil {
		return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("campaign id must be a UUID")
	}
	name := trimBounded(in.Name, 160)
	if name == "" {
		return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("name is required")
	}
	scope := trimBounded(in.Scope, 120)
	if scope == "" {
		scope = "all_nhi"
	}
	reviewer := trimBounded(in.ReviewerSubject, 180)
	if reviewer == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			reviewer = trimBounded(actor.Subject, 180)
		}
	}
	if reviewer == "" {
		return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("reviewer_subject is required")
	}
	requestedBy := reviewer
	if actor, ok := events.ActorFromContext(ctx); ok && strings.TrimSpace(actor.Subject) != "" {
		requestedBy = trimBounded(actor.Subject, 180)
	}
	if len(in.Items) == 0 {
		return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("at least one NHI access review item is required")
	}
	if len(in.Items) > MaxNHIReviewCampaignItems {
		return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("at most %d NHI access review items are allowed", MaxNHIReviewCampaignItems)
	}
	items := make([]projections.NHIAccessReviewItem, 0, len(in.Items))
	seen := map[string]bool{}
	for _, raw := range in.Items {
		item, err := normalizeNHIReviewItem(raw)
		if err != nil {
			return projections.NHIAccessReviewCampaignStarted{}, err
		}
		if seen[item.ItemID] {
			return projections.NHIAccessReviewCampaignStarted{}, fmt.Errorf("duplicate item_id %s", item.ItemID)
		}
		seen[item.ItemID] = true
		items = append(items, item)
	}
	return projections.NHIAccessReviewCampaignStarted{
		ID: id, Name: name, Scope: scope, ReviewerSubject: reviewer,
		RequestedBy: requestedBy, DueAt: in.DueAt, Items: items,
	}, nil
}

func normalizeNHIReviewItem(in NHIReviewItemRequest) (projections.NHIAccessReviewItem, error) {
	itemID := strings.TrimSpace(in.ItemID)
	if itemID == "" {
		itemID = uuid.NewString()
	} else if _, err := uuid.Parse(itemID); err != nil {
		return projections.NHIAccessReviewItem{}, fmt.Errorf("item_id must be a UUID")
	}
	nhiID := trimBounded(in.NHIID, 240)
	nhiKind := trimBounded(in.NHIKind, 80)
	resource := trimBounded(in.Resource, 240)
	entitlement := trimBounded(in.Entitlement, 160)
	if nhiID == "" || nhiKind == "" || resource == "" || entitlement == "" {
		return projections.NHIAccessReviewItem{}, fmt.Errorf("nhi_id, nhi_kind, resource, and entitlement are required")
	}
	displayName := trimBounded(in.DisplayName, 200)
	if displayName == "" {
		displayName = nhiID
	}
	risk := strings.ToLower(trimBounded(in.Risk, 40))
	if risk == "" {
		risk = "medium"
	}
	refs, err := normalizeEvidenceRefs(in.EvidenceRefs)
	if err != nil {
		return projections.NHIAccessReviewItem{}, err
	}
	return projections.NHIAccessReviewItem{
		ItemID: itemID, NHIID: nhiID, NHIKind: nhiKind, DisplayName: displayName,
		OwnerRef: trimBounded(in.OwnerRef, 180), Resource: resource, Entitlement: entitlement,
		Risk: risk, EvidenceRefs: refs,
	}, nil
}

func normalizeNHIReviewDecision(ctx context.Context, campaignID, itemID string, in NHIReviewDecisionRequest) (projections.NHIAccessReviewItemDecided, error) {
	decision := strings.ToLower(strings.TrimSpace(in.Decision))
	switch decision {
	case "certified", "revoked", "exception":
	default:
		return projections.NHIAccessReviewItemDecided{}, fmt.Errorf("decision must be certified, revoked, or exception")
	}
	reviewer := trimBounded(in.ReviewerSubject, 180)
	if reviewer == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			reviewer = trimBounded(actor.Subject, 180)
		}
	}
	if reviewer == "" {
		return projections.NHIAccessReviewItemDecided{}, fmt.Errorf("reviewer_subject is required")
	}
	reason := trimBounded(in.Reason, 500)
	if decision != "certified" && reason == "" {
		return projections.NHIAccessReviewItemDecided{}, fmt.Errorf("reason is required for revoked or exception decisions")
	}
	refs, err := normalizeEvidenceRefs(in.DecisionEvidenceRefs)
	if err != nil {
		return projections.NHIAccessReviewItemDecided{}, err
	}
	return projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: decision,
		ReviewerSubject: reviewer, Reason: reason, DecisionEvidenceRefs: refs,
		DecidedAt: time.Now().UTC(),
	}, nil
}

func normalizeEvidenceRefs(refs []string) ([]string, error) {
	if len(refs) > 20 {
		return nil, fmt.Errorf("at most 20 evidence_refs are allowed")
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = trimBounded(ref, 260)
		if ref == "" {
			continue
		}
		out = append(out, ref)
	}
	return out, nil
}

func findNHIReviewItem(items []store.NHIReviewItem, itemID string) (store.NHIReviewItem, bool) {
	for _, item := range items {
		if item.ItemID == itemID {
			return item, true
		}
	}
	return store.NHIReviewItem{}, false
}

func trimBounded(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}
