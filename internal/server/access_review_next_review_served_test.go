// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// Q1-L7: a keep decision records when its credential is next reviewed, and
// nothing opened that review when the date passed. The leader's review
// reconcile now opens it: a "Next review" campaign with the same reviewer and
// one pending item per due credential, linked to the item it reviews again,
// whose pending date is cleared so it opens once. A person cannot forge that
// link to cancel another item's next review.
func TestServedAccessReviewOpensTheNextReviewWhenItIsDueQ1L7(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l7-lead", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	_, tokenID := seedM1Token(t, h, "billing-exporter", "certs:read")
	const itemID = "7b1e0c52-3d44-4f8e-9a21-6c7e0d1b0001"
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, "q1l7-campaign", map[string]any{
		"name": "Exporter tokens", "reviewer_subject": "review-bob",
		"items": []map[string]any{{"item_id": itemID, "nhi_id": "token:" + tokenID, "nhi_kind": "api_token",
			"resource": "trstctl api", "entitlement": "certs:read", "evidence_refs": []string{"owner:billing"}}},
	})
	var campaign q1Campaign
	if status != http.StatusCreated || json.Unmarshal(raw, &campaign) != nil || len(campaign.Items) != 1 {
		t.Fatalf("start the campaign: HTTP %d %s", status, raw)
	}
	decision := "/api/v1/access/reviews/" + campaign.ID + "/items/" + itemID + "/decision"
	if status, raw := secretsReqKey(t, h, http.MethodPost, decision, bob, "q1l7-keep", map[string]any{
		"decision": "certified", "reason": "still exports invoices", "next_review_days": 30,
	}); status != http.StatusOK {
		t.Fatalf("keep: HTTP %d %s", status, raw)
	}
	if kept := q1GetItem(t, h, bob, campaign.ID, itemID); kept.NextReviewAt == nil {
		t.Fatalf("the keep decision recorded no next review date: %+v", kept)
	}
	// Thirty days pass: the next review date is behind us.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE nhi_access_review_items SET next_review_at = now() - interval '1 minute'
			WHERE tenant_id = $1 AND campaign_id = $2 AND item_id = $3`, h.tenant, campaign.ID, itemID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	campaigns := func() []store.NHIReviewCampaign {
		t.Helper()
		rows, err := h.store.ListNHIReviewCampaignsPage(ctx, h.tenant, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if err := h.srv.ReconcileNHIReviewsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var next *store.NHIReviewCampaign
	for _, c := range campaigns() {
		if c.ID != campaign.ID {
			c := c
			next = &c
		}
	}
	if next == nil {
		t.Fatal("no next review opened after the item's next review date passed")
	}
	full, err := h.store.GetNHIReviewCampaign(ctx, h.tenant, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Name != "Next review: Exporter tokens" || full.ReviewerSubject != "review-bob" ||
		full.RequestedBy != store.NHIReviewSchedulerSubject || len(full.Items) != 1 {
		t.Fatalf("next review = %+v", full)
	}
	again := full.Items[0]
	if again.NHIID != "token:"+tokenID || again.Status != "pending" || again.Entitlement != "certs:read" ||
		!slices.Contains(again.EvidenceRefs, "owner:billing") ||
		!slices.Contains(again.EvidenceRefs, store.NHIReviewNextReviewOf(campaign.ID, itemID)) {
		t.Fatalf("next review item = %+v", again)
	}
	if kept := q1GetItem(t, h, bob, campaign.ID, itemID); kept.NextReviewAt != nil {
		t.Fatalf("the certified item still holds a pending next review: %+v", kept)
	}
	// It opens once.
	if err := h.srv.ReconcileNHIReviewsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(campaigns()); n != 2 {
		t.Fatalf("campaigns after a second pass = %d, want 2", n)
	}
	// A person cannot forge the link.
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, "q1l7-forged", map[string]any{
		"name": "forged", "reviewer_subject": "review-bob",
		"items": []map[string]any{{"nhi_id": "token:" + tokenID, "nhi_kind": "api_token", "resource": "trstctl api",
			"entitlement": "certs:read", "evidence_refs": []string{store.NHIReviewNextReviewOf(campaign.ID, itemID)}}},
	})
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "next-review-of") {
		t.Fatalf("a person's campaign carrying a next-review link = HTTP %d %s, want 400", status, raw)
	}
}
