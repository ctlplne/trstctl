// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// q1l4Campaign starts a campaign of the given items and records a revoke
// decision on each without acting on it, as a request that died after its
// decision would leave it.
func q1l4Campaign(t *testing.T, h *servedHarness, lead, key string, items []map[string]any) q1Campaign {
	t.Helper()
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, key, map[string]any{
		"name": key, "reviewer_subject": "review-bob", "items": items,
	})
	var campaign q1Campaign
	if status != http.StatusCreated || json.Unmarshal(raw, &campaign) != nil || len(campaign.Items) != len(items) {
		t.Fatalf("start campaign %s: HTTP %d %s", key, status, raw)
	}
	reviewer := events.ContextWithActor(t.Context(), events.Actor{Subject: "review-bob"})
	for _, item := range items {
		if _, err := h.srv.orch.DecideNHIReviewItem(reviewer, h.tenant, campaign.ID, item["item_id"].(string), orchestrator.NHIReviewDecisionRequest{
			Decision: "revoked", Reason: "the pipeline moved to workload identity",
		}); err != nil {
			t.Fatalf("record the decision on %s: %v", item["item_id"], err)
		}
	}
	return campaign
}

// TestServedAccessReviewReconcileFinishesEveryOpenItemInOnePassQ1L4 is Q1-L4's
// Done-when (served): the reconcile read at most 200 open items per tenant
// per pass, so a larger backlog drained over several minutes. It now pages
// through all of them: 450 decisions whose requests died (five campaigns, the
// most a campaign holds being 100) are acted on and closed by one call, with
// the default budget, each token revoked once.
func TestServedAccessReviewReconcileFinishesEveryOpenItemInOnePassQ1L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l4-lead", "access:read", "access:write")
	seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	const total = 450
	tokens := make([]string, 0, total)
	for start := 0; start < total; start += orchestrator.MaxNHIReviewCampaignItems {
		var items []map[string]any
		for i := start; i < total && i < start+orchestrator.MaxNHIReviewCampaignItems; i++ {
			_, tokenID := seedM1Token(t, h, fmt.Sprintf("ci-deployer-%03d", i), "certs:read")
			tokens = append(tokens, tokenID)
			items = append(items, map[string]any{
				"item_id": fmt.Sprintf("7b1e0c2a-5d43-4c8e-9b31-%012d", i), "nhi_id": "token:" + tokenID,
				"nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read",
			})
		}
		q1l4Campaign(t, h, lead, fmt.Sprintf("q1l4-campaign-%d", start/orchestrator.MaxNHIReviewCampaignItems), items)
	}
	actorCtx := events.ContextWithActor(t.Context(), events.Actor{Subject: nhiReviewReconcileActor})
	began := time.Now()
	closed, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	if closed != total {
		t.Fatalf("one call closed %d of %d open items (in %s)", closed, total, took)
	}
	var open int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM nhi_access_review_items
		 WHERE tenant_id = $1 AND status = 'revoked' AND revocation_status <> 'closed'`, h.tenant).Scan(&open); err != nil {
		t.Fatal(err)
	}
	revoked := map[string]int{}
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == "api_token.revoked" {
			for _, id := range tokens {
				if strings.Contains(string(e.Data), id) {
					revoked[id]++
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range tokens {
		if revoked[id] != 1 {
			t.Fatalf("token %s was revoked %d times, want once", id, revoked[id])
		}
	}
	if open != 0 {
		t.Fatalf("%d items are still open after the call", open)
	}
	t.Logf("Q1L4_OK closed=%d in %s", closed, took.Round(time.Millisecond))
}

// TestServedAccessReviewReconcileResumesWhereItsBudgetRanOutQ1L4: a pass
// bounded by its budget stops after the item it was on, and the next pass
// resumes just past it, so an item behind others that stay open is still
// reached; once past the end, a pass wraps to the start. With a budget of one
// item per pass, three items left to their own revocation (they stay open)
// come before a token: the fourth pass revokes the token, and the fifth
// visits the first item again.
func TestServedAccessReviewReconcileResumesWhereItsBudgetRanOutQ1L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithNHIReviewReconcileBudget(time.Nanosecond))
	})
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l4-lead", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	_, tokenID := seedM1Token(t, h, "ci-deployer-behind", "certs:read")
	ids := []string{
		"7b1e0c2a-5d43-4c8e-9b31-5b7e0c1a2001", "7b1e0c2a-5d43-4c8e-9b31-5b7e0c1a2002",
		"7b1e0c2a-5d43-4c8e-9b31-5b7e0c1a2003", "7b1e0c2a-5d43-4c8e-9b31-5b7e0c1a2004",
	}
	var items []map[string]any
	for i, id := range ids[:3] {
		items = append(items, map[string]any{
			"item_id": id, "nhi_id": fmt.Sprintf("ext:partner-key-%d", i), "nhi_kind": "partner_api_key",
			"resource": "partner portal", "entitlement": "orders:read",
		})
	}
	items = append(items, map[string]any{
		"item_id": ids[3], "nhi_id": "token:" + tokenID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read",
	})
	// One decision at a time, so the items are listed in this order.
	campaign := q1l4Campaign(t, h, lead, "q1l4-resume", items)
	actorCtx := events.ContextWithActor(t.Context(), events.Actor{Subject: nhiReviewReconcileActor})
	statuses := func() []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = q1GetItem(t, h, bob, campaign.ID, id).RevocationStatus
		}
		return out
	}
	for pass := 1; pass <= 4; pass++ {
		if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		got := statuses()
		for i := range ids {
			acted := got[i] != ""
			if acted != (i < pass) {
				t.Fatalf("after pass %d the items read %q; want the first %d acted on, in order", pass, got, pass)
			}
		}
	}
	if got := statuses(); got[0] != "manual" || got[1] != "manual" || got[2] != "manual" || got[3] != "closed" {
		t.Fatalf("after four passes the items read %q; want three left to their own revocation and the token's closed", got)
	}
	// Past the end, the next pass wraps to the first item.
	if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := statuses(); got[0] != "manual" || got[3] != "closed" {
		t.Fatalf("the wrapped pass left %q", got)
	}
	t.Logf("Q1L4_RESUME_OK token=%s", tokenID)
}
