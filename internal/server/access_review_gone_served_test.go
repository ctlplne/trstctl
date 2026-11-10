// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// Q1-L3: a revoke decision's item closes when its credential reads revoked.
// A credential whose record trstctl no longer holds read as "not yet evidence",
// so its item stayed open on every reconcile pass (and a failed revoke of it
// was retried for a week). Gone is now evidence of its own: the item closes
// with closed_as "gone" and evidence naming what is gone, while an item whose
// credential reads revoked still closes as "revoked".
func TestServedAccessReviewClosesAnItemWhoseCredentialIsGoneQ1L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l3-lead", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	_, goneID := seedM1Token(t, h, "ci-deployer-retired", "certs:read")
	_, heldID := seedM1Token(t, h, "ci-deployer-current", "certs:read")
	const goneItem, heldItem = "6a0f9a52-1d43-4c8e-9b31-5b7e0c1a0001", "6a0f9a52-1d43-4c8e-9b31-5b7e0c1a0002"
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, "q1l3-campaign", map[string]any{
		"name": "CI tokens", "reviewer_subject": "review-bob",
		"items": []map[string]any{
			{"item_id": goneItem, "nhi_id": "token:" + goneID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read"},
			{"item_id": heldItem, "nhi_id": "token:" + heldID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read"},
		},
	})
	var campaign q1Campaign
	if status != http.StatusCreated || json.Unmarshal(raw, &campaign) != nil || len(campaign.Items) != 2 {
		t.Fatalf("start the campaign: HTTP %d %s", status, raw)
	}
	// The retired token's record is removed while the campaign is open.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE tenant_id = $1 AND id = $2`, h.tenant, goneID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, itemID := range []string{goneItem, heldItem} {
		decision := "/api/v1/access/reviews/" + campaign.ID + "/items/" + itemID + "/decision"
		if status, raw := secretsReqKey(t, h, http.MethodPost, decision, bob, "q1l3-revoke-"+itemID, map[string]any{
			"decision": "revoked", "reason": "the pipeline moved to workload identity",
		}); status != http.StatusOK {
			t.Fatalf("revoke %s: HTTP %d %s", itemID, status, raw)
		}
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
	if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC().Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	gone := q1GetItem(t, h, bob, campaign.ID, goneItem)
	if gone.RevocationStatus != "closed" || gone.ClosedAs != "gone" || gone.ClosedAt == nil ||
		!strings.HasPrefix(gone.ClosingEvidence, "gone: trstctl no longer holds the API token") {
		t.Fatalf("the item whose token's record is gone = %+v; want it closed as gone, naming what is gone", gone)
	}
	held := q1GetItem(t, h, bob, campaign.ID, heldItem)
	if held.RevocationStatus != "closed" || held.ClosedAs != "revoked" || !strings.HasPrefix(held.ClosingEvidence, "API token revoked") {
		t.Fatalf("the item whose token reads revoked = %+v; want it closed as revoked", held)
	}
}
