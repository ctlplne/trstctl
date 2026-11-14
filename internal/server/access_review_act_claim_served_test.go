// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestServedAccessReviewActsOnADiedDecisionAtTheNextPassQ1L10 is Q1-L10's
// Done-when (served): the reconcile no longer waits a fixed two minutes after
// a decision before acting on it. A decision whose request died after it was
// recorded is acted on at the very next pass, once. While the decision's own
// request still holds the item's act claim the reconcile does not act on it,
// however long ago the decision was; when that request's database session
// dies the claim goes with it and the next pass acts, once. A decision made
// through the API acts in its own request and the reconcile never repeats it.
func TestServedAccessReviewActsOnADiedDecisionAtTheNextPassQ1L10(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l10-lead", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	_, diedID := seedM1Token(t, h, "ci-deployer-died", "certs:read")
	_, heldID := seedM1Token(t, h, "ci-deployer-held", "certs:read")
	_, liveID := seedM1Token(t, h, "ci-deployer-live", "certs:read")
	const diedItem, heldItem, liveItem = "6a0f9a52-1d43-4c8e-9b31-5b7e0c1a1001", "6a0f9a52-1d43-4c8e-9b31-5b7e0c1a1002", "6a0f9a52-1d43-4c8e-9b31-5b7e0c1a1003"
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, "q1l10-campaign", map[string]any{
		"name": "CI tokens", "reviewer_subject": "review-bob",
		"items": []map[string]any{
			{"item_id": diedItem, "nhi_id": "token:" + diedID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read"},
			{"item_id": heldItem, "nhi_id": "token:" + heldID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read"},
			{"item_id": liveItem, "nhi_id": "token:" + liveID, "nhi_kind": "api_token", "resource": "trstctl api", "entitlement": "certs:read"},
		},
	})
	var campaign q1Campaign
	if status != http.StatusCreated || json.Unmarshal(raw, &campaign) != nil || len(campaign.Items) != 3 {
		t.Fatalf("start the campaign: HTTP %d %s", status, raw)
	}
	revocations := func(tokenID string) int {
		t.Helper()
		n := 0
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID == h.tenant && e.Type == "api_token.revoked" && strings.Contains(string(e.Data), tokenID) {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	reviewer := events.ContextWithActor(ctx, events.Actor{Subject: "review-bob"})
	decideOnly := func(itemID string) {
		t.Helper()
		if _, err := h.srv.orch.DecideNHIReviewItem(reviewer, h.tenant, campaign.ID, itemID, orchestrator.NHIReviewDecisionRequest{
			Decision: "revoked", Reason: "the pipeline moved to workload identity",
		}); err != nil {
			t.Fatalf("record the decision on %s: %v", itemID, err)
		}
	}
	reconcileNow := func() {
		t.Helper()
		actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
		if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC()); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	// A request that died after its decision was recorded: the very next
	// pass acts on it, with no fixed wait, and only once.
	decideOnly(diedItem)
	reconcileNow()
	if got := q1GetItem(t, h, bob, campaign.ID, diedItem); got.RevocationStatus != "closed" || !strings.HasPrefix(got.ClosingEvidence, "API token revoked") {
		t.Fatalf("the next pass after a died decision left the item %+v; want its token revoked and the item closed", got)
	}
	reconcileNow()
	if n := revocations(diedID); n != 1 {
		t.Fatalf("the died decision's token was revoked %d times, want once", n)
	}

	// A request still acting holds the item's act claim: the reconcile does
	// not act on its decision, however long ago it was made.
	decideOnly(heldItem)
	claimed, stop, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		acquired, err := h.store.WithNHIReviewActClaim(context.Background(), h.tenant, campaign.ID, heldItem, func(context.Context) error {
			close(claimed)
			<-stop
			return nil
		})
		if err == nil && !acquired {
			err = context.Canceled
		}
		finished <- err
	}()
	select {
	case <-claimed:
	case err := <-finished:
		t.Fatalf("hold the act claim as the deciding request: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the act claim was not taken")
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
	if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := q1GetItem(t, h, bob, campaign.ID, heldItem); got.RevocationStatus != "" || revocations(heldID) != 0 {
		t.Fatalf("the reconcile acted on a decision whose request still holds its claim: %+v", got)
	}
	// Another request on the item answers 409 while the claim is held.
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/"+campaign.ID+"/items/"+heldItem+"/decision", bob, "q1l10-while-held",
		map[string]any{"decision": "revoked", "reason": "the pipeline moved to workload identity"}); status != http.StatusConflict ||
		!strings.Contains(string(raw), "being acted on now") {
		t.Fatalf("a decision request while the item's claim is held: HTTP %d %s", status, raw)
	}
	// The deciding request's process dies: its database session ends, and
	// the claim with it, without a release.
	var holders []int32
	rows, err := h.store.SystemPool().Query(ctx, `SELECT pid FROM pg_locks
		 WHERE locktype = 'advisory' AND objsubid = 1 AND granted
		   AND ((classid::bigint << 32) | objid::bigint) = hashtextextended($1, 0)`,
		"nhi-review-act\x1f"+h.tenant+"\x1f"+campaign.ID+"\x1f"+heldItem)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var pid int32
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		holders = append(holders, pid)
	}
	rows.Close()
	if len(holders) != 1 {
		t.Fatalf("the act claim is held by %d sessions, want 1", len(holders))
	}
	if _, err := h.store.SystemPool().Exec(ctx, `SELECT pg_terminate_backend($1)`, holders[0]); err != nil {
		t.Fatal(err)
	}
	close(stop)
	<-finished // the dead session cannot release the claim; it is already gone
	var stillHeld bool
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1)`, holders[0]).Scan(&stillHeld); err != nil {
			t.Fatal(err)
		}
		if !stillHeld || time.Now().After(deadline) {
			break
		}
	}
	if stillHeld {
		t.Fatal("the terminated session still holds locks")
	}
	reconcileNow()
	if got := q1GetItem(t, h, bob, campaign.ID, heldItem); got.RevocationStatus != "closed" || !strings.HasPrefix(got.ClosingEvidence, "API token revoked") {
		t.Fatalf("the pass after the deciding request died left the item %+v; want its token revoked and the item closed", got)
	}
	reconcileNow()
	if n := revocations(heldID); n != 1 {
		t.Fatalf("the held decision's token was revoked %d times, want once", n)
	}

	// A decision through the API acts in its own request; the reconcile never
	// repeats it.
	decision := "/api/v1/access/reviews/" + campaign.ID + "/items/" + liveItem + "/decision"
	status, raw = secretsReqKey(t, h, http.MethodPost, decision, bob, "q1l10-revoke-live", map[string]any{
		"decision": "revoked", "reason": "the pipeline moved to workload identity",
	})
	if decided := q1ItemFrom(t, status, raw, liveItem); decided.RevocationStatus != "requested" {
		t.Fatalf("the API decision = %+v; want its revocation requested in the request", decided)
	}
	reconcileNow()
	reconcileNow()
	if got := q1GetItem(t, h, bob, campaign.ID, liveItem); got.RevocationStatus != "closed" || revocations(liveID) != 1 {
		t.Fatalf("the API decision's item %+v with %d revocations; want closed after exactly one", got, revocations(liveID))
	}
	t.Logf("Q1L10_OK died=%s held=%s live=%s", diedItem, heldItem, liveItem)
}
