// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Q1-L2: a failed review revocation is retried. A reviewer revokes a PAM
// session through an access review and the session's provider removal fails
// for good, so the item reads failed. The leader's reconcile does not retry
// before its backoff passes and retries on its own after it, under a fresh
// key PAM accepts (PAM refuses to retry a failed revocation under the key that
// failed). When that attempt fails too, an operator retries with a reason: an
// exact replay answers the same without a second attempt, a retry of a
// revocation that is not failed is refused, and the item closes once the
// repaired removal revokes the session and PostgreSQL refuses the login.
func TestServedAccessReviewFailedRevocationIsRetriedQ1L2(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, pamPostgresAdminFileRef(t, pgDSN), 5*time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 3 * time.Minute, MaxTTL: 5 * time.Minute,
			Attestors:       []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"}}},
		}
	})
	// Serve issuance, then pause this harness's dispatcher so each provider
	// removal can be driven to the outcome the test needs.
	dispatchCtx, cancelDispatch := context.WithCancel(context.Background())
	dispatchDone := make(chan struct{})
	go func() { defer close(dispatchDone); h.srv.RunDispatcher(dispatchCtx) }()
	ctx := t.Context()
	for _, m := range []store.TenantMember{
		{Subject: "pam-requester", DisplayName: "Rita Requester", Roles: []string{"operator"}, Source: "test"},
		{Subject: "pam-reviewer-one", DisplayName: "Rev One", Roles: []string{"admin"}, Source: "test"},
		{Subject: "pam-reviewer-two", DisplayName: "Rev Two", Roles: []string{"admin"}, Source: "test"},
	} {
		if _, err := h.srv.orch.UpsertTenantMember(ctx, h.tenant, m); err != nil {
			t.Fatalf("seed member %s: %v", m.Subject, err)
		}
	}
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "review-lead", "access:read", "access:write", "graph:read")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")
	session := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "q1l2-session", map[string]any{
		"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
		"reason": "Q1-L2 retry proof", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 180,
	})
	cancelDispatch()
	<-dispatchDone
	if session.Postgres == nil {
		t.Fatalf("PAM session returned no PostgreSQL credential: %+v", session)
	}
	assertPAMPostgresAccess(t, session.Postgres.DSN, true)

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", lead, "q1l2-generate", map[string]any{
		"name": "pg-main retry", "source": "graph_reachers", "target": "res:pam:postgres:pg-main", "reviewer_subject": "review-bob",
	})
	var generated struct {
		Campaign q1Campaign `json:"campaign"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &generated) != nil || len(generated.Campaign.Items) != 1 {
		t.Fatalf("generate from the database: HTTP %d %s", status, raw)
	}
	campaign, item := generated.Campaign, generated.Campaign.Items[0]
	if item.NHIID != "pam:"+session.ID {
		t.Fatalf("generated item = %+v; want the PAM session", item)
	}
	decision := "/api/v1/access/reviews/" + campaign.ID + "/items/" + item.ItemID + "/decision"
	status, raw = secretsReqKey(t, h, http.MethodPost, decision, bob, "q1l2-revoke", map[string]any{"decision": "revoked", "reason": "no longer needs production reads"})
	if decided := q1ItemFrom(t, status, raw, item.ItemID); decided.RevocationStatus != "requested" {
		t.Fatalf("revoke decision = %+v", decided)
	}

	// failRemoval drives the session's queued provider removal to a terminal
	// failure, so the session reads revocation_failed, and returns the row.
	dispatcher := h.srv.obHandler.(*issuanceDispatcher).secretIntegrations
	removal := func() orchestrator.Record {
		t.Helper()
		if err := h.srv.pam.expireOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		rec, err := h.store.GetPAMSession(context.Background(), h.tenant, session.ID)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, rec.BackendRef)
		if err != nil || lease.RevokeOutboxID == nil {
			t.Fatalf("provider removal not queued: %+v, %v", lease, err)
		}
		row, err := h.srv.outbox.Get(context.Background(), h.tenant, *lease.RevokeOutboxID)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	failRemoval := func() int64 {
		t.Helper()
		row := removal()
		message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, IdempotencyKey: row.IdempotencyKey, Payload: row.Payload, Attempts: 10}
		if handled, err := dispatcher.DeliverTerminalFailure(context.Background(), message, errors.New("provider unavailable")); !handled || err != nil {
			t.Fatalf("terminal provider failure: handled=%t err=%v", handled, err)
		}
		if err := h.srv.pam.expireOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if rec, err := h.store.GetPAMSession(context.Background(), h.tenant, session.ID); err != nil || rec.Status != store.PAMSessionStatusRevocationFailed {
			t.Fatalf("session after a failed provider removal = %+v, %v; want revocation_failed", rec.Status, err)
		}
		return row.ID
	}
	revocationRequests := func() []events.Event {
		t.Helper()
		var out []events.Event
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID == h.tenant && e.Type == "pam.session.revocation_requested" && strings.Contains(string(e.Data), session.ID) {
				out = append(out, e)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	reconcileAt := func(at time.Time) {
		t.Helper()
		actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
		if _, err := h.srv.api.ReconcileNHIReviewRevocations(actorCtx, h.tenant, at); err != nil {
			t.Fatal(err)
		}
	}

	firstRemoval := failRemoval()
	reconcileAt(time.Now().UTC())
	if got := q1GetItem(t, h, bob, campaign.ID, item.ItemID); got.RevocationStatus != "failed" {
		t.Fatalf("item after the session's revocation failed = %+v; want failed", got)
	}
	// Not before the backoff passes...
	reconcileAt(time.Now().UTC().Add(time.Minute))
	if got := q1GetItem(t, h, bob, campaign.ID, item.ItemID); got.RevocationStatus != "failed" || len(revocationRequests()) != 1 {
		t.Fatalf("a retry before the backoff: item %+v, %d PAM requests; want failed and one request", got, len(revocationRequests()))
	}
	// ...and on its own after it, under a key PAM accepts.
	reconcileAt(time.Now().UTC().Add(6 * time.Minute))
	retried := q1GetItem(t, h, bob, campaign.ID, item.ItemID)
	requests := revocationRequests()
	if retried.RevocationStatus != "requested" || !strings.Contains(retried.RevocationDetail, "automatic retry") || len(requests) != 2 {
		t.Fatalf("automatic retry: item %+v, %d PAM requests; want requested by an automatic retry, two requests", retried, len(requests))
	}
	if string(requests[0].Data) == string(requests[1].Data) {
		t.Fatal("the automatic retry repeated the failed request")
	}
	// A second reconcile pass does not retry again while the retry stands.
	reconcileAt(time.Now().UTC().Add(7 * time.Minute))
	if n := len(revocationRequests()); n != 2 {
		t.Fatalf("PAM requests after another pass = %d; want 2", n)
	}

	// That attempt fails too; an operator retries with a reason.
	if second := failRemoval(); second == firstRemoval {
		t.Fatal("the automatic retry queued no new provider removal")
	}
	reconcileAt(time.Now().UTC())
	if got := q1GetItem(t, h, bob, campaign.ID, item.ItemID); got.RevocationStatus != "failed" {
		t.Fatalf("item after the retry failed = %+v; want failed", got)
	}
	retry := "/api/v1/access/reviews/" + campaign.ID + "/items/" + item.ItemID + "/revocation-retry"
	if status, raw := secretsReqKey(t, h, http.MethodPost, retry, bob, "q1l2-retry-no-reason", map[string]any{"reason": "  "}); status != http.StatusBadRequest {
		t.Fatalf("retry without a reason = HTTP %d %s; want 400", status, raw)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, retry, bob, "q1l2-retry", map[string]any{"reason": "provider repaired"})
	operator := q1ItemFrom(t, status, raw, item.ItemID)
	if operator.RevocationStatus != "requested" || !strings.Contains(operator.RevocationDetail, "retried by review-bob (provider repaired)") {
		t.Fatalf("operator retry = %+v", operator)
	}
	if replayStatus, replay := secretsReqKey(t, h, http.MethodPost, retry, bob, "q1l2-retry", map[string]any{"reason": "provider repaired"}); replayStatus != status || string(replay) != string(raw) {
		t.Fatalf("an exact retry did not replay: HTTP %d %s", replayStatus, replay)
	}
	if n := len(revocationRequests()); n != 3 {
		t.Fatalf("PAM requests after the operator retry and its replay = %d; want 3", n)
	}
	if status, raw := secretsReqKey(t, h, http.MethodPost, retry, bob, "q1l2-retry-again", map[string]any{"reason": "again"}); status != http.StatusConflict {
		t.Fatalf("a retry of a revocation that is not failed = HTTP %d %s; want 409", status, raw)
	}

	// The repaired removal completes and the item closes.
	row := removal()
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, IdempotencyKey: row.IdempotencyKey, Payload: row.Payload, Attempts: 1}
	if handled, err := dispatcher.Deliver(context.Background(), message); !handled || err != nil {
		t.Fatalf("dispatch the repaired provider removal: handled=%t err=%v", handled, err)
	}
	if err := h.srv.pam.expireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	reconcileAt(time.Now().UTC())
	closed := q1GetItem(t, h, bob, campaign.ID, item.ItemID)
	if closed.RevocationStatus != "closed" || !strings.Contains(closed.ClosingEvidence, "PAM session revoked") {
		t.Fatalf("item after the repaired removal = %+v; want closed on the session's revocation", closed)
	}
	assertPAMPostgresAccess(t, session.Postgres.DSN, false)
	requests = revocationRequests()
	if len(requests) != 3 || requests[2].Actor == nil || requests[2].Actor.Subject != "review-bob" ||
		requests[1].Actor == nil || requests[1].Actor.Subject != nhiReviewReconcileActor {
		t.Fatalf("PAM requests = %v; want the decision, the reconcile's retry and review-bob's retry", q1EventData(requests))
	}
}
