// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type q1Item struct {
	ItemID           string     `json:"item_id"`
	NHIID            string     `json:"nhi_id"`
	NHIKind          string     `json:"nhi_kind"`
	OwnerRef         string     `json:"owner_ref"`
	Resource         string     `json:"resource"`
	Entitlement      string     `json:"entitlement"`
	EvidenceRefs     []string   `json:"evidence_refs"`
	Status           string     `json:"status"`
	DecisionBy       string     `json:"decision_by"`
	RevocationStatus string     `json:"revocation_status"`
	ClosingEvidence  string     `json:"closing_evidence"`
	ClosedAt         *time.Time `json:"closed_at"`
	NextReviewAt     *time.Time `json:"next_review_at"`
}

type q1Campaign struct {
	ID    string   `json:"id"`
	Scope string   `json:"scope"`
	Items []q1Item `json:"items"`
}

// Q1: an access review acts. A campaign generated from "credentials that reach
// this database" lists the PAM session that reaches it; revoking it drops the
// session's database role exactly once (an exact retry replays, a second
// decision is refused and the reconcile never revokes again), PostgreSQL then
// refuses the login, the revocation names the reviewer, and the item closes
// only once the session reads revoked. A keep decision on a stale owner's
// credential renews that owner's attestation as the reviewer and sets the next
// review date, changing no right upstream.
func TestServedAccessReviewThatActsQ1(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 10*time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute,
			ExpiryInterval: 10 * time.Millisecond,
			Attestors:      []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{
				TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"},
			}},
		}
	})
	startServedExternalCADispatcher(t, h)
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
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "review-lead", "access:read", "access:write", "graph:read",
		"owners:read", "owners:write", "identities:read", "identities:write")
	noGraph := seedScopedTokenSubject(t, h.store, h.tenant, "review-clerk", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "review-bob", "access:read", "access:write")

	session := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "q1-session", map[string]any{
		"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
		"reason": "Q1 access review proof", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 300,
	})
	if session.Postgres == nil {
		t.Fatalf("PAM session returned no PostgreSQL credential: %+v", session)
	}
	assertPAMPostgresAccess(t, session.Postgres.DSN, true)

	// A campaign generated from "credentials that reach this database".
	generate := map[string]any{
		"name": "pg-main access", "source": "graph_reachers", "target": "res:pam:postgres:pg-main", "reviewer_subject": "review-bob",
	}
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", noGraph, "q1-no-graph", generate); status != http.StatusForbidden {
		t.Fatalf("a principal without graph:read generated a graph review: HTTP %d %s", status, raw)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", lead, "q1-generate", generate)
	var generated struct {
		Campaign q1Campaign `json:"campaign"`
		Coverage struct {
			Note string `json:"note"`
		} `json:"coverage"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &generated) != nil || len(generated.Campaign.Items) != 1 ||
		generated.Coverage.Note == "" {
		t.Fatalf("generate from the database: HTTP %d %s", status, raw)
	}
	campaign := generated.Campaign
	item := campaign.Items[0]
	for _, want := range []string{"graph:holder:person:pam-requester", "graph:approver:person:pam-reviewer-one", "graph:approver:person:pam-reviewer-two"} {
		if !slices.Contains(item.EvidenceRefs, want) {
			t.Fatalf("item evidence %v lacks %s", item.EvidenceRefs, want)
		}
	}
	if item.NHIID != "pam:"+session.ID || item.NHIKind != "pam_session" || item.Resource != "res:pam:postgres:pg-main" || item.Status != "pending" {
		t.Fatalf("generated item = %+v", item)
	}

	// The revoke decision acts once.
	decision := "/api/v1/access/reviews/" + campaign.ID + "/items/" + item.ItemID + "/decision"
	revoke := map[string]any{"decision": "revoked", "reason": "no longer needs production reads"}
	status, raw = secretsReqKey(t, h, http.MethodPost, decision, bob, "q1-revoke", revoke)
	decided := q1ItemFrom(t, status, raw, item.ItemID)
	if decided.Status != "revoked" || decided.DecisionBy != "review-bob" || decided.RevocationStatus != "requested" || decided.ClosedAt != nil {
		t.Fatalf("revoke decision = %+v", decided)
	}
	if replayStatus, replay := secretsReqKey(t, h, http.MethodPost, decision, bob, "q1-revoke", revoke); replayStatus != status || string(replay) != string(raw) {
		t.Fatalf("an exact retry did not replay the decision: HTTP %d %s", replayStatus, replay)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, decision, bob, "q1-revoke-again", revoke); status != http.StatusConflict {
		t.Fatalf("a second revoke decision returned HTTP %d, want 409", status)
	}
	// The request alone never closes the item.
	if err := h.srv.ReconcileNHIReviewsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := q1GetItem(t, h, bob, campaign.ID, item.ItemID); got.RevocationStatus != "requested" || got.ClosedAt != nil {
		t.Fatalf("the item closed before the session was revoked: %+v", got)
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); h.srv.RunPAMSessionExpiry(workerCtx) }()
	defer func() { cancel(); <-workerDone }()
	var closed q1Item
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if err := h.srv.ReconcileNHIReviewsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if closed = q1GetItem(t, h, bob, campaign.ID, item.ItemID); closed.RevocationStatus == "closed" {
			break
		}
	}
	if closed.RevocationStatus != "closed" || closed.ClosedAt == nil || !strings.Contains(closed.ClosingEvidence, "PAM session revoked") {
		t.Fatalf("the item did not close on the session's revocation: %+v", closed)
	}
	// PostgreSQL refuses the reviewed login.
	assertPAMPostgresAccess(t, session.Postgres.DSN, false)
	if err := h.srv.ReconcileNHIReviewsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// Exactly once, naming the reviewer.
	var requested []events.Event
	closings := 0
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		switch {
		case e.TenantID != h.tenant:
		case e.Type == "pam.session.revocation_requested" && strings.Contains(string(e.Data), session.ID):
			requested = append(requested, e)
		case e.Type == "nhi.access_review.item.closed":
			closings++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(requested) != 1 || !strings.Contains(string(requested[0].Data), `"requested_by":"review-bob"`) ||
		requested[0].Actor == nil || requested[0].Actor.Subject != "review-bob" {
		t.Fatalf("PAM revocation requests = %d, want exactly one naming review-bob (%v)", len(requested), q1EventData(requested))
	}
	if closings != 1 {
		t.Fatalf("item closed %d times, want once", closings)
	}

	// Keep: a stale owner's credential renews the owner's attestation.
	stale := servedCreateID(t, h, lead, "q1-stale-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "ledger", "application_id": "ledger", "environment": "prod",
	})
	fresh := servedCreateID(t, h, lead, "q1-fresh-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "billing", "application_id": "billing", "environment": "prod",
	})
	ledgerID := servedCreateID(t, h, lead, "q1-ledger-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "ledger.example.test", "owner_id": stale,
	})
	ledgerAPIID := servedCreateID(t, h, lead, "q1-ledger-api-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "api.ledger.example.test", "owner_id": stale,
	})
	servedCreateID(t, h, lead, "q1-billing-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "billing.example.test", "owner_id": fresh,
	})
	if _, err := h.srv.orch.AttestOwnership(ctx, h.tenant, fresh, "owner-of-billing"); err != nil {
		t.Fatal(err)
	}
	// Q1-L5: an owner with no application or environment can never be
	// attested; the stale review surfaces its credentials instead of
	// skipping them, so a campaign is where it gets completed.
	unfinished := servedCreateID(t, h, lead, "q1-unfinished-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "reports"})
	reportsID := servedCreateID(t, h, lead, "q1-reports-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "reports.example.test", "owner_id": unfinished,
	})
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", noGraph, "q1-stale", map[string]any{
		"name": "stale owners", "source": "stale_owner_attestation", "reviewer_subject": "review-bob",
	})
	if status != http.StatusCreated || json.Unmarshal(raw, &generated) != nil {
		t.Fatalf("generate from stale owner attestations: HTTP %d %s", status, raw)
	}
	var keepItem q1Item
	for _, candidate := range generated.Campaign.Items {
		if candidate.OwnerRef == "wl:"+fresh {
			t.Fatalf("a freshly attested owner's credential is in the stale review: %+v", candidate)
		}
		if candidate.NHIID == "id:"+ledgerID {
			keepItem = candidate
		}
	}
	if keepItem.OwnerRef != "wl:"+stale {
		t.Fatalf("stale owner items = %+v, want the ledger identity owned by %s", generated.Campaign.Items, stale)
	}
	var unfinishedItem q1Item
	for _, candidate := range generated.Campaign.Items {
		if candidate.NHIID == "id:"+reportsID {
			unfinishedItem = candidate
		}
	}
	if unfinishedItem.OwnerRef != "wl:"+unfinished || !strings.Contains(unfinishedItem.Entitlement, "ownership incomplete") {
		t.Fatalf("an owner without an application or environment is not in the stale review: %+v", generated.Campaign.Items)
	}
	keepPath := "/api/v1/access/reviews/" + generated.Campaign.ID + "/items/" + keepItem.ItemID + "/decision"
	status, raw = secretsReqKey(t, h, http.MethodPost, keepPath, bob, "q1-keep", map[string]any{"decision": "certified", "next_review_days": 30})
	kept := q1ItemFrom(t, status, raw, keepItem.ItemID)
	if kept.Status != "certified" || kept.NextReviewAt == nil || kept.RevocationStatus != "" ||
		kept.NextReviewAt.Sub(time.Now().AddDate(0, 0, 30)).Abs() > time.Hour {
		t.Fatalf("keep decision = %+v, want certified with a next review in 30 days", kept)
	}
	owner, err := h.store.GetOwner(ctx, h.tenant, stale)
	if err != nil || owner.OwnershipVerifiedAt == nil || owner.OwnershipVerifiedBy != "review-bob" ||
		time.Since(*owner.OwnershipVerifiedAt) > time.Minute {
		t.Fatalf("the keep decision did not renew the owner's attestation as the reviewer: %+v (%v)", owner, err)
	}
	// Q1-L6: the same owner's second kept credential in this campaign does
	// not attest it again; one campaign attests an owner once.
	var secondItem q1Item
	for _, candidate := range generated.Campaign.Items {
		if candidate.NHIID == "id:"+ledgerAPIID {
			secondItem = candidate
		}
	}
	if secondItem.ItemID == "" {
		t.Fatalf("the owner's second credential is not in the stale review: %+v", generated.Campaign.Items)
	}
	secondPath := "/api/v1/access/reviews/" + generated.Campaign.ID + "/items/" + secondItem.ItemID + "/decision"
	status, raw = secretsReqKey(t, h, http.MethodPost, secondPath, bob, "q1-keep-second", map[string]any{"decision": "certified", "next_review_days": 30})
	if second := q1ItemFrom(t, status, raw, secondItem.ItemID); second.Status != "certified" {
		t.Fatalf("second keep = %+v", second)
	}
	attestations := 0
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == projections.EventOwnershipAttested && strings.Contains(string(e.Data), stale) {
			attestations++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attestations != 1 {
		t.Fatalf("one campaign attested owner %s %d times, want once", stale, attestations)
	}

	// A keep whose owner cannot be attested is refused before anything is recorded.
	incomplete := servedCreateID(t, h, lead, "q1-incomplete-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "scratch"})
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews", lead, "q1-manual", map[string]any{
		"name": "hand-made", "reviewer_subject": "review-bob", "items": []map[string]any{{
			"nhi_id": "id:" + ledgerID, "nhi_kind": "x509_certificate", "owner_ref": "wl:" + incomplete,
			"resource": "owner scratch", "entitlement": "ownership",
		}},
	})
	var manual q1Campaign
	if status != http.StatusCreated || json.Unmarshal(raw, &manual) != nil || len(manual.Items) != 1 {
		t.Fatalf("hand-made campaign: HTTP %d %s", status, raw)
	}
	refusedPath := "/api/v1/access/reviews/" + manual.ID + "/items/" + manual.Items[0].ItemID + "/decision"
	if status, raw := secretsReqKey(t, h, http.MethodPost, refusedPath, bob, "q1-keep-incomplete", map[string]any{"decision": "certified"}); status != http.StatusConflict {
		t.Fatalf("keep on an incomplete owner returned HTTP %d %s, want 409", status, raw)
	}
	if got := q1GetItem(t, h, bob, manual.ID, manual.Items[0].ItemID); got.Status != "pending" {
		t.Fatalf("a refused keep left the item %s", got.Status)
	}
}

func q1ItemFrom(t *testing.T, status int, raw []byte, itemID string) q1Item {
	t.Helper()
	var campaign q1Campaign
	if status != http.StatusOK || json.Unmarshal(raw, &campaign) != nil {
		t.Fatalf("decision: HTTP %d %s", status, raw)
	}
	for _, item := range campaign.Items {
		if item.ItemID == itemID {
			return item
		}
	}
	t.Fatalf("item %s missing from %s", itemID, raw)
	return q1Item{}
}

func q1GetItem(t *testing.T, h *servedHarness, token, campaignID, itemID string) q1Item {
	t.Helper()
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/access/reviews/"+campaignID, token, nil)
	return q1ItemFrom(t, status, raw, itemID)
}

func q1EventData(evs []events.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, string(e.Data))
	}
	return out
}
