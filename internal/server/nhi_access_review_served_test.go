// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedNHIAccessReviewCAPGOV02EndToEnd(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	creator := seedScopedTokenSubject(t, h.store, h.tenant, "iga-creator", "access:read", "access:write")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "iga-reviewer", "access:read", "access:write")

	campaignID := "44444444-4444-4444-8444-444444444444"
	item1 := "55555555-5555-4555-8555-555555555555"
	item2 := "66666666-6666-4666-8666-666666666666"
	request := map[string]any{
		"id":               campaignID,
		"name":             "Q3 NHI access certification",
		"scope":            "production-nhi",
		"reviewer_subject": "iga-reviewer",
		"items": []map[string]any{
			{
				"item_id":       item1,
				"nhi_id":        "spiffe://prod/payments/api",
				"nhi_kind":      "spiffe_workload",
				"display_name":  "payments-api workload",
				"owner_ref":     "team:payments",
				"resource":      "postgres://payments-prod",
				"entitlement":   "db:writer",
				"risk":          "high",
				"evidence_refs": []string{"audit:discovery.finding.recorded:payments-api"},
			},
			{
				"item_id":       item2,
				"nhi_id":        "oauth-app:legacy-ci-deployer",
				"nhi_kind":      "oauth_client",
				"display_name":  "legacy CI deployer",
				"owner_ref":     "team:platform",
				"resource":      "github:org/prod-deploy",
				"entitlement":   "repo:admin",
				"risk":          "critical",
				"evidence_refs": []string{"discovery:finding:legacy-ci-deployer"},
			},
		},
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", creator, "cap-gov-02-start", request)
	if status != http.StatusCreated {
		t.Fatalf("start NHI review = %d body %s", status, body)
	}
	var created struct {
		ID              string `json:"id"`
		TenantID        string `json:"tenant_id"`
		ReviewerSubject string `json:"reviewer_subject"`
		RequestedBy     string `json:"requested_by"`
		Status          string `json:"status"`
		ItemCount       int    `json:"item_count"`
		PendingCount    int    `json:"pending_count"`
		Items           []struct {
			ItemID       string   `json:"item_id"`
			NHIID        string   `json:"nhi_id"`
			Resource     string   `json:"resource"`
			Entitlement  string   `json:"entitlement"`
			EvidenceRefs []string `json:"evidence_refs"`
			Status       string   `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode campaign: %v", err)
	}
	if created.ID != campaignID || created.TenantID != h.tenant || created.ReviewerSubject != "iga-reviewer" ||
		created.RequestedBy != "iga-creator" || created.Status != "open" || created.ItemCount != 2 ||
		created.PendingCount != 2 || len(created.Items) != 2 {
		t.Fatalf("bad campaign response: %+v", created)
	}
	if created.Items[0].ItemID != item1 || created.Items[0].NHIID != "spiffe://prod/payments/api" ||
		created.Items[0].Resource != "postgres://payments-prod" || created.Items[0].Entitlement != "db:writer" ||
		len(created.Items[0].EvidenceRefs) != 1 || created.Items[0].Status != "pending" {
		t.Fatalf("bad first item: %+v", created.Items[0])
	}
	if events := nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewCampaignStarted, campaignID); len(events) != 1 {
		t.Fatalf("campaign-start events = %d, want 1", len(events))
	}
	replayStatus, replayBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", creator, "cap-gov-02-start", request)
	if replayStatus != http.StatusCreated || string(replayBody) != string(body) {
		t.Fatalf("start replay status/body changed: %d %s", replayStatus, replayBody)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewCampaignStarted, campaignID); len(events) != 1 {
		t.Fatalf("campaign-start events after replay = %d, want 1", len(events))
	}

	decision1 := map[string]any{
		"decision":               "certified",
		"reviewer_subject":       "iga-reviewer",
		"reason":                 "workload owner confirmed production write access is still required",
		"decision_evidence_refs": []string{"ticket:IGA-1024"},
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item1+"/decision", reviewer, "cap-gov-02-item1", decision1)
	if status != http.StatusOK {
		t.Fatalf("decide first item = %d body %s", status, body)
	}
	replayStatus, replayBody = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item1+"/decision", reviewer, "cap-gov-02-item1", decision1)
	if replayStatus != http.StatusOK || string(replayBody) != string(body) {
		t.Fatalf("decision replay status/body changed: %d %s", replayStatus, replayBody)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewItemDecided, item1); len(events) != 1 {
		t.Fatalf("item1 decision events after replay = %d, want 1", len(events))
	}

	decision2 := map[string]any{
		"decision":               "revoked",
		"reviewer_subject":       "iga-reviewer",
		"reason":                 "legacy deployer no longer has a system owner",
		"decision_evidence_refs": []string{"ticket:IGA-1025", "graph:nhi:legacy-ci-deployer"},
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item2+"/decision", reviewer, "cap-gov-02-item2", decision2)
	if status != http.StatusOK {
		t.Fatalf("decide second item = %d body %s", status, body)
	}
	var completed struct {
		Status         string `json:"status"`
		PendingCount   int    `json:"pending_count"`
		CertifiedCount int    `json:"certified_count"`
		RevokedCount   int    `json:"revoked_count"`
		Items          []struct {
			ItemID               string   `json:"item_id"`
			Status               string   `json:"status"`
			DecisionBy           string   `json:"decision_by"`
			DecisionReason       string   `json:"decision_reason"`
			DecisionEvidenceRefs []string `json:"decision_evidence_refs"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed campaign: %v", err)
	}
	if completed.Status != "completed" || completed.PendingCount != 0 || completed.CertifiedCount != 1 || completed.RevokedCount != 1 {
		t.Fatalf("bad completed counts: %+v", completed)
	}
	projected, err := h.store.GetNHIReviewCampaign(context.Background(), h.tenant, campaignID)
	if err != nil {
		t.Fatalf("load projected campaign: %v", err)
	}
	if projected.Status != "completed" || projected.PendingCount != 0 || projected.CertifiedCount != 1 || projected.RevokedCount != 1 || len(projected.Items) != 2 {
		t.Fatalf("projected campaign = %+v", projected)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/reviews/"+campaignID, creator, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get campaign = %d body %s", status, body)
	}
	if status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/reviews", creator, "", nil); status != http.StatusOK {
		t.Fatalf("list campaigns = %d body %s", status, body)
	}
}

func TestServedNHIAccessReviewReviewerAuthorityBeforeAppend(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	creator := seedScopedTokenSubject(t, h.store, h.tenant, "review-creator", "access:read", "access:write")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "assigned-reviewer", "access:read", "access:write")
	other := seedScopedTokenSubject(t, h.store, h.tenant, "other-writer", "access:read", "access:write")
	const campaignID = "77777777-7777-4777-8777-777777777771"
	const itemID = "77777777-7777-4777-8777-777777777772"
	request := map[string]any{
		"id": campaignID, "name": "reviewer authority fence", "reviewer_subject": "assigned-reviewer",
		"items": []map[string]any{{
			"item_id": itemID, "nhi_id": "spiffe://qa.local/reviewer-fence", "nhi_kind": "workload",
			"resource": "qa-local-postgres", "entitlement": "schema:qa/read",
		}},
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", creator, "reviewer-fence-start", request)
	if status != http.StatusCreated {
		t.Fatalf("start review = %d body %s", status, body)
	}
	var started struct {
		RequestedBy     string `json:"requested_by"`
		ReviewerSubject string `json:"reviewer_subject"`
	}
	if err := json.Unmarshal(body, &started); err != nil || started.RequestedBy != "review-creator" || started.ReviewerSubject != "assigned-reviewer" {
		t.Fatalf("campaign actor binding = %+v err %v", started, err)
	}
	path := "/api/v1/access/reviews/" + campaignID + "/items/" + itemID + "/decision"
	for _, attempt := range []struct {
		name, token string
		body        map[string]any
	}{
		{"creator-spoofs-reviewer", creator, map[string]any{"decision": "certified", "reviewer_subject": "assigned-reviewer"}},
		{"other-writer-omits-reviewer", other, map[string]any{"decision": "certified"}},
		{"reviewer-spoofs-other", reviewer, map[string]any{"decision": "certified", "reviewer_subject": "other-writer"}},
	} {
		status, body := doBearer(t, h.ts, http.MethodPost, path, attempt.token, "reviewer-fence-"+attempt.name, attempt.body)
		if status != http.StatusForbidden {
			t.Fatalf("%s = %d body %s, want 403 before append", attempt.name, status, body)
		}
		if got := len(nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewItemDecided, itemID)); got != 0 {
			t.Fatalf("%s appended %d decision events, want zero", attempt.name, got)
		}
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/reviews/"+campaignID, creator, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("refused decisions changed read state: %d %s", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, path, reviewer, "reviewer-fence-valid", map[string]any{
		"decision": "certified", "reason": "assigned reviewer checked the QA entitlement",
	})
	if status != http.StatusOK || !strings.Contains(string(body), `"decision_by":"assigned-reviewer"`) {
		t.Fatalf("assigned reviewer decision = %d body %s", status, body)
	}
	if got := len(nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewItemDecided, itemID)); got != 1 {
		t.Fatalf("valid decision events = %d, want one", got)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, path, reviewer, "reviewer-fence-second", map[string]any{"decision": "revoked", "reason": "late decision"})
	if status != http.StatusConflict {
		t.Fatalf("second decision = %d body %s, want 409", status, body)
	}
	if got := len(nhiReviewEvents(t, h.log, projections.EventNHIAccessReviewItemDecided, itemID)); got != 1 {
		t.Fatalf("second decision appended %d events, want one", got)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", creator, "reviewer-fence-self-assigned", map[string]any{
		"name": "self assigned review", "reviewer_subject": "review-creator",
		"items": request["items"],
	})
	if status != http.StatusBadRequest {
		t.Fatalf("self-assigned campaign = %d body %s, want 400", status, body)
	}
}

func nhiReviewEvents(t *testing.T, log *events.Log, typ, needle string) []events.Event {
	t.Helper()
	var out []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == typ && (needle == "" || strings.Contains(string(e.Data), needle)) {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	return out
}
