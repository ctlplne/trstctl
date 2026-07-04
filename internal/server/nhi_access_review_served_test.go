// SPDX-License-Identifier: MPL-2.0

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
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "iga-reviewer", "access:read", "access:write")

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
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", tok, "cap-gov-02-start", request)
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
		created.RequestedBy != "iga-reviewer" || created.Status != "open" || created.ItemCount != 2 ||
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
	replayStatus, replayBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews", tok, "cap-gov-02-start", request)
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
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item1+"/decision", tok, "cap-gov-02-item1", decision1)
	if status != http.StatusOK {
		t.Fatalf("decide first item = %d body %s", status, body)
	}
	replayStatus, replayBody = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item1+"/decision", tok, "cap-gov-02-item1", decision1)
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
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/reviews/"+campaignID+"/items/"+item2+"/decision", tok, "cap-gov-02-item2", decision2)
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

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/reviews/"+campaignID, tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get campaign = %d body %s", status, body)
	}
	if status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/reviews", tok, "", nil); status != http.StatusOK {
		t.Fatalf("list campaigns = %d body %s", status, body)
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
