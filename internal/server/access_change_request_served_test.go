package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedAccessChangeRequestCAPGOV05EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	requesterTok := seedScopedTokenSubject(t, h.store, h.tenant, "platform-dev@example.test", "access:read", "access:write")
	approverTok := seedScopedTokenSubject(t, h.store, h.tenant, "security-reviewer@example.test", "access:read", "access:write")
	cabTok := seedScopedTokenSubject(t, h.store, h.tenant, "cab@example.test", "access:read", "access:write")

	requestID := "77777777-7777-4777-8777-777777777777"
	create := map[string]any{
		"id":                 requestID,
		"requested_action":   "grant",
		"nhi_id":             "github-app:prod-deployer",
		"nhi_kind":           "oauth_app",
		"display_name":       "prod deployer GitHub App",
		"owner_ref":          "team:platform",
		"resource":           "github:org/prod-infra",
		"entitlement":        "repo:contents:write",
		"change_ref":         "github:trstctl/prod-infra#4821",
		"change_url":         "https://github.com/trstctl/prod-infra/pull/4821",
		"risk":               "high",
		"reason":             "new deploy automation needs scoped repository write access",
		"evidence_refs":      []string{"pull:4821/checks", "ticket:CAB-4821"},
		"required_approvals": 2,
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests", requesterTok, "cap-gov-05-create", create)
	if status != http.StatusCreated {
		t.Fatalf("create access request = %d body %s", status, body)
	}
	var created struct {
		ID                string   `json:"id"`
		TenantID          string   `json:"tenant_id"`
		RequestedAction   string   `json:"requested_action"`
		RequesterSubject  string   `json:"requester_subject"`
		ChangeSystem      string   `json:"change_system"`
		Status            string   `json:"status"`
		ApprovalCount     int      `json:"approval_count"`
		RequiredApprovals int      `json:"required_approvals"`
		EvidenceRefs      []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created access request: %v", err)
	}
	if created.ID != requestID || created.TenantID != h.tenant || created.RequestedAction != "grant" ||
		created.RequesterSubject != "platform-dev@example.test" || created.ChangeSystem != "github" ||
		created.Status != "pending" || created.ApprovalCount != 0 || created.RequiredApprovals != 2 ||
		len(created.EvidenceRefs) != 2 {
		t.Fatalf("bad created access request: %+v", created)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventAccessChangeRequestCreated, requestID); len(events) != 1 {
		t.Fatalf("access request create events = %d, want 1", len(events))
	}
	replayStatus, replayBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests", requesterTok, "cap-gov-05-create", create)
	if replayStatus != http.StatusCreated || string(replayBody) != string(body) {
		t.Fatalf("create replay status/body changed: %d %s", replayStatus, replayBody)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventAccessChangeRequestCreated, requestID); len(events) != 1 {
		t.Fatalf("access request create events after replay = %d, want 1", len(events))
	}

	selfDecision := map[string]any{
		"decision": "approved",
		"reason":   "self approval must fail",
	}
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests/"+requestID+"/decisions", requesterTok, "cap-gov-05-self", selfDecision); status != http.StatusBadRequest {
		t.Fatalf("self decision status = %d body %s", status, body)
	}

	firstDecision := map[string]any{
		"decision":               "approved",
		"reason":                 "PR limits the app to repository contents write",
		"decision_evidence_refs": []string{"github-review:security-reviewer", "ci:4821/policy"},
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests/"+requestID+"/decisions", approverTok, "cap-gov-05-approve-1", firstDecision)
	if status != http.StatusOK {
		t.Fatalf("first decision = %d body %s", status, body)
	}
	var first struct {
		Status            string `json:"status"`
		ApprovalCount     int    `json:"approval_count"`
		RequiredApprovals int    `json:"required_approvals"`
		Decisions         []struct {
			ApproverSubject string   `json:"approver_subject"`
			Decision        string   `json:"decision"`
			EvidenceRefs    []string `json:"decision_evidence_refs"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatalf("decode first decision: %v", err)
	}
	if first.Status != "pending" || first.ApprovalCount != 1 || first.RequiredApprovals != 2 ||
		len(first.Decisions) != 1 || first.Decisions[0].ApproverSubject != "security-reviewer@example.test" ||
		first.Decisions[0].Decision != "approved" || len(first.Decisions[0].EvidenceRefs) != 2 {
		t.Fatalf("bad first decision response: %+v", first)
	}
	replayStatus, replayBody = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests/"+requestID+"/decisions", approverTok, "cap-gov-05-approve-1", firstDecision)
	if replayStatus != http.StatusOK || string(replayBody) != string(body) {
		t.Fatalf("decision replay status/body changed: %d %s", replayStatus, replayBody)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventAccessChangeRequestDecided, "security-reviewer@example.test"); len(events) != 1 {
		t.Fatalf("first decision events after replay = %d, want 1", len(events))
	}

	secondDecision := map[string]any{
		"decision":               "approved",
		"reason":                 "CAB approved the production entitlement change",
		"decision_evidence_refs": []string{"ticket:CAB-4821/approved"},
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/requests/"+requestID+"/decisions", cabTok, "cap-gov-05-approve-2", secondDecision)
	if status != http.StatusOK {
		t.Fatalf("second decision = %d body %s", status, body)
	}
	var approved struct {
		Status        string `json:"status"`
		ApprovalCount int    `json:"approval_count"`
		CompletedAt   string `json:"completed_at"`
		Decisions     []struct {
			ApproverSubject string `json:"approver_subject"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(body, &approved); err != nil {
		t.Fatalf("decode approved request: %v", err)
	}
	if approved.Status != "approved" || approved.ApprovalCount != 2 || approved.CompletedAt == "" || len(approved.Decisions) != 2 {
		t.Fatalf("bad approved response: %+v", approved)
	}

	if status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/requests/"+requestID, approverTok, "", nil); status != http.StatusOK {
		t.Fatalf("get access request = %d body %s", status, body)
	}
	if status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/requests", approverTok, "", nil); status != http.StatusOK {
		t.Fatalf("list access requests = %d body %s", status, body)
	}
	if events := nhiReviewEvents(t, h.log, projections.EventAccessChangeRequestDecided, requestID); len(events) != 2 {
		t.Fatalf("decision events = %d, want 2", len(events))
	}
}
