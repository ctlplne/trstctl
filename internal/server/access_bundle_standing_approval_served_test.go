// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/cli"
)

type servedBundleStandingApproval struct {
	ID             string     `json:"id"`
	BundleID       string     `json:"bundle_id"`
	Status         string     `json:"status"`
	Approvals      int64      `json:"approvals"`
	LastApprovedAt *time.Time `json:"last_approved_at"`
	RevokeReason   string     `json:"revoke_reason"`
}

// TestServedBundleStandingApprovalOpensAgentSessionsOD9: an administrator who
// may approve access grants an agent's access bundle a standing approval for
// its one delegated account (OD-9). The agent launcher, run with the bundle's
// run token and no reviewer anywhere, gets its session approved by the
// standing approval, opened through the gateway, and the agent completes its
// task. The approval stands in for reviewers only for the bundle's runs, for
// that account and role: an operator asking for the same account still waits
// for reviewers. Revoking it ends the live session it approved, refuses a
// request it approved that was not opened yet, and the run's next request
// waits for reviewers. Granting needs access:approve, an account the bundle
// delegates, an expiry within 90 days, and a grantor the bundle is not
// granted to.
func TestServedBundleStandingApprovalOpensAgentSessionsOD9(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h
	const agent = "agent-9"
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "od9-admin", "access:read", "access:write", "access:bundle.run")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "od9-approver", "access:read", "access:write", "access:approve")

	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles", admin, "od9-bundle", map[string]any{
		"name": "od9-report-agent", "permissions": []string{"access:sessions.open"}, "max_run_ttl_seconds": 3600,
		"access_targets": []map[string]any{{"target_type": "postgres", "target_id": "pg-gw", "roles": []string{"readonly"}}},
	})
	var bundle struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &bundle) != nil || bundle.ID == "" {
		t.Fatalf("create the bundle = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "od9-grant",
		map[string]any{"principal_type": "machine", "principal": agent}); status != http.StatusCreated {
		t.Fatalf("grant the bundle = %d %s", status, body)
	}
	standingPath := "/api/v1/access/bundles/" + bundle.ID + "/standing-approvals"
	grantBody := func(change map[string]any) map[string]any {
		out := map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
			"reason": "the nightly report agent", "expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}
		for k, v := range change {
			out[k] = v
		}
		return out
	}

	// Nothing is approved in advance by default.
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, standingPath, admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"items":[]`) {
		t.Fatalf("a new bundle's standing approvals = %d %s", status, body)
	}
	// Refused grants change nothing.
	for name, tc := range map[string]struct {
		token  string
		body   map[string]any
		status int
		want   string
	}{
		"without access:approve":  {admin, grantBody(nil), http.StatusForbidden, "needs access:approve"},
		"an undelegated role":     {approver, grantBody(map[string]any{"role": "superuser"}), http.StatusUnprocessableEntity, "is not among the accounts this bundle delegates"},
		"an undelegated account":  {approver, grantBody(map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user"}), http.StatusUnprocessableEntity, "is not among the accounts this bundle delegates"},
		"more than 90 days":       {approver, grantBody(map[string]any{"expires_at": time.Now().Add(91 * 24 * time.Hour).UTC().Format(time.RFC3339)}), http.StatusUnprocessableEntity, "90 days"},
		"an expiry in the past":   {approver, grantBody(map[string]any{"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}), http.StatusUnprocessableEntity, "five minutes"},
		"no reason":               {approver, grantBody(map[string]any{"reason": "  "}), http.StatusBadRequest, "reason is required"},
		"an unknown bundle's":     {approver, grantBody(nil), http.StatusNotFound, "not found"},
		"by a grantee (rejected)": {"", nil, 0, ""},
	} {
		if tc.token == "" {
			continue
		}
		path := standingPath
		if name == "an unknown bundle's" {
			path = "/api/v1/access/bundles/" + uuid.NewString() + "/standing-approvals"
		}
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, tc.token, "od9-refused-"+name, tc.body); status != tc.status || !strings.Contains(string(body), tc.want) {
			t.Fatalf("a standing approval %s = %d %s; want %d naming %q", name, status, body, tc.status, tc.want)
		}
	}
	// Nobody approves their own sessions in advance: while the bundle is
	// granted to the approver, the approver cannot grant one.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "od9-self-grant",
		map[string]any{"principal_type": "machine", "principal": "od9-approver"})
	var selfGrant struct {
		Grant struct {
			ID string `json:"id"`
		} `json:"grant"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &selfGrant) != nil || selfGrant.Grant.ID == "" {
		t.Fatalf("grant the bundle to the approver = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, standingPath, approver, "od9-refused-self", grantBody(nil)); status != http.StatusForbidden ||
		!strings.Contains(string(body), "granted to you") {
		t.Fatalf("a standing approval by a grantee of the bundle = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodDelete, "/api/v1/access/bundles/"+bundle.ID+"/grants/"+selfGrant.Grant.ID+"?reason=separation",
		admin, "od9-self-ungrant", nil); status != http.StatusOK {
		t.Fatalf("remove the approver's grant = %d %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, standingPath, admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"items":[]`) {
		t.Fatalf("refused grants left approvals: %d %s", status, body)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, standingPath, approver, "od9-standing", grantBody(nil))
	var standing servedBundleStandingApproval
	if status != http.StatusCreated || json.Unmarshal(body, &standing) != nil || standing.Status != "active" || standing.Approvals != 0 || standing.BundleID != bundle.ID {
		t.Fatalf("grant the standing approval = %d %s", status, body)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/runs", admin, "od9-run",
		map[string]any{"principal": agent, "bundle_ids": []string{bundle.ID}, "ttl_seconds": 1800, "label": "nightly report"})
	var run struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
		Token string `json:"token"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.Token == "" {
		t.Fatalf("mint the agent's run = %d %s", status, body)
	}

	// No reviewer runs anywhere in this test: the launcher's session is
	// approved by the standing approval alone.
	payload := filepath.Join(f.dir, "od9-attestation")
	if err := os.WriteFile(payload, []byte("genuine"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "od9-agent")
	t.Setenv("A257_AGENT_OUT", out)
	var transcript lockedBuffer
	exited := make(chan int, 1)
	go func() {
		exited <- cli.Run(f.ctx, []string{"access", "agent", "--account", "postgres/pg-gw:readonly", "--reason", "nightly report", "--method", "stub_pam",
			"--payload-file", payload, "--ttl", "60s", "--approval-wait", "20s", "--", os.Args[0], "-test.run=^TestA257AgentProcessHelper$"},
			cli.Env{Server: f.api.URL, Token: run.Token, Tenant: h.tenant, HTTPClient: f.api.Client()}, strings.NewReader(""), &transcript, &transcript)
	}()
	a201Await(t, "the agent completes its task under the standing approval", func() bool {
		select {
		case code := <-exited:
			t.Fatalf("the launcher exited %d: %s (gateway: %s)", code, transcript.String(), f.gatewayLog.String())
		default:
		}
		return strings.Contains(transcript.String(), "agent: holding a connection")
	})
	if !strings.Contains(transcript.String(), "agent: task done, pam_smoke rows=1") {
		t.Fatalf("the agent's task = %s", transcript.String())
	}
	m := a257OpenedSession.FindStringSubmatch(transcript.String())
	if m == nil {
		t.Fatalf("no session in the transcript: %s", transcript.String())
	}
	sessionID := m[1]
	read := f.sessionRead(sessionID)
	if read["requested_by"] != "bundle-run:"+agent || read["delivery"] != "gateway" {
		t.Fatalf("the agent's session = %v", read)
	}
	// The request had one approval, the standing approval's, and its
	// evidence names the approval.
	rec, err := h.store.GetPAMSession(f.ctx, h.tenant, sessionID)
	if err != nil || rec.ApprovalRequestID == "" {
		t.Fatalf("the session's approval link = %+v, %v", rec, err)
	}
	approval, err := h.store.GetOperationApproval(f.ctx, h.tenant, rec.ApprovalRequestID)
	if err != nil || approval.RequiredApprovals != 1 || approval.ApprovalCount != 1 ||
		!slices.Contains(approval.EvidenceRefs, "pam-standing-approval:"+standing.ID) {
		t.Fatalf("the session's approval = %+v, %v", approval, err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, standingPath, admin, nil)
	var listed struct {
		Items []servedBundleStandingApproval `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 1 || listed.Items[0].Approvals != 1 || listed.Items[0].LastApprovedAt == nil {
		t.Fatalf("the standing approval after one session = %d %s", status, body)
	}

	// It stands in for reviewers only for the bundle's runs: an operator
	// asking for the same account waits for reviewers.
	operatorRequest := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
		"reason": "operator check", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", admin, "od9-operator-request", operatorRequest)
	if status != http.StatusAccepted || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("an operator's request under the standing approval = %d %s; want pending", status, body)
	}
	// A request the standing approval approved but that is not opened yet.
	unopened := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
		"reason": "second report", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", run.Token, "od9-unopened-request", unopened)
	var pending struct {
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		Status            string `json:"status"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &pending) != nil || pending.Status != "approved" {
		t.Fatalf("the run's second request = %d %s; want approved", status, body)
	}

	// Revoking it ends the live session it approved.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, standingPath+"/"+standing.ID+"/revoke", approver, "od9-revoke",
		map[string]any{"reason": "the report agent is retired"})
	var revoked struct {
		Approval      servedBundleStandingApproval `json:"approval"`
		EndedSessions []struct {
			ID string `json:"id"`
		} `json:"ended_sessions"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &revoked) != nil || revoked.Approval.Status != "revoked" ||
		revoked.Approval.RevokeReason != "the report agent is retired" || len(revoked.EndedSessions) != 1 || revoked.EndedSessions[0].ID != sessionID {
		t.Fatalf("revoke the standing approval = %d %s", status, body)
	}
	select {
	case code := <-exited:
		if code != 3 || !strings.Contains(transcript.String(), "agent: held connection ended=true") {
			t.Fatalf("the agent ended with %d: %s", code, transcript.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the agent's held connection outlived the revocation: %s", transcript.String())
	}
	a201Await(t, "the gateway acknowledges ending the session", func() bool {
		end, _ := f.sessionRead(sessionID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	// The request it approved and that was not opened is refused.
	unopened["approval_request_id"], unopened["intent_digest"] = pending.ApprovalRequestID, pending.IntentDigest
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", run.Token, "od9-unopened-open", unopened); status != http.StatusForbidden ||
		!strings.Contains(string(body), "standing approval that approved this request was revoked") {
		t.Fatalf("opening a request the revoked approval approved = %d %s", status, body)
	}
	// The run's next request waits for reviewers.
	next := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
		"reason": "after revocation", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", run.Token, "od9-after-revoke", next); status != http.StatusAccepted ||
		!strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("the run's request after revocation = %d %s; want pending", status, body)
	}
	// Revoking again is a no-op that ends nothing.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, standingPath+"/"+standing.ID+"/revoke", approver, "od9-revoke-again",
		map[string]any{"reason": "again"}); status != http.StatusOK || !strings.Contains(string(body), `"ended_sessions":[]`) ||
		!strings.Contains(string(body), "the report agent is retired") {
		t.Fatalf("revoking again = %d %s", status, body)
	}

	// The bundle's activity records the grant, the use by the run and the
	// revocation.
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/activity?bundle="+bundle.ID+"&limit=50", admin, nil)
	var activity struct {
		Items []struct {
			Action    string `json:"action"`
			RunID     string `json:"run_id"`
			Principal string `json:"principal"`
			Actor     string `json:"actor"`
			Detail    string `json:"detail"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &activity) != nil {
		t.Fatalf("bundle activity = %d %s", status, body)
	}
	seen := map[string]bool{}
	for _, item := range activity.Items {
		switch item.Action {
		case "standing_approval_granted":
			seen[item.Action] = item.Actor == "od9-approver" && strings.HasPrefix(item.Detail, "postgres/pg-gw as readonly until ")
		case "standing_approval_used":
			seen[item.Action] = seen[item.Action] || (item.RunID == run.Run.ID && item.Principal == agent && item.Actor == "standing-approval:"+standing.ID)
		case "standing_approval_revoked":
			seen[item.Action] = item.Actor == "od9-approver" && strings.Contains(item.Detail, "the report agent is retired")
		}
	}
	for _, action := range []string{"standing_approval_granted", "standing_approval_used", "standing_approval_revoked"} {
		if !seen[action] {
			t.Fatalf("bundle activity has no %s as recorded: %s", action, body)
		}
	}
}
