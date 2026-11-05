// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// a258Session is an opened session with its start, for its length.
type a258Session struct {
	servedPAMSessionResponse
	StartedAt time.Time `json:"started_at"`
}

// TestServedTemplatesAndEmergencyAccessA258: an access template's reason is
// recorded, its approvals raise the quorum and its length bounds the session.
// A named responder opens emergency access at once through the gateway; every
// approver is notified on the approval channels; the session ends at its
// short deadline; its post-incident review stays pending until someone other
// than the responder, holding access:approve, closes it. Nobody else can open
// emergency access, the normal open does not skip review, and the responder
// cannot review their own grant.
func TestServedTemplatesAndEmergencyAccessA258(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a258-admin", "access:read", "access:write", "access:targets.write")
	reviewerThree := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-three", "access:approve")
	responder := seedScopedTokenSubject(t, h.store, h.tenant, "oncall@ops.example", "access:read", "access:sessions.open")
	attestation := base64.StdEncoding.EncodeToString([]byte("genuine"))

	// A template below the deployment's quorum is refused; a valid one saved.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", admin, "a258-template-weak", map[string]any{
		"name": "too-weak", "reason": "anything", "required_approvals": 1, "max_ttl_seconds": 120}); status == http.StatusCreated {
		t.Fatal("a template below the deployment's quorum was saved")
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", admin, "a258-template", map[string]any{
		"name": "db-incident", "reason": "Incident database triage", "required_approvals": 3, "max_ttl_seconds": 60})
	var template struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.ID == "" {
		t.Fatalf("save the template = %d %s", status, body)
	}

	// A request naming it: the template's reason, a quorum of three, and a
	// session no longer than its maximum.
	request := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
		"reason": "INC-42", "method": "stub_pam", "payload_base64": attestation, "ttl_seconds": 600, "template_id": template.ID}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a258-template-request", request)
	var pending struct {
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &pending) != nil || pending.RequiredApprovals != 3 {
		t.Fatalf("templated request = %d %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/approval-requests?status=pending", f.reviewerOne, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "Incident database triage: INC-42") || !strings.Contains(string(body), "pam-template:db-incident@1") {
		t.Fatalf("the reviewers do not see the template's reason and name: %s", body)
	}
	request["approval_request_id"], request["intent_digest"] = pending.ApprovalRequestID, pending.IntentDigest
	for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo, reviewerThree} {
		if i == 2 {
			if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester, "a258-early-open", request); status == http.StatusCreated {
				t.Fatal("a templated session opened with two of its three approvals")
			}
		}
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewer,
			"a258-template-review-"+string(rune('a'+i)), map[string]any{"intent_digest": pending.IntentDigest}); status != http.StatusOK {
			t.Fatalf("approval %d = %d %s", i+1, status, body)
		}
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester, "a258-template-open", request)
	var templated a258Session
	if status != http.StatusCreated || json.Unmarshal(body, &templated) != nil {
		t.Fatalf("templated open = %d %s", status, body)
	}
	// Asked for 600 s under a deployment maximum of 180 s, the session gets
	// the template's 60 s (its start and deadline are stamped a few
	// milliseconds apart by the open).
	if length := templated.ExpiresAt.Sub(templated.StartedAt); length > 61*time.Second {
		t.Fatalf("the templated session lasts %s, beyond the template's 60 s", length)
	}

	// Emergency access: only a named responder, never a bundle run or a
	// token minted for someone else, and never by the normal open.
	emergency := func(token, key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/emergency-sessions", token, key, map[string]any{
			"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "reason": "primary database refusing writes",
			"method": "stub_pam", "payload_base64": attestation, "ttl_seconds": 20})
	}
	if status, _ := emergency(responder, "a258-before-named"); status != http.StatusForbidden {
		t.Fatalf("an unnamed responder opened emergency access: %d", status)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/emergency/responders", admin, "a258-responders",
		map[string]any{"subjects": []string{"oncall@ops.example"}}); status != http.StatusOK || !strings.Contains(string(body), "oncall@ops.example") {
		t.Fatalf("name the responder = %d %s", status, body)
	}
	if status, _ := emergency(f.requester, "a258-requester"); status != http.StatusForbidden {
		t.Fatalf("a requester who is not a named responder opened emergency access: %d", status)
	}
	// A token the admin minted for the responder (F262) does the responder's
	// work, but emergency access belongs to the person.
	minted := createServedToken(t, h.ts, admin, "oncall@ops.example", []string{"access:read", "access:sessions.open"})
	if status, _ := emergency(minted, "a258-delegated"); status != http.StatusForbidden {
		t.Fatalf("a token minted for the responder opened emergency access: %d", status)
	}
	unreviewed := map[string]any{"request_id": uuid.NewString(), "approval_request_id": uuid.NewString(), "intent_digest": "forged",
		"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "reason": "emergency", "method": "stub_pam",
		"payload_base64": attestation, "emergency": true}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", responder, "a258-forged-open", unreviewed); status == http.StatusCreated {
		t.Fatal("the normal open skipped review")
	}

	status, body = emergency(responder, "a258-emergency")
	var opened struct {
		a258Session
		Emergency struct {
			Responder string `json:"responder"`
			Review    struct {
				Status string `json:"status"`
			} `json:"review"`
		} `json:"emergency"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &opened) != nil || opened.Emergency.Responder != "oncall@ops.example" ||
		opened.Emergency.Review.Status != "pending" || opened.Delivery != "gateway" {
		t.Fatalf("emergency open = %d %s", status, body)
	}
	if length := opened.ExpiresAt.Sub(opened.StartedAt); length > 21*time.Second {
		t.Fatalf("the emergency session lasts %s, beyond the 20 s it asked for", length)
	}
	local, stop := f.postgresTunnel(opened.servedPAMSessionResponse)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://responder@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("the emergency session does not reach the database: %v", err)
	}
	if r := conn.ExecParams(f.ctx, "SELECT count(*) FROM public.pam_smoke", nil, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}

	// Every approver is notified on the approval channels; the notice names
	// no credential.
	var payload string
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT convert_from(payload, 'UTF8') FROM outbox
		WHERE tenant_id = $1 AND destination = 'notification.approval' AND idempotency_key = $2`,
		h.tenant, "emergency-access:"+opened.ID).Scan(&payload); err != nil {
		t.Fatalf("no approval-channel notice for the emergency grant: %v", err)
	}
	if !strings.Contains(payload, "access.emergency_opened") || !strings.Contains(payload, "oncall@ops.example") ||
		!strings.Contains(payload, "primary database refusing writes") || strings.Contains(payload, "password") {
		t.Fatalf("notice = %s", payload)
	}

	// It ends at its deadline.
	a201Await(t, "the emergency session ends at its deadline", func() bool {
		return conn.ExecParams(f.ctx, "SELECT 1", nil, nil, nil, nil).Read().Err != nil
	})
	a201Await(t, "the emergency session reads ended", func() bool {
		status, _ := f.sessionRead(opened.ID)["status"].(string)
		return status == "expired" || status == "revoked"
	})

	// The review: not the responder, not without access:approve, once.
	review := func(token, key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/emergency-sessions/"+opened.ID+"/review", token, key,
			map[string]any{"outcome": "justified", "notes": "INC-43: replica promotion needed a write; access ended on time"})
	}
	if status, _ := review(responder, "a258-self-review"); status != http.StatusForbidden {
		t.Fatalf("the responder reviewed their own emergency access: %d", status)
	}
	if status, _ := review(f.requester, "a258-requester-review"); status != http.StatusForbidden {
		t.Fatalf("a principal without access:approve reviewed: %d", status)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/emergency-sessions", admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("the pending review is not visible: %d %s", status, body)
	}
	if status, body := review(f.reviewerOne, "a258-review"); status != http.StatusOK || !strings.Contains(string(body), `"status":"reviewed"`) ||
		!strings.Contains(string(body), `"reviewer":"pam-reviewer-one"`) {
		t.Fatalf("review = %d %s", status, body)
	}
	if status, _ := review(f.reviewerTwo, "a258-second-review"); status == http.StatusOK {
		t.Fatal("a reviewed grant was reviewed again")
	}
	if em, _ := f.sessionRead(opened.ID)["emergency"].(map[string]any); em == nil {
		t.Fatal("the session read does not show its emergency grant")
	}
}
