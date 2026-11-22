// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/pgsignin"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An auto-approval is a recorded policy decision, not a skipped review. A
// request outside any one of the rule's criteria still needs human review.
func TestServedAutoApprovalRulesMatchOnlyTheirCriteriaA261(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a261-rules-admin", "access:read", "access:write", "access:targets.write")
	sessionOnly := seedScopedTokenSubject(t, h.store, h.tenant, "a261-rules-session-only", "access:read", "access:sessions.open")
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "a261-rules-auditor", "audit:read")
	call := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, method, path, admin, key, body)
	}
	// Pick an IANA fixed-offset zone where the local hour is12, so the live
	// proof cannot straddle a window boundary. Boundary/DST cases are pure tests.
	offset := time.Now().UTC().Hour() - 12
	zone := fmt.Sprintf("Etc/GMT%+d", offset)
	window := map[string]any{"days": []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, "start": "10:00", "end": "15:00", "time_zone": zone}
	ruleID := uuid.NewString()
	a261CleanupRule(t, h, admin, ruleID)
	body := map[string]any{"name": "Routine incident review", "applies_to": []string{"session"}, "target_types": []string{"postgres"},
		"target_ids": []string{"pg-gw"}, "requester_roles": []string{"api-token"}, "window": window,
		"ticket_pattern": "^INC-[0-9]+$", "max_ttl_seconds": 120, "enabled": true}
	revision := int64(0)
	save := func() {
		t.Helper()
		body["revision"] = revision
		status, raw := call(http.MethodPut, "/api/v1/access/auto-approval-rules/"+ruleID, uuid.NewString(), body)
		var saved struct {
			Revision int64 `json:"revision"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &saved) != nil || saved.Revision != revision+1 {
			t.Fatalf("save rule = %d %s", status, raw)
		}
		revision = saved.Revision
	}
	save()
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/auto-approval-rules/"+uuid.NewString(), sessionOnly, uuid.NewString(), body); status != http.StatusForbidden {
		t.Fatalf("session-only caller changed auto-approval policy = %d %s", status, raw)
	}
	if status, raw := call(http.MethodPost, "/api/v1/access/targets", uuid.NewString(), map[string]any{"id": "auto-other", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register other target = %d %s", status, raw)
	}
	request := func(target, reason string, ttl int, want string) api.PAMApprovalRequest {
		t.Helper()
		req := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": target, "role": "readonly", "reason": reason, "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": ttl}
		key := uuid.NewString()
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, key, req)
		var review api.PAMApprovalRequest
		if status != http.StatusAccepted || json.Unmarshal(raw, &review) != nil || review.Status != want {
			t.Fatalf("%s/%s review = %d %s; want %s", target, reason, status, raw, want)
		}
		if replayStatus, replay := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, key, req); replayStatus != status || string(replay) != string(raw) {
			t.Fatalf("review replay changed: %d %s", replayStatus, replay)
		}
		return review
	}
	matched := request("pg-gw", "INC-261", 60, "approved")
	if matched.RequiredApprovals != 1 || matched.ApprovalCount != 1 {
		t.Fatalf("rule decision = %+v", matched)
	}
	if n := pamEventCount(t, h.servedHarness, "pam.auto_approval.applied"); n != 1 {
		t.Fatalf("replay produced %d rule events", n)
	}
	status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/audit/events?type=pam.auto_approval.applied", auditor, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), ruleID) || !strings.Contains(string(raw), matched.ApprovalRequestID) || !strings.Contains(string(raw), "api-token") {
		t.Fatalf("rule audit record = %d %s", status, raw)
	}
	// An approved review must actually open the gateway and execute a stock
	// PostgreSQL client query; an approved HTTP response alone is insufficient.
	openBody := map[string]any{"request_id": matched.RequestID, "approval_request_id": matched.ApprovalRequestID, "intent_digest": matched.IntentDigest,
		"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "reason": "INC-261", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester, uuid.NewString(), openBody)
	var opened a258Session
	if status != http.StatusCreated || json.Unmarshal(raw, &opened) != nil || opened.Delivery != "gateway" {
		t.Fatalf("automatically reviewed open = %d %s", status, raw)
	}
	local, stop := f.postgresTunnel(opened.servedPAMSessionResponse)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://reader@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("automatically reviewed database connection: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if result := conn.ExecParams(f.ctx, "SELECT 1", nil, nil, nil, nil).Read(); result.Err != nil {
		t.Fatalf("automatically reviewed database query: %v", result.Err)
	}
	request("auto-other", "INC-261", 60, "pending")
	request("pg-gw", "no ticket", 60, "pending")
	request("pg-gw", "INC-261", 180, "pending")
	body["requester_roles"] = []string{"operator"}
	save()
	request("pg-gw", "INC-261", 60, "pending")
	body["requester_roles"] = []string{"api-token"}
	body["window"] = map[string]any{"days": []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, "start": "00:00", "end": "01:00", "time_zone": zone}
	save()
	request("pg-gw", "INC-261", 60, "pending")
	body["window"] = window
	body["enabled"] = false
	save()
	request("pg-gw", "INC-261", 60, "pending")
	if n := pamEventCount(t, h.servedHarness, "pam.auto_approval.applied"); n != 1 {
		t.Fatalf("nonmatch produced rule event, count=%d", n)
	}
	body["enabled"] = true
	save()
	if status, raw := call(http.MethodDelete, fmt.Sprintf("/api/v1/access/auto-approval-rules/%s?revision=%d", ruleID, revision), uuid.NewString(), nil); status != http.StatusOK {
		t.Fatalf("delete rule = %d %s", status, raw)
	}
	request("pg-gw", "INC-261", 60, "pending")
	// A tombstone is not a new policy slot with reset authority.
	body["revision"] = revision + 1
	if status, raw := call(http.MethodPut, "/api/v1/access/auto-approval-rules/"+ruleID, uuid.NewString(), body); status != http.StatusConflict {
		t.Fatalf("resurrect deleted rule = %d %s", status, raw)
	}
	const neighbor = "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(f.ctx, store.Tenant{TenantID: neighbor, Name: "Auto-approval neighbor"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, neighbor, "a261-auto-neighbor", "access:read", "access:write")
	if status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/auto-approval-rules", foreign, nil); status != http.StatusOK || strings.Contains(string(raw), ruleID) {
		t.Fatalf("foreign rules = %d %s", status, raw)
	}
}

// Durable policy evaluation survives a crash after the decision and a later
// policy edit. The same command recovers one decision, with its original rule
// and expiry, even when submitted under a fresh HTTP idempotency key.
func TestServedAutoApprovalRecoversDecisionAndChecksOutA261(t *testing.T) {
	const duplicateWindow = 100 * time.Millisecond
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true, duplicateWindow: duplicateWindow})
	h := f.h
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a261-auto-recovery-admin", "access:read", "access:write", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a261-auto-recovery-user", "access:read", "access:sessions.open")
	ruleID := uuid.NewString()
	a261CleanupRule(t, h, admin, ruleID)
	rule := map[string]any{"name": "Routine read access", "applies_to": []string{"session"}, "target_ids": []string{"pg-gw"}, "requester_roles": []string{"api-token"}, "max_ttl_seconds": 120, "enabled": true, "revision": 0}
	save := func() {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/auto-approval-rules/"+ruleID, admin, uuid.NewString(), rule)
		if status != http.StatusOK {
			t.Fatalf("save recovery rule = %d %s", status, raw)
		}
	}
	save()
	var crashed atomic.Bool
	h.srv.pam.afterAutoApprovalDecision = func() error {
		if crashed.CompareAndSwap(false, true) {
			return errors.New("injected crash after durable automatic decision")
		}
		return nil
	}
	requestID := uuid.NewString()
	req := map[string]any{"request_id": requestID, "target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "reason": "INC-261", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 120}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", requester, uuid.NewString(), req); status != http.StatusInternalServerError {
		t.Fatalf("injected crash status = %d", status)
	}
	rows, err := h.store.ActiveOperationApprovalsForScope(f.ctx, h.tenant, "pam", "pam:"+requestID, "activate", "a261-auto-recovery-user")
	if err != nil || len(rows) != 1 || rows[0].Status != store.ApprovalStatusApproved {
		t.Fatalf("durable approval after crash = %+v, %v", rows, err)
	}
	if n := pamEventCount(t, h.servedHarness, projections.EventPAMAutoApprovalApplied); n != 0 {
		t.Fatalf("pre-crash applied records = %d", n)
	}
	// Cross the real broker's finite duplicate memory; recovery must use
	// the durable identity index rather than append a second decision.
	time.Sleep(2 * duplicateWindow)
	rule["revision"], rule["enabled"] = 1, false
	save()
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", requester, uuid.NewString(), req)
	var recovered api.PAMApprovalRequest
	if status != http.StatusAccepted || json.Unmarshal(raw, &recovered) != nil || recovered.Status != "approved" || recovered.ApprovalRequestID != rows[0].ID || recovered.IntentDigest != rows[0].IntentDigest || !recovered.ExpiresAt.Equal(rows[0].ExpiresAt) {
		t.Fatalf("recover after rule edit = %d %s", status, raw)
	}
	for _, kind := range []string{projections.EventPAMAutoApprovalEvaluated, projections.EventApprovalRequested, projections.EventApprovalDecisionRecorded, projections.EventPAMAutoApprovalApplied} {
		if n := pamEventCount(t, h.servedHarness, kind); n != 1 {
			t.Fatalf("recovery duplicated %s: %d", kind, n)
		}
	}
	// A requester colliding with the policy's synthetic approver must retain
	// the normal human quorum, rather than becoming its own one-vote approver.
	rule["revision"], rule["enabled"] = 2, true
	save()
	collision := seedScopedTokenSubject(t, h.store, h.tenant, "auto-approval:"+ruleID, "access:read", "access:sessions.open")
	req["request_id"] = uuid.NewString()
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", collision, uuid.NewString(), req)
	var human api.PAMApprovalRequest
	if status != http.StatusAccepted || json.Unmarshal(raw, &human) != nil || human.Status != "pending" || human.RequiredApprovals != 2 || human.ApprovalCount != 0 {
		t.Fatalf("synthetic requester collision = %d %s", status, raw)
	}
	// A checkout-only rule grants one reveal of the actual vaulted credential.
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261-auto-secrets", "secrets:read", "secrets:write")
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, uuid.NewString(), map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed vaulted secret status=%d", status)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", admin, uuid.NewString(), map[string]any{"id": "auto-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole}, "account_secret": twoUserRole, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register vaulted target = %d %s", status, raw)
	}
	rule["revision"], rule["applies_to"], rule["target_ids"] = 3, []string{"checkout"}, []string{"auto-vault"}
	save()
	checkoutID := uuid.NewString()
	t.Cleanup(func() {
		row, err := h.store.GetPAMCheckout(context.Background(), h.tenant, checkoutID)
		if err != nil {
			t.Errorf("read automatic checkout fixture state: %v", err)
			return
		}
		if row.Status == "revealed" {
			t.Error("automatic checkout fixture leaves revealed material for later expiry sweeps")
		}
	})
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, uuid.NewString(), map[string]any{"request_id": checkoutID, "target_type": "postgres", "target_id": "auto-vault", "reason": "INC-261", "ttl_seconds": 120})
	var review api.PAMCheckoutReview
	if status != http.StatusAccepted || json.Unmarshal(raw, &review) != nil || review.Status != "approved" || review.RequiredApprovals != 1 {
		t.Fatalf("auto checkout review = %d %s", status, raw)
	}
	reveal := func() (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+checkoutID+"/reveal", requester, uuid.NewString(), map[string]any{"approval_request_id": review.ApprovalRequestID, "intent_digest": review.IntentDigest})
	}
	status, raw = reveal()
	defer secret.Wipe(raw)
	var revealed api.PAMCheckoutReveal
	if status != http.StatusOK || json.Unmarshal(raw, &revealed) != nil || len(revealed.Credential) == 0 || revealed.Checkout.Status != "revealed" {
		t.Fatalf("automatic checkout reveal status=%d (credential withheld)", status)
	}
	defer secret.Wipe(revealed.Credential)
	signed, err := pgsignin.SignIn(f.ctx, revealed.Credential, pgsignin.Options{})
	if err != nil {
		t.Fatal("automatically revealed credential cannot sign in (credential withheld)")
	}
	_ = signed.Conn.Close()
	if status, again := reveal(); status != http.StatusConflict {
		secret.Wipe(again)
		t.Fatalf("second automatic reveal status=%d", status)
	} else {
		secret.Wipe(again)
	}
	// Finish the resource lifecycle before this fixture stops its database.
	// Otherwise another fixture's expiry sweep can queue a stale rotation for
	// the same shared tenant/secret and block that fixture's reviewed checkout.
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+checkoutID+"/checkin", requester, uuid.NewString(), nil)
	var checked api.PAMCheckout
	if status != http.StatusOK || json.Unmarshal(raw, &checked) != nil || checked.Status != "checked_in" || checked.RotationCommandID == "" {
		t.Fatalf("check in automatic checkout = %d (credential withheld)", status)
	}
	a201Await(t, "the automatic checkout rotation completes before fixture shutdown", func() bool {
		ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
		defer cancel()
		_ = h.srv.Drain(ctx)
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/rotations", custodian, nil)
		var page struct {
			Items []struct {
				ID    string `json:"id"`
				Phase string `json:"phase"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return false
		}
		for _, item := range page.Items {
			if item.ID == checked.RotationCommandID {
				return item.Phase == "completed"
			}
		}
		return false
	})
	retired, err := pgsignin.SignIn(f.ctx, revealed.Credential, pgsignin.Options{})
	if err == nil {
		_ = retired.Conn.Close()
		t.Fatal("checked-in automatic credential still signs in")
	}
	if !strings.Contains(err.Error(), "SQLSTATE 28P01") {
		t.Fatal("retired automatic credential was not refused by database authentication (credential withheld)")
	}
	if n := pamEventCount(t, h.servedHarness, projections.EventPAMAutoApprovalApplied); n != 2 {
		t.Fatalf("automatic checkout applied records = %d", n)
	}
}

func TestServedAutoApprovalRuleCapacityIsBoundedA261(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h
	const tenant = "40400000-0000-4000-8000-000000000001"
	if err := h.store.UpsertTenant(f.ctx, store.Tenant{TenantID: tenant, Name: "A261 capacity"}); err != nil {
		t.Fatal(err)
	}
	admin := seedScopedTokenSubject(t, h.store, tenant, "a261-capacity-admin", "access:read", "access:write")
	body := map[string]any{"name": "Routine read", "applies_to": []string{"session"}, "target_ids": []string{"pg-gw"}, "max_ttl_seconds": 120, "enabled": false, "revision": 0}
	first := ""
	ownedIDs := []string{}
	t.Cleanup(func() {
		for _, id := range ownedIDs {
			current, err := h.store.GetPAMAutoApprovalRule(context.Background(), tenant, id)
			if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
				continue
			}
			if err != nil {
				t.Errorf("read capacity cleanup: %v", err)
				continue
			}
			status, _ := secretsReqKey(t, h.servedHarness, http.MethodDelete, fmt.Sprintf("/api/v1/access/auto-approval-rules/%s?revision=%d", id, current.Revision), admin, uuid.NewString(), nil)
			if status != http.StatusOK {
				t.Errorf("capacity cleanup status=%d", status)
			}
		}
	})
	for i := 0; i < 256; i++ {
		id := uuid.NewString()
		ownedIDs = append(ownedIDs, id)
		if i == 0 {
			first = id
		}
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/auto-approval-rules/"+id, admin, uuid.NewString(), body)
		if status != http.StatusOK {
			t.Fatalf("save rule %d = %d %s", i, status, raw)
		}
	}
	before := pamEventCount(t, h.servedHarness, projections.EventPAMAutoApprovalRuleSaved)
	extraID := uuid.NewString()
	ownedIDs = append(ownedIDs, extraID)
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/auto-approval-rules/"+extraID, admin, uuid.NewString(), body); status != http.StatusUnprocessableEntity {
		t.Fatalf("257th rule = %d %s", status, raw)
	}
	if after := pamEventCount(t, h.servedHarness, projections.EventPAMAutoApprovalRuleSaved); after != before {
		t.Fatal("capacity rejection emitted a saved event")
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodDelete, "/api/v1/access/auto-approval-rules/"+first+"?revision=1", admin, uuid.NewString(), nil); status != http.StatusOK {
		t.Fatalf("delete to free capacity = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/auto-approval-rules/"+extraID, admin, uuid.NewString(), body); status != http.StatusOK {
		t.Fatalf("replacement rule = %d %s", status, raw)
	}
}

// Each fixture uses the shared control-plane database. Remove only this
// test's exact rule, before the fixture shuts its server down.
func a261CleanupRule(t *testing.T, h *roleHarness, admin, id string) {
	t.Helper()
	t.Cleanup(func() {
		current, err := h.store.GetPAMAutoApprovalRule(context.Background(), h.tenant, id)
		if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
			return
		}
		if err != nil {
			t.Errorf("read owned rule cleanup: %v", err)
			return
		}
		status, _ := secretsReqKey(t, h.servedHarness, http.MethodDelete, fmt.Sprintf("/api/v1/access/auto-approval-rules/%s?revision=%d", id, current.Revision), admin, uuid.NewString(), nil)
		if status != http.StatusOK {
			t.Errorf("delete owned automatic rule status=%d", status)
		}
	})
}
