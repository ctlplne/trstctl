// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestServedCheckoutRevealsOnceAndRotatesA261: a vaulted account is checked
// out after independent review — its requester cannot review it, and nobody
// else can reveal it. The reveal shows the account's current credential once
// (a second reveal is refused) and is audited; checking it in queues the
// rotation that retires it, after which the revealed credential is refused
// by the database. A check-out not checked in is rotated at its deadline.
func TestServedCheckoutRevealsOnceAndRotatesA261(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-requester", "access:read", "access:sessions.open")
	bystander := seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-bystander", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-reviewer-2", "access:read", "access:approve"),
	}
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "a261-co-auditor", "audit:read")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a261-co-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a261-co-register",
		map[string]any{"id": "orders-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}

	type review struct {
		RequestID         string `json:"request_id"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		Status            string `json:"status"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	type checkout struct {
		Status            string `json:"status"`
		SecretVersion     int    `json:"secret_version"`
		RequestedBy       string `json:"requested_by"`
		RotationCommandID string `json:"rotation_command_id"`
		EndedBy           string `json:"ended_by"`
	}
	request := func(key string, ttl int) review {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, key,
			map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-vault",
				"reason": "INC-4471 reconcile the orders ledger by hand", "ttl_seconds": ttl})
		var r review
		if status != http.StatusAccepted || json.Unmarshal(raw, &r) != nil || r.Status != "pending" {
			t.Fatalf("request a check-out = %d %s", status, raw)
		}
		if r.RequiredApprovals < 1 || r.RequiredApprovals > len(reviewers) {
			t.Fatalf("a check-out needs %d approvals", r.RequiredApprovals)
		}
		return r
	}
	approve := func(r review) {
		t.Helper()
		for i, reviewer := range reviewers[:r.RequiredApprovals] {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals",
				reviewer, r.RequestID+"-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": r.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d = %d %s", i+1, status, body)
			}
		}
	}
	reveal := func(caller, key string, r review) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/reveal", caller, key,
			map[string]any{"approval_request_id": r.ApprovalRequestID, "intent_digest": r.IntentDigest})
	}
	revealed := func(r review) (string, checkout) {
		t.Helper()
		status, raw := reveal(requester, r.RequestID+"-reveal", r)
		var got struct {
			Checkout   checkout `json:"checkout"`
			Credential string   `json:"credential"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &got) != nil || got.Credential == "" || got.Checkout.Status != "revealed" {
			t.Fatalf("reveal = %d %s", status, raw)
		}
		return got.Credential, got.Checkout
	}
	get := func(r review) checkout {
		t.Helper()
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/checkouts/"+r.RequestID, requester, nil)
		var c checkout
		if status != http.StatusOK || json.Unmarshal(raw, &c) != nil {
			t.Fatalf("get the check-out = %d %s", status, raw)
		}
		return c
	}
	rotated := func(commandID string) {
		t.Helper()
		a201Await(t, "the check-out's rotation completes", func() bool {
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
				if item.ID == commandID && item.Phase == "completed" {
					return true
				}
			}
			return false
		})
	}
	signsIn := func(credential string) error {
		conn, err := pgconn.Connect(f.ctx, credential)
		if err == nil {
			_ = conn.Close(context.Background())
		}
		return err
	}

	// Out-of-range lifetimes are refused.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, "a261-co-short",
		map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-vault", "reason": "too short", "ttl_seconds": 5}); status != http.StatusUnprocessableEntity {
		t.Fatalf("a 5-second check-out = %d %s", status, body)
	}

	// Reviewed: not before approval, not by its requester, not by anyone else.
	r := request("a261-co-request", 120)
	if status, body := reveal(requester, "a261-co-early", r); status == http.StatusOK {
		t.Fatalf("an unreviewed check-out revealed: %s", body)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals", requester,
		"a261-co-self-approve", map[string]any{"intent_digest": r.IntentDigest}); status == http.StatusOK {
		t.Fatal("the requester approved their own check-out")
	}
	approve(r)
	if status, body := reveal(bystander, "a261-co-bystander", r); status == http.StatusOK {
		t.Fatalf("another principal revealed the check-out: %s", body)
	}

	// Shown once: the account's current credential, which signs in.
	credential, c := revealed(r)
	if credential != f.vaultDSN || c.SecretVersion != 1 || c.RequestedBy == "" {
		t.Fatalf("revealed version %d by %q; want the vaulted account's version 1", c.SecretVersion, c.RequestedBy)
	}
	if err := signsIn(credential); err != nil {
		t.Fatalf("the revealed credential does not sign in: %v", err)
	}
	if status, body := reveal(requester, "a261-co-again", r); status != http.StatusConflict || !strings.Contains(string(body), "shown once") {
		t.Fatalf("a second reveal = %d %s", status, body)
	}

	// Audited.
	status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/audit/events?type=pam.checkout.revealed", auditor, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), r.RequestID) || strings.Contains(string(raw), credential) {
		t.Fatalf("the reveal's audit record = %d %s", status, raw)
	}

	// Checked in by its requester (not a bystander): the rotation retires the
	// revealed credential.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/checkin", bystander,
		"a261-co-bystander-checkin", nil); status != http.StatusForbidden {
		t.Fatalf("a bystander's check-in = %d %s", status, body)
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/checkin", requester, "a261-co-checkin", nil)
	if status != http.StatusOK || json.Unmarshal(raw, &c) != nil || c.Status != "checked_in" || c.RotationCommandID == "" {
		t.Fatalf("check in = %d %s", status, raw)
	}
	rotated(c.RotationCommandID)
	if err := signsIn(credential); err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("after check-in the revealed credential signs in: %v", err)
	}
	if again := get(r); again.Status != "checked_in" || again.RotationCommandID != c.RotationCommandID {
		t.Fatalf("the checked-in record = %+v", again)
	}

	// Not checked in: the deadline rotates it.
	r = request("a261-co-request-2", 60)
	approve(r)
	credential, c = revealed(r)
	if c.SecretVersion != 2 || signsIn(credential) != nil {
		t.Fatalf("the second check-out revealed version %d", c.SecretVersion)
	}
	h.srv.pam.expireCheckouts(context.Background(), time.Now().Add(30*time.Second))
	if c = get(r); c.Status != "revealed" {
		t.Fatalf("a check-out ended before its deadline: %+v", c)
	}
	h.srv.pam.expireCheckouts(context.Background(), time.Now().Add(2*time.Minute))
	if c = get(r); c.Status != "expired" || c.RotationCommandID == "" || c.EndedBy != pamCheckoutExpiryActor {
		t.Fatalf("past its deadline the check-out = %+v", c)
	}
	rotated(c.RotationCommandID)
	if err := signsIn(credential); err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("after its deadline the revealed credential signs in: %v", err)
	}
}
