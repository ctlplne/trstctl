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

// A261-L1: a check-out ends with the rotation that retires what it revealed.
// When the account's custodian (or a schedule) already queued a rotation of
// the account after the reveal, that rotation replaces the revealed version,
// so checking in adopts it: the check-in succeeds at once and names that
// rotation, instead of being refused with 409 while it runs and retried at
// every deadline tick. Once it completes the revealed credential no longer
// signs in.
func TestServedCheckInAdoptsTheRotationAlreadyInFlightA261L1(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261l1-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a261l1-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a261l1-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l1-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l1-reviewer-2", "access:read", "access:approve"),
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a261l1-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a261l1-register",
		map[string]any{"id": "orders-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}

	var review struct {
		RequestID         string `json:"request_id"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, "a261l1-request",
		map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-vault",
			"reason": "INC-5120 reconcile a stuck payout by hand", "ttl_seconds": 120})
	if status != http.StatusAccepted || json.Unmarshal(raw, &review) != nil || review.RequiredApprovals < 1 || review.RequiredApprovals > len(reviewers) {
		t.Fatalf("request a check-out = %d %s", status, raw)
	}
	for i, reviewer := range reviewers[:review.RequiredApprovals] {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.ApprovalRequestID+"/approvals",
			reviewer, "a261l1-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": review.IntentDigest}); status != http.StatusOK {
			t.Fatalf("review %d = %d %s", i+1, status, body)
		}
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/reveal", requester,
		"a261l1-reveal", map[string]any{"approval_request_id": review.ApprovalRequestID, "intent_digest": review.IntentDigest})
	var revealed struct {
		Checkout struct {
			SecretVersion int `json:"secret_version"`
		} `json:"checkout"`
		Credential string `json:"credential"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &revealed) != nil || revealed.Credential == "" {
		t.Fatalf("reveal = %d %s", status, raw)
	}
	signsIn := func(credential string) error {
		conn, err := pgconn.Connect(f.ctx, credential)
		if err == nil {
			_ = conn.Close(context.Background())
		}
		return err
	}
	if err := signsIn(revealed.Credential); err != nil {
		t.Fatalf("the revealed credential does not sign in: %v", err)
	}

	// The custodian rotates the account while the check-out is open.
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", custodian, "a261l1-manual-rotation",
		map[string]any{"provider": "pam-pg-vault", "key": twoUserRole, "old_ref": twoUserAccountA})
	var queued struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &queued) != nil || queued.CommandID == "" {
		t.Fatalf("queue the custodian's rotation = %d %s", status, raw)
	}

	// Checking in adopts it rather than waiting for it.
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/checkin", requester, "a261l1-checkin", nil)
	var checkedIn struct {
		Status            string `json:"status"`
		RotationCommandID string `json:"rotation_command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &checkedIn) != nil || checkedIn.Status != "checked_in" || checkedIn.RotationCommandID != queued.CommandID {
		t.Fatalf("check in while the custodian's rotation is in flight = %d %s; want it checked in on rotation %s", status, raw, queued.CommandID)
	}
	a201Await(t, "the adopted rotation completes", func() bool {
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
			if item.ID == queued.CommandID && item.Phase == "completed" {
				return true
			}
		}
		return false
	})
	if err := signsIn(revealed.Credential); err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("after the adopted rotation the revealed credential signs in: %v", err)
	}
}
