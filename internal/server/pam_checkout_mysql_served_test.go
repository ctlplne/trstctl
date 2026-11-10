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

	"trstctl.com/trstctl/internal/dynsecret"
)

// A261-L3: a vaulted MySQL account is checked out as a PostgreSQL one is (the
// PostgreSQL journey is TestServedCheckoutRevealsOnceAndRotatesA261). A MySQL
// role's rotation mints a new account, so a check-out waits for the account's
// first rotation, which replaces the seeded account. After independent review
// the credential is shown once to its requester and signs in to MySQL;
// checking it in rotates the account again, dropping the revealed one, so the
// revealed credential is refused; the next check-out shows the successor.
func TestServedMySQLCheckoutRevealsOnceAndRotatesA261L3(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{mysqlVaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261l3-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a261l3-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a261l3-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l3-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l3-reviewer-2", "access:read", "access:approve"),
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a261l3-seed",
		map[string]any{"name": mysqlVaultRole, "value": f.mysqlVaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a261l3-register",
		map[string]any{"id": "ledger-vault", "target_type": "mysql", "provider_id": "pam-mysql-vault", "allowed_roles": []string{mysqlVaultRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": mysqlVaultRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted MySQL target = %d %s", status, body)
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
		RotationCommandID string `json:"rotation_command_id"`
	}
	request := func(key string) review {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, key,
			map[string]any{"request_id": uuid.NewString(), "target_type": "mysql", "target_id": "ledger-vault",
				"reason": "INC-5120 correct a ledger row by hand", "ttl_seconds": 120})
		var r review
		if status != http.StatusAccepted || json.Unmarshal(raw, &r) != nil || r.Status != "pending" || r.RequiredApprovals < 1 || r.RequiredApprovals > len(reviewers) {
			t.Fatalf("request a MySQL check-out = %d %s", status, raw)
		}
		for i, reviewer := range reviewers[:r.RequiredApprovals] {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals",
				reviewer, r.RequestID+"-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": r.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d = %d %s", i+1, status, body)
			}
		}
		return r
	}
	reveal := func(key string, r review) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/reveal", requester, key,
			map[string]any{"approval_request_id": r.ApprovalRequestID, "intent_digest": r.IntentDigest})
	}
	revealed := func(r review) (string, checkout) {
		t.Helper()
		status, raw := reveal(r.RequestID+"-reveal", r)
		var got struct {
			Checkout   checkout `json:"checkout"`
			Credential string   `json:"credential"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &got) != nil || got.Credential == "" || got.Checkout.Status != "revealed" {
			t.Fatalf("reveal = %d %s", status, raw)
		}
		return got.Credential, got.Checkout
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
		ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
		defer cancel()
		db, err := dynsecret.OpenMySQLExecutor(ctx, []byte(credential))
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		var one int
		return db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
	}

	// A MySQL role's rotation mints a new account, so it can retire only an
	// account it minted: a check-out waits for the account's first rotation.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, "a261l3-too-early",
		map[string]any{"request_id": uuid.NewString(), "target_type": "mysql", "target_id": "ledger-vault",
			"reason": "before the first rotation", "ttl_seconds": 120}); status != http.StatusConflict || !strings.Contains(string(body), "first rotation") {
		t.Fatalf("a check-out before the first rotation = %d %s", status, body)
	}
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/rotations", custodian, "a261l3-first-rotation",
		map[string]any{"provider": "pam-mysql-vault", "key": mysqlVaultRole, "old_ref": mysqlVaultSeedUser})
	var first struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &first) != nil || first.CommandID == "" {
		t.Fatalf("queue the first rotation = %d %s", status, raw)
	}
	rotated(first.CommandID)
	if err := signsIn(f.mysqlVaultDSN); err == nil || !strings.Contains(err.Error(), "refused the credential") {
		t.Fatalf("after the first rotation the seeded account signs in: %v", err)
	}

	r := request("a261l3-request")
	credential, c := revealed(r)
	if credential == f.mysqlVaultDSN || c.SecretVersion != 2 || !strings.HasPrefix(credential, mysqlVaultPrefix+"_") {
		t.Fatalf("revealed version %d; want the account the first rotation minted (version 2)", c.SecretVersion)
	}
	if err := signsIn(credential); err != nil {
		t.Fatalf("the revealed MySQL credential does not sign in: %v", err)
	}
	if status, body := reveal("a261l3-again", r); status != http.StatusConflict || !strings.Contains(string(body), "shown once") {
		t.Fatalf("a second reveal = %d %s", status, body)
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/checkin", requester, "a261l3-checkin", nil)
	if status != http.StatusOK || json.Unmarshal(raw, &c) != nil || c.Status != "checked_in" || c.RotationCommandID == "" {
		t.Fatalf("check in = %d %s", status, raw)
	}
	rotated(c.RotationCommandID)
	if err := signsIn(credential); err == nil || !strings.Contains(err.Error(), "refused the credential") {
		t.Fatalf("after check-in the revealed MySQL credential signs in: %v", err)
	}

	// The next check-out shows the successor account, which signs in.
	r = request("a261l3-request-2")
	successor, c := revealed(r)
	if c.SecretVersion != 3 || successor == credential {
		t.Fatalf("the second check-out revealed version %d", c.SecretVersion)
	}
	if err := signsIn(successor); err != nil {
		t.Fatalf("the successor MySQL account does not sign in: %v", err)
	}
}
