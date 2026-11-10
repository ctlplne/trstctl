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
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/notify"
)

// A261-L2: a check-out whose rotation cannot be queued when its deadline
// passes — here its provider is gone, so the secrets API refuses the
// rotation as it would after the provider's removal — stays revealed, and its
// credential still signs in. It raises one critical alert naming the
// check-out, the target, the requester and why, never the credential, and
// later ticks that still cannot end it raise no second alert. Once a rotation
// can be queued again, the next tick ends it.
func TestServedCheckoutThatCannotRotateRaisesOneAlertA261L2(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261l2-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a261l2-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a261l2-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l2-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a261l2-reviewer-2", "access:read", "access:approve"),
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a261l2-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a261l2-register",
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
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, "a261l2-request",
		map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-vault",
			"reason": "INC-5133 repair a ledger row by hand", "ttl_seconds": 180})
	if status != http.StatusAccepted || json.Unmarshal(raw, &review) != nil || review.RequiredApprovals < 1 || review.RequiredApprovals > len(reviewers) {
		t.Fatalf("request a check-out = %d %s", status, raw)
	}
	for i, reviewer := range reviewers[:review.RequiredApprovals] {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.ApprovalRequestID+"/approvals",
			reviewer, "a261l2-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": review.IntentDigest}); status != http.StatusOK {
			t.Fatalf("review %d = %d %s", i+1, status, body)
		}
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/reveal", requester,
		"a261l2-reveal", map[string]any{"approval_request_id": review.ApprovalRequestID, "intent_digest": review.IntentDigest})
	var revealed struct {
		Credential string `json:"credential"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &revealed) != nil || revealed.Credential == "" {
		t.Fatalf("reveal = %d %s", status, raw)
	}
	checkoutStatus := func() string {
		t.Helper()
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/checkouts/"+review.RequestID, requester, nil)
		var c struct {
			Status string `json:"status"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &c) != nil {
			t.Fatalf("get the check-out = %d %s", status, raw)
		}
		return c.Status
	}
	alerts := func() []notify.Alert {
		t.Helper()
		var out []notify.Alert
		if err := h.store.WithTenant(f.ctx, h.tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(f.ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
				h.tenant, notify.DestinationRisk, "pam-checkout-rotation-blocked:"+review.RequestID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var payload []byte
				if err := rows.Scan(&payload); err != nil {
					return err
				}
				var alert notify.Alert
				if err := json.Unmarshal(payload, &alert); err != nil {
					return err
				}
				out = append(out, alert)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// The account's provider is gone: the secrets API refuses its rotation.
	working := h.srv.pam.rotation.queue
	h.srv.pam.rotation.queue = func(ctx context.Context, tenantID, _, key, currentAccount, requestID string,
		revealedAt time.Time, revealedVersion int) (string, error) {
		return h.srv.api.QueueVaultedAccountRotation(ctx, tenantID, "pam-pg-vault-removed", key, currentAccount, requestID, revealedAt, revealedVersion)
	}
	for _, after := range []time.Duration{4 * time.Minute, 5 * time.Minute} {
		h.srv.pam.expireCheckouts(context.Background(), time.Now().Add(after))
	}
	if got := checkoutStatus(); got != "revealed" {
		t.Fatalf("a check-out whose rotation cannot be queued = %q, want it still revealed", got)
	}
	got := alerts()
	if len(got) != 1 {
		t.Fatalf("alerts for the blocked check-out = %d, want one across two ticks", len(got))
	}
	alert := got[0]
	if alert.Kind != notify.KindCheckoutRotationBlocked || alert.Severity != notify.AlertSeverityCritical ||
		alert.Subject != "postgres/orders-vault" || !strings.Contains(alert.Detail, review.RequestID) ||
		!strings.Contains(alert.Detail, "a261l2-requester") || !strings.Contains(alert.Detail, "still signs in") ||
		strings.Contains(alert.Detail, revealed.Credential) {
		t.Fatalf("blocked check-out alert = %+v", alert)
	}

	// The provider is back: the next tick ends the check-out with its rotation.
	h.srv.pam.rotation.queue = working
	h.srv.pam.expireCheckouts(context.Background(), time.Now().Add(6*time.Minute))
	if got := checkoutStatus(); got != "expired" {
		t.Fatalf("once a rotation can be queued the check-out = %q, want expired", got)
	}
	if len(alerts()) != 1 {
		t.Fatal("ending the check-out raised another alert")
	}
}
