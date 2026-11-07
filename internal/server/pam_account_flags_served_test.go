// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
)

// TestServedOrphanedAccountActionIsApprovedAppliedAndReadBackA276: a
// brokered account with no owner is flagged orphaned — and unused once it
// sat past the window. A proposed reassignment needs two reviewers, is
// applied once and reads back as the account's owner; the flag clears from
// open to actioned and its approval cannot be applied again. When that
// owner's member is offboarded the account is flagged again; an approved
// rotate-and-disable queues the vaulted credential's rotation, which
// completes, and disables the target, read back on both.
func TestServedOrphanedAccountActionIsApprovedAppliedAndReadBackA276(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a276-secrets", "secrets:read", "secrets:write")
	steward := seedScopedTokenSubject(t, h.store, h.tenant, "a276-steward", "access:read", "access:write", "access:targets.write", "access:role.assign", "owners:read", "owners:write")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a276-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a276-reviewer-2", "access:read", "access:approve"),
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a276-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", steward, "a276-register",
		map[string]any{"id": "orders-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register: %d %s", status, body)
	}
	flagOf := func() api.PAMAccountFlag {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/account-flags", steward, nil)
		var listed struct {
			Items []api.PAMAccountFlag `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("flags: %d %s", status, body)
		}
		for _, fl := range listed.Items {
			if fl.TargetType == "postgres" && fl.TargetID == "orders-vault" {
				return fl
			}
		}
		return api.PAMAccountFlag{}
	}
	scan := func(key string) {
		t.Helper()
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/account-flags/scan", steward, key, nil); status != http.StatusOK {
			t.Fatalf("scan %s: %d %s", key, status, body)
		}
	}
	target := func() api.PAMTarget {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/targets/postgres/orders-vault", steward, nil)
		var tg api.PAMTarget
		if status != http.StatusOK || json.Unmarshal(body, &tg) != nil {
			t.Fatalf("target: %d %s", status, body)
		}
		return tg
	}
	// approve proposes an action, has both reviewers approve it and applies it.
	approve := func(key string, action map[string]any) (map[string]any, api.PAMAccountFlag) {
		t.Helper()
		action["request_id"] = uuid.NewString()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/account-flags/postgres/orders-vault/actions", steward, key, action)
		var review api.PAMAccountActionReview
		if status != http.StatusAccepted || json.Unmarshal(body, &review) != nil || review.RequiredApprovals != 2 {
			t.Fatalf("propose %s: %d %s", key, status, body)
		}
		apply := func(k string) (int, []byte) {
			action["approval_request_id"], action["intent_digest"] = review.ApprovalRequestID, review.IntentDigest
			return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/account-flags/postgres/orders-vault/actions/apply", steward, k, action)
		}
		if status, _ := apply(key + "-early"); status == http.StatusOK {
			t.Fatalf("%s applied before its review", key)
		}
		for i, reviewer := range reviewers {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.ApprovalRequestID+"/approvals",
				reviewer, key+"-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": review.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d of %s: %d %s", i+1, key, status, body)
			}
		}
		status, body = apply(key + "-apply")
		var flag api.PAMAccountFlag
		if status != http.StatusOK || json.Unmarshal(body, &flag) != nil {
			t.Fatalf("apply %s: %d %s", key, status, body)
		}
		if again, againBody := apply(key + "-apply-again"); again != http.StatusOK {
			t.Fatalf("re-applying %s with its approval: %d %s", key, again, againBody)
		}
		return action, flag
	}

	// Orphaned: no owner. Unused: past the window (the PAM clock moved on).
	scan("a276-scan-1")
	if fl := flagOf(); fl.Status != "open" || !slices.Equal(fl.Reasons, []string{"orphaned"}) {
		t.Fatalf("the ownerless account's flag: %+v", fl)
	}
	previous := h.srv.pam.clock
	h.srv.pam.clock = func() time.Time { return time.Now().Add(91 * 24 * time.Hour) }
	scan("a276-scan-unused")
	h.srv.pam.clock = previous
	if fl := flagOf(); fl.Status != "open" || !slices.Equal(fl.Reasons, []string{"orphaned", "unused"}) {
		t.Fatalf("the long-unused ownerless account's flag: %+v", fl)
	}
	scan("a276-scan-2")
	if fl := flagOf(); !slices.Equal(fl.Reasons, []string{"orphaned"}) {
		t.Fatalf("the flag after the window was back: %+v", fl)
	}

	// Reassign to a person owner, approved and read back.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/members/"+url.PathEscape("dana@example.test"), steward, "a276-member",
		map[string]any{"display_name": "Dana", "email": "dana@example.test", "roles": []string{"viewer"}}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("onboard the member: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/owners", steward, "a276-owner",
		map[string]any{"kind": "user", "name": "Dana", "email": "dana@example.test"})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil {
		t.Fatalf("owner: %d %s", status, body)
	}
	action, flag := approve("a276-reassign", map[string]any{"action": "reassign", "owner_id": owner.ID, "reason": "Dana runs the orders ledger"})
	if flag.Status != "actioned" || flag.Action != "reassign" || flag.ActionOwnerID != owner.ID || flag.ApprovalRequestID != action["approval_request_id"] {
		t.Fatalf("the reassigned flag: %+v", flag)
	}
	if tg := target(); tg.OwnerID != owner.ID {
		t.Fatalf("the reassigned target's owner: %+v", tg)
	}
	scan("a276-scan-3")
	if fl := flagOf(); fl.Status != "actioned" {
		t.Fatalf("a resolved flag reopened: %+v", fl)
	}

	// The owner's member is offboarded: orphaned again.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/members/"+url.PathEscape("dana@example.test")+"/offboard",
		steward, "a276-offboard", map[string]any{"reason": "left the company"}); status != http.StatusOK {
		t.Fatalf("offboard: %d %s", status, body)
	}
	scan("a276-scan-4")
	if fl := flagOf(); fl.Status != "open" || !slices.Equal(fl.Reasons, []string{"orphaned"}) || fl.OwnerID != owner.ID {
		t.Fatalf("the offboarded owner's account: %+v", fl)
	}

	// Rotate and disable, approved; the rotation completes and the target
	// reads disabled.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/account-flags/postgres/orders-vault/actions", steward, "a276-guess",
		map[string]any{"request_id": uuid.NewString(), "action": "rotate_disable", "reason": "a guess", "rotation_old_ref": "none"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("a rotation without the account in use: %d %s", status, body)
	}
	_, flag = approve("a276-rotate-disable", map[string]any{"action": "rotate_disable", "rotation_old_ref": twoUserAccountA, "reason": "no owner left; retire the account"})
	if flag.Status != "actioned" || flag.Action != "rotate_disable" || flag.ActionRotationID == "" {
		t.Fatalf("the rotated and disabled flag: %+v", flag)
	}
	if tg := target(); tg.Enabled {
		t.Fatalf("the target is still enabled: %+v", tg)
	}
	var rotation staticRotationCommandView
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		staticRotationDueFor(t, h.servedHarness, h.tenant)
		h.srv.dispatchOnce(context.Background())
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/rotations/"+flag.ActionRotationID, custodian, nil)
		if status != http.StatusOK || json.Unmarshal(body, &rotation) != nil {
			t.Fatalf("read the rotation: %d %s", status, body)
		}
		if rotation.Terminal || time.Now().After(deadline) {
			break
		}
	}
	if rotation.Phase != "completed" {
		t.Fatalf("the account's rotation: %+v", rotation)
	}
}
