// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// CR-001: an automatic approval rule stands in for the people who review
// privileged access, so writing one is approval authority, as granting an
// access bundle's standing approval is (OD-9). Only a principal that may
// approve access itself saves or deletes a rule (never the requester persona,
// which holds access:write without access:approve, and never a token someone
// else minted for its subject); a rule never approves a request its own author
// makes; it applies only while its author may still approve; and its approval
// is one of the request's required approvals, reviewers giving the rest, unless
// the deployment lets a rule approve alone (pam.auto_approval_alone, off here).
func TestServedAutoApprovalRuleIsApprovalAuthorityCR001(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	const target = "cr001-pg"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, MaxTTL: time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: target, ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"}}},
		}
	})
	ctx := context.Background()
	// The control-plane database is shared by every served test: subjects are
	// unique to this run, and every rule it saves is deleted before it ends.
	run := strings.ToLower(uuid.NewString()[:8])
	subject := func(role string) string { return "cr001-" + role + "-" + run }
	admin := seedScopedTokenSubject(t, h.store, h.tenant, subject("admin"), "*")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, subject("approver"), "access:read", "access:write", "access:approve")
	// The requester persona: it may request privileged access, never approve it.
	requester := seedScopedTokenSubject(t, h.store, h.tenant, subject("requester"), "access:read", "access:write")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, subject("reviewer"), "access:approve")
	// A token the administrator minted for another subject (F262).
	delegated := seedHistoricalDelegatedToken(t, h.srv.orch, h.tenant, subject("admin"), subject("delegate"), []string{"access:read", "access:write", "access:approve"})

	var owned []string
	t.Cleanup(func() {
		for _, id := range owned {
			current, err := h.store.GetPAMAutoApprovalRule(context.Background(), h.tenant, id)
			if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
				continue
			}
			if err != nil {
				t.Errorf("read rule for cleanup: %v", err)
				continue
			}
			if status, raw := secretsReqKey(t, h, http.MethodDelete, fmt.Sprintf("/api/v1/access/auto-approval-rules/%s?revision=%d", id, current.Revision),
				admin, uuid.NewString(), nil); status != http.StatusOK {
				t.Errorf("cleanup rule %s = %d %s", id, status, raw)
			}
		}
	})
	rule := func(name string, enabled bool) map[string]any {
		return map[string]any{"name": name, "revision": 0, "applies_to": []string{"session", "checkout"}, "target_ids": []string{target},
			"max_ttl_seconds": 120, "enabled": enabled}
	}
	save := func(token, id string, body map[string]any) (int, []byte) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/auto-approval-rules/"+id, token, uuid.NewString(), body)
		if status == http.StatusOK {
			owned = append(owned, id)
		}
		return status, raw
	}
	ask := func(token, who string) api.PAMApprovalRequest {
		t.Helper()
		body := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": target, "role": "readonly",
			"reason": "cr001 review", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", token, uuid.NewString(), body)
		var out api.PAMApprovalRequest
		if status != http.StatusAccepted || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("%s session request = %d %s", who, status, raw)
		}
		return out
	}

	// An approver's rule for the target, the subject of every check below.
	ruleID := uuid.NewString()
	if status, raw := save(approver, ruleID, rule("cr001 approver rule", true)); status != http.StatusOK {
		t.Fatalf("an approver (access:read+access:write+access:approve) saves a rule = %d %s", status, raw)
	}

	t.Run("only a principal that may approve access changes a rule", func(t *testing.T) {
		if status, raw := save(requester, uuid.NewString(), rule("cr001 requester rule", true)); status != http.StatusForbidden {
			t.Errorf("the requester persona (access:read+access:write) saved a rule = %d %s, want 403", status, raw)
		}
		idle := uuid.NewString()
		if status, raw := save(approver, idle, rule("cr001 idle rule", false)); status != http.StatusOK {
			t.Fatalf("an approver saves a disabled rule = %d %s", status, raw)
		}
		if status, raw := secretsReqKey(t, h, http.MethodDelete, "/api/v1/access/auto-approval-rules/"+idle+"?revision=1", requester, uuid.NewString(), nil); status != http.StatusForbidden {
			t.Errorf("the requester persona deleted a rule = %d %s, want 403", status, raw)
		}
		if status, raw := save(delegated, uuid.NewString(), rule("cr001 delegated rule", true)); status != http.StatusForbidden || !bytes.Contains(raw, []byte("minted")) {
			t.Errorf("a token minted for its subject by someone else saved a rule = %d %s, want 403 naming the minted token", status, raw)
		}
	})

	t.Run("a rule never approves a request its author makes", func(t *testing.T) {
		own := ask(approver, "the rule's author")
		if own.Status != "pending" || own.ApprovalCount != 0 {
			t.Errorf("the rule approved its own author's request: status=%s approvals=%d/%d, want pending with no approval",
				own.Status, own.ApprovalCount, own.RequiredApprovals)
		}
	})

	t.Run("a rule's approval is one of the deployment's required approvals", func(t *testing.T) {
		got := ask(requester, "another requester")
		if got.Status != "pending" || got.ApprovalCount != 1 || got.RequiredApprovals != 2 {
			t.Fatalf("another requester's request under the approver's rule: status=%s approvals=%d/%d, want pending 1/2 (the rule's approval, then a reviewer's)",
				got.Status, got.ApprovalCount, got.RequiredApprovals)
		}
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+got.ApprovalRequestID+"/approvals", reviewer, uuid.NewString(),
			map[string]any{"intent_digest": got.IntentDigest}); status != http.StatusOK {
			t.Fatalf("a reviewer approves = %d %s", status, raw)
		}
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/access/session-requests/"+got.ApprovalRequestID, requester, nil)
		var progress api.PAMRequestProgress
		if status != http.StatusOK || json.Unmarshal(raw, &progress) != nil || progress.Status != "approved" || progress.ApprovalCount != 2 {
			t.Fatalf("progress after the rule's and a reviewer's approval = %d %s, want approved 2/2", status, raw)
		}
	})

	t.Run("a rule stops applying once its author may no longer approve", func(t *testing.T) {
		// Offboarding the author revokes its tokens and ends its membership.
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/members/"+subject("approver")+"/offboard", admin, uuid.NewString(),
			map[string]any{"reason": "cr001 author leaves"}); status != http.StatusOK {
			t.Fatalf("offboard the rule's author = %d %s", status, raw)
		}
		if got := ask(requester, "a requester after its author left"); got.Status != "pending" || got.ApprovalCount != 0 {
			t.Errorf("the rule kept approving after its author was offboarded: status=%s approvals=%d/%d", got.Status, got.ApprovalCount, got.RequiredApprovals)
		}
		// A member whose role grants access:approve saves a rule with its own token.
		member := subject("member")
		upsertMember(t, h.ts, admin, member, []string{"operator"})
		memberToken := seedScopedTokenSubject(t, h.store, h.tenant, member, "access:read", "access:write", "access:approve")
		if status, raw := save(memberToken, uuid.NewString(), rule("cr001 member rule", true)); status != http.StatusOK {
			t.Fatalf("a member approver saves a rule = %d %s", status, raw)
		}
		if got := ask(requester, "a requester under the member's rule"); got.ApprovalCount != 1 {
			t.Fatalf("the member's rule did not apply: status=%s approvals=%d/%d", got.Status, got.ApprovalCount, got.RequiredApprovals)
		}
		// Its token is revoked, but its member role still grants access:approve.
		tokens, err := h.store.ListAPITokensPage(ctx, h.tenant, store.ZeroUUID, member, false, 10)
		if err != nil || len(tokens) == 0 {
			t.Fatalf("list the member's tokens = %d, %v", len(tokens), err)
		}
		for _, tok := range tokens {
			if status, raw := secretsReqKey(t, h, http.MethodDelete, "/api/v1/access/api-tokens/"+tok.ID, admin, uuid.NewString(), nil); status != http.StatusNoContent {
				t.Fatalf("revoke the member's token = %d %s", status, raw)
			}
		}
		if got := ask(requester, "a requester after the member's token was revoked"); got.ApprovalCount != 1 {
			t.Errorf("the rule of a member whose role still grants access:approve stopped applying: status=%s approvals=%d/%d", got.Status, got.ApprovalCount, got.RequiredApprovals)
		}
		// Its role is lowered to one without access:approve.
		if status, raw := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/"+member, admin, "member-"+member+"-viewer",
			map[string]any{"display_name": member, "roles": []string{"viewer"}, "source": "manual"}); status != http.StatusOK {
			t.Fatalf("lower the member's role = %d %s", status, raw)
		}
		if got := ask(requester, "a requester after the member's role was lowered"); got.Status != "pending" || got.ApprovalCount != 0 {
			t.Errorf("the rule kept approving after its author's role lost access:approve: status=%s approvals=%d/%d", got.Status, got.ApprovalCount, got.RequiredApprovals)
		}
	})
}

// CR-001: a deployment may let a matching rule approve a request alone
// (pam.auto_approval_alone). The rule then approves another requester's
// request by itself, and still never a request its own author makes.
func TestServedAutoApprovalRuleApprovesAloneOnlyWhereTheDeploymentAllowsCR001(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	const target = "cr001-alone-pg"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, MaxTTL: time.Minute, AutoApprovalAlone: true, Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: target, ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"}}},
		}
	})
	run := strings.ToLower(uuid.NewString()[:8])
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "cr001-alone-approver-"+run, "access:read", "access:write", "access:approve")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "cr001-alone-requester-"+run, "access:read", "access:write")
	ruleID := uuid.NewString()
	t.Cleanup(func() {
		current, err := h.store.GetPAMAutoApprovalRule(context.Background(), h.tenant, ruleID)
		if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
			return
		}
		if err != nil {
			t.Errorf("read rule for cleanup: %v", err)
			return
		}
		if status, raw := secretsReqKey(t, h, http.MethodDelete, fmt.Sprintf("/api/v1/access/auto-approval-rules/%s?revision=%d", ruleID, current.Revision),
			approver, uuid.NewString(), nil); status != http.StatusOK {
			t.Errorf("cleanup rule = %d %s", status, raw)
		}
	})
	body := map[string]any{"name": "cr001 rule that approves alone", "revision": 0, "applies_to": []string{"session"}, "target_ids": []string{target},
		"max_ttl_seconds": 120, "enabled": true}
	if status, raw := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/auto-approval-rules/"+ruleID, approver, uuid.NewString(), body); status != http.StatusOK {
		t.Fatalf("an approver saves a rule = %d %s", status, raw)
	}
	ask := func(token, who string) api.PAMApprovalRequest {
		t.Helper()
		req := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": target, "role": "readonly",
			"reason": "cr001 review", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60}
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", token, uuid.NewString(), req)
		var out api.PAMApprovalRequest
		if status != http.StatusAccepted || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("%s session request = %d %s", who, status, raw)
		}
		return out
	}
	if got := ask(requester, "another requester"); got.Status != "approved" || got.ApprovalCount != 1 || got.RequiredApprovals != 1 {
		t.Errorf("where the deployment lets a rule approve alone, another requester's request = %s %d/%d, want approved 1/1",
			got.Status, got.ApprovalCount, got.RequiredApprovals)
	}
	if got := ask(approver, "the rule's author"); got.Status != "pending" || got.ApprovalCount != 0 || got.RequiredApprovals != 2 {
		t.Errorf("the rule approved its own author's request: %s %d/%d, want pending 0/2", got.Status, got.ApprovalCount, got.RequiredApprovals)
	}
}
