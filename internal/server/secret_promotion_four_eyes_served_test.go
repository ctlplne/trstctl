// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestServedPromotionIntoARestrictedEnvironmentNeedsFourEyesA236L1 is A236-L1
// over the served API. A promotion into a restricted environment writes
// nothing until other members who hold write there (the tenant's required
// number of distinct approvers, two by default) approve that exact plan. The answer names the request. The requester cannot approve it, a
// non-member neither sees nor decides it, and a viewer of the environment
// cannot decide it either. Once approved, the same apply writes the versions
// and consumes the approval, so the next plan needs a new one. A promotion
// into an open environment needs none.
func TestServedPromotionIntoARestrictedEnvironmentNeedsFourEyesA236L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-admin", "access:write", "secrets:read", "secrets:write")
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-alice", "secrets:read", "secrets:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-bob", "secrets:read", "secrets:write")
	carol := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-carol", "secrets:read", "secrets:write")
	dave := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-dave", "secrets:read", "secrets:write")
	erin := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1-erin", "secrets:read", "secrets:write")

	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	const project = "/api/v1/secrets/projects/pay236"
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "a236l1-project", map[string]any{"slug": "pay236", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "stage"}, map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	for member, grant := range map[string]map[string]any{
		"a236l1-alice": {"role": "developer"},
		"a236l1-bob":   {"role": "developer", "environments": []string{"prod"}},
		"a236l1-carol": {"role": "viewer", "environments": []string{"prod"}},
		"a236l1-erin":  {"role": "admin", "environments": []string{"prod"}},
	} {
		call(admin, http.MethodPut, project+"/members/"+member, "a236l1-grant-"+member, grant, http.StatusOK)
	}
	call(alice, http.MethodPost, "/api/v1/secrets/store", "a236l1-dev-v1", map[string]any{"name": "pay236/dev/db/password", "value": "dev-v1"}, http.StatusCreated)

	plan := func(to string) string {
		t.Helper()
		var preview struct {
			PlanDigest string `json:"plan_digest"`
		}
		if err := json.Unmarshal(call(alice, http.MethodPost, project+"/promotions/preview", "", map[string]any{"from": "dev", "to": to}, http.StatusOK), &preview); err != nil || preview.PlanDigest == "" {
			t.Fatalf("preview dev into %s: %v", to, err)
		}
		return preview.PlanDigest
	}
	pending := regexp.MustCompile(`approval_required:pay236/prod request_id=([0-9a-f-]{36}) intent_digest=(sha256:[0-9a-f]{64})`)
	apply := func(digest, key string) (int, string) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, project+"/promotions", alice, key, map[string]any{"from": "dev", "to": "prod", "plan_digest": digest})
		return status, string(raw)
	}

	// The first apply writes nothing and names the request.
	digest := plan("prod")
	status, raw := apply(digest, "a236l1-apply-1")
	match := pending.FindStringSubmatch(raw)
	if status != http.StatusForbidden || match == nil {
		t.Fatalf("a promotion into prod applied without approval: HTTP %d %s", status, raw)
	}
	requestID, intent := match[1], match[2]
	call(alice, http.MethodGet, "/api/v1/secrets/store/pay236/prod/db/password", "", nil, http.StatusNotFound)

	listed := func(tok string) []string {
		t.Helper()
		var out struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(call(tok, http.MethodGet, "/api/v1/approval-requests", "", nil, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, item := range out.Items {
			ids = append(ids, item.ID)
		}
		return ids
	}
	if !slices.Contains(listed(bob), requestID) {
		t.Fatal("prod's developer does not see the promotion's approval request")
	}
	if slices.Contains(listed(dave), requestID) {
		t.Fatal("a member not granted prod sees the promotion's approval request")
	}
	decide := func(tok, key string) (int, string) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", tok, key,
			map[string]any{"intent_digest": intent, "reason": "reviewed the plan"})
		return status, string(raw)
	}
	for who, tok := range map[string]string{"the requester": alice, "a non-member": dave, "prod's viewer": carol} {
		if status, raw := decide(tok, "a236l1-decide-"+who); status == http.StatusOK {
			t.Fatalf("%s approved the promotion: %s", who, raw)
		}
	}
	// The tenant requires two distinct approvers (the default); both hold
	// write in prod.
	if status, raw := decide(bob, "a236l1-decide-bob"); status != http.StatusOK {
		t.Fatalf("prod's developer could not approve: HTTP %d %s", status, raw)
	}
	if status, raw := apply(digest, "a236l1-apply-1"); status != http.StatusForbidden || pending.FindStringSubmatch(raw) == nil {
		t.Fatalf("one approval of two let the promotion apply: HTTP %d %s", status, raw)
	}
	if status, raw := decide(erin, "a236l1-decide-erin"); status != http.StatusOK {
		t.Fatalf("prod's admin could not approve: HTTP %d %s", status, raw)
	}

	// Approved: the same apply writes prod and consumes the approval.
	if status, raw := apply(digest, "a236l1-apply-1"); status != http.StatusCreated {
		t.Fatalf("the approved promotion: HTTP %d %s", status, raw)
	}
	var promoted struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(call(alice, http.MethodGet, "/api/v1/secrets/store/pay236/prod/db/password", "", nil, http.StatusOK), &promoted); err != nil || promoted.Value != "dev-v1" {
		t.Fatalf("prod after the approved promotion = %q, %v", promoted.Value, err)
	}
	var records struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(bob, http.MethodGet, "/api/v1/approval-requests", "", nil, http.StatusOK), &records); err != nil {
		t.Fatal(err)
	}
	consumed := false
	for _, item := range records.Items {
		consumed = consumed || (item.ID == requestID && item.Status == "consumed")
	}
	if !consumed {
		t.Fatalf("the approval after the promotion is not consumed: %+v", records.Items)
	}

	// The next plan needs its own approval.
	call(alice, http.MethodPut, "/api/v1/secrets/store/pay236/dev/db/password", "a236l1-dev-v2", map[string]any{"value": "dev-v2"}, http.StatusOK)
	status, raw = apply(plan("prod"), "a236l1-apply-2")
	if next := pending.FindStringSubmatch(raw); status != http.StatusForbidden || next == nil || next[1] == requestID {
		t.Fatalf("the next promotion into prod: HTTP %d %s, want a new approval request", status, raw)
	}

	// An open environment needs no approval.
	call(alice, http.MethodPost, project+"/promotions", "a236l1-stage", map[string]any{"from": "dev", "to": "stage", "plan_digest": plan("stage")}, http.StatusCreated)
	t.Logf("A236L1_FOUR_EYES_OK request=%s", requestID)
}

// TestServedRestrictedSecretApprovalsKeepToTheEnvironmentA236L1: with dual
// control on, the approval request for a change to a restricted environment's
// secret is listed to, and decided on the generic approval route by, only the
// members who hold write there. Before, any secrets:write holder saw the
// secret's name and could approve it on that route, though the secret's own
// approval route refused.
func TestServedRestrictedSecretApprovalsKeepToTheEnvironmentA236L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1b-admin", "access:write", "secrets:read", "secrets:write")
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1b-alice", "secrets:read", "secrets:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1b-bob", "secrets:read", "secrets:write")
	dave := seedScopedTokenSubject(t, h.store, h.tenant, "a236l1b-dave", "secrets:read", "secrets:write")
	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "a236l1b-project", map[string]any{"slug": "pay237", "environments": []any{
		map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	for _, member := range []string{"a236l1b-alice", "a236l1b-bob"} {
		call(admin, http.MethodPut, "/api/v1/secrets/projects/pay237/members/"+member, "a236l1b-grant-"+member,
			map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	}
	call(alice, http.MethodPost, "/api/v1/secrets/store", "a236l1b-create", map[string]any{"name": "pay237/prod/db", "value": "v1"}, http.StatusCreated)
	status, raw := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/pay237/prod/db", alice, "a236l1b-rotate", map[string]any{"value": "v2"})
	match := regexp.MustCompile(`request_id=([0-9a-f-]{36}) intent_digest=(sha256:[0-9a-f]{64})`).FindStringSubmatch(string(raw))
	if status != http.StatusForbidden || match == nil {
		t.Fatalf("a dual-controlled rotation of a prod secret: HTTP %d %s", status, raw)
	}
	requestID, intent := match[1], match[2]
	listed := func(tok string) bool {
		t.Helper()
		var out struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(call(tok, http.MethodGet, "/api/v1/approval-requests", "", nil, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		for _, item := range out.Items {
			if item.ID == requestID {
				return true
			}
		}
		return false
	}
	if listed(dave) {
		t.Fatal("a member not granted prod sees the prod secret's approval request")
	}
	if !listed(bob) {
		t.Fatal("prod's developer does not see the prod secret's approval request")
	}
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", dave, "a236l1b-dave",
		map[string]any{"intent_digest": intent, "reason": "not mine to approve"}); status != http.StatusForbidden {
		t.Fatalf("a non-member approved the prod secret's rotation on the generic route: HTTP %d %s", status, raw)
	}
	call(bob, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", "a236l1b-bob", map[string]any{"intent_digest": intent, "reason": "reviewed"}, http.StatusOK)
	call(alice, http.MethodPut, "/api/v1/secrets/store/pay237/prod/db", "a236l1b-rotate", map[string]any{"value": "v2"}, http.StatusOK)
	t.Log("A236L1_RESTRICTED_SECRET_APPROVALS_OK")
}
