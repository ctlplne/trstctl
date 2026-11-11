// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedApprovedScopedSyncConvergesOnlyWithApprovalA237L1 is A237-L1's
// approval-gated convergence over the served API.
//   - An approved definition's sources change and the reconciler plans it like
//     an auto one, but writes nothing. It records that the plan awaits an
//     approval request, which the definition's author asks for.
//   - The author cannot approve. The other members who write in the source's
//     restricted environment can (the tenant's required number, two here). A
//     member not granted the environment neither sees nor decides it.
//   - Once approved, the next pass applies that exact plan to the destination
//     and the request reads consumed.
//   - A manual apply of the next plan waits for its own approval.
//   - Leaving the approved mode, or removing the definition, needs
//     access:write.
func TestServedApprovedScopedSyncConvergesOnlyWithApprovalA237L1(t *testing.T) {
	const token = "a237l1-kv-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	emulator := newScopedKVEmulator(t, token)
	pusher, err := secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: []byte(token), Mount: "kv", PathPrefix: "apps",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pusher.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {"kv": secretsync.NewTarget("kv", pusher)}}
	})
	registerServedTenant(t, h, "A237-L1 approval-gated sync tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a237l1-admin", "access:write", "secrets:read", "secrets:write")
	author := seedScopedTokenSubject(t, h.store, h.tenant, "a237l1-author", "secrets:read", "secrets:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "a237l1-bob", "secrets:read", "secrets:write")
	erin := seedScopedTokenSubject(t, h.store, h.tenant, "a237l1-erin", "secrets:read", "secrets:write")
	dave := seedScopedTokenSubject(t, h.store, h.tenant, "a237l1-dave", "secrets:read", "secrets:write")

	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "a237l1-project", map[string]any{"slug": "sync237", "environments": []any{
		map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	for _, member := range []string{"a237l1-author", "a237l1-bob", "a237l1-erin"} {
		call(admin, http.MethodPut, "/api/v1/secrets/projects/sync237/members/"+member, "a237l1-grant-"+member,
			map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	}
	call(author, http.MethodPost, "/api/v1/secrets/store", "a237l1-a1", map[string]any{"name": "sync237/prod/a", "value": "a-one"}, http.StatusCreated)
	var defined struct {
		ID   string `json:"id"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(call(author, http.MethodPost, "/api/v1/secrets/scoped-syncs", "a237l1-define", map[string]any{
		"name": "sync237-approved", "source_prefix": "sync237/prod/", "target": "kv", "destination_prefix": "sync237", "mode": "approved",
	}, http.StatusCreated), &defined); err != nil || defined.Mode != "approved" {
		t.Fatalf("define an approved scoped sync: %+v %v", defined, err)
	}
	sync := "/api/v1/secrets/scoped-syncs/" + defined.ID
	drain := func() {
		t.Helper()
		for range 3 {
			head, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE projection_checkpoint SET applied_seq = GREATEST(applied_seq, $1), updated_at = now() WHERE id = 1`, head); err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.SystemPool().Exec(t.Context(),
				`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			_ = h.srv.Drain(ctx)
			cancel()
		}
	}
	reconcile := func() int {
		t.Helper()
		n, err := h.srv.ReconcileScopedSyncsOnce(t.Context())
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		return n
	}
	type view struct {
		Mode            string `json:"mode"`
		ReconcileStatus string `json:"reconcile_status"`
		ReconcileReason string `json:"reconcile_reason"`
	}
	show := func() view {
		t.Helper()
		var v view
		if err := json.Unmarshal(call(author, http.MethodGet, sync, "", nil, http.StatusOK), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	type request struct {
		ID           string `json:"id"`
		IntentDigest string `json:"intent_digest"`
		Status       string `json:"status"`
		ResourceID   string `json:"resource_id"`
	}
	requests := func(tok string) []request {
		t.Helper()
		var out struct {
			Items []request `json:"items"`
		}
		if err := json.Unmarshal(call(tok, http.MethodGet, "/api/v1/approval-requests", "", nil, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		return slices.DeleteFunc(out.Items, func(r request) bool { return r.ResourceID != defined.ID })
	}

	// The sources changed: the reconciler plans, writes nothing, and waits.
	if n := reconcile(); n != 0 {
		t.Fatalf("an approved definition applied %d plans without approval", n)
	}
	drain()
	if _, ok := emulator.raw("sync237/a"); ok {
		t.Fatal("the destination was written before approval")
	}
	waiting := show()
	if waiting.ReconcileStatus != "awaiting_approval" {
		t.Fatalf("the approved definition after the first pass = %+v", waiting)
	}
	pending := requests(bob)
	if len(pending) != 1 || pending[0].Status != "pending" || !strings.Contains(waiting.ReconcileReason, pending[0].ID) {
		t.Fatalf("the plan's approval request = %+v, reconcile %+v", pending, waiting)
	}
	if len(requests(dave)) != 0 {
		t.Fatal("a member not granted prod sees the sync's approval request")
	}
	decide := func(tok, key string) (int, string) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+pending[0].ID+"/approvals", tok, key,
			map[string]any{"intent_digest": pending[0].IntentDigest, "reason": "reviewed the plan"})
		return status, string(raw)
	}
	for who, tok := range map[string]string{"the author": author, "a non-member": dave} {
		if status, raw := decide(tok, "a237l1-decide-"+who); status == http.StatusOK {
			t.Fatalf("%s approved the sync's plan: %s", who, raw)
		}
	}
	if status, raw := decide(bob, "a237l1-decide-bob"); status != http.StatusOK {
		t.Fatalf("a prod developer could not approve: HTTP %d %s", status, raw)
	}
	if n := reconcile(); n != 0 {
		t.Fatalf("one approval of two applied the plan (%d)", n)
	}
	if status, raw := decide(erin, "a237l1-decide-erin"); status != http.StatusOK {
		t.Fatalf("the second prod developer could not approve: HTTP %d %s", status, raw)
	}

	// Approved: the next pass applies that exact plan.
	if n := reconcile(); n != 1 {
		t.Fatalf("the approved plan applied %d times, want 1", n)
	}
	drain()
	if v, _ := emulator.raw("sync237/a"); v != "a-one" {
		t.Fatalf("the destination after the approved apply = %q", v)
	}
	if v := show(); v.ReconcileStatus != "applied" {
		t.Fatalf("after the approved apply: %+v", v)
	}
	if got := requests(bob); len(got) != 1 || got[0].Status != "consumed" {
		t.Fatalf("the approval after the apply = %+v", got)
	}

	// A manual apply of the next plan waits for its own approval.
	call(author, http.MethodPut, "/api/v1/secrets/store/sync237/prod/a", "a237l1-a2", map[string]any{"value": "a-two"}, http.StatusOK)
	var plan struct {
		PlanDigest string `json:"plan_digest"`
	}
	if err := json.Unmarshal(call(author, http.MethodPost, sync+"/preview", "", nil, http.StatusOK), &plan); err != nil {
		t.Fatal(err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, sync+"/apply", bob, "a237l1-manual-apply", map[string]any{"plan_digest": plan.PlanDigest})
	if status != http.StatusForbidden || !regexp.MustCompile(`approval_required:`+defined.ID+` request_id=`).Match(raw) {
		t.Fatalf("a manual apply of an approved definition: HTTP %d %s", status, raw)
	}
	if v, _ := emulator.raw("sync237/a"); v != "a-one" {
		t.Fatalf("the destination changed without approval: %q", v)
	}

	// Leaving the gate, or removing the definition, is the administrator's.
	call(author, http.MethodPut, sync+"/mode", "a237l1-ungate", map[string]any{"mode": "manual"}, http.StatusForbidden)
	call(author, http.MethodDelete, sync, "a237l1-remove", nil, http.StatusForbidden)
	call(admin, http.MethodPut, sync+"/mode", "a237l1-ungate-admin", map[string]any{"mode": "manual"}, http.StatusOK)
	// Entering the gate is anyone's who may write; it projects like any mode.
	var regated struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(call(author, http.MethodPut, sync+"/mode", "a237l1-regate", map[string]any{"mode": "approved"}, http.StatusOK), &regated); err != nil || regated.Mode != "approved" {
		t.Fatalf("switching a manual sync to approved = %+v, %v", regated, err)
	}
	t.Logf("A237L1_APPROVED_CONVERGENCE_OK request=%s", pending[0].ID)
}
