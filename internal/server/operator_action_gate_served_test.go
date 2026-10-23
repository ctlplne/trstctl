// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// operatorGateAction is one operator action that revokes (or rotates) an
// identity outside the identity transition route.
type operatorGateAction struct {
	name   string
	scopes []string // the route's own permission
	run    func(t *testing.T, h *servedHarness, token, key, identityID string) (int, []byte)
}

var operatorGateActions = []operatorGateAction{
	{"identity-revoke", []string{"incidents:write"}, func(t *testing.T, h *servedHarness, token, key, identityID string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/remediation/playbooks/identity-revoke/runs", token, key,
			map[string]any{"target_identity_id": identityID, "reason": "credential exposed in a build log"})
	}},
	{"credential-rotate", []string{"incidents:write"}, func(t *testing.T, h *servedHarness, token, key, identityID string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/remediation/playbooks/credential-rotate/runs", token, key,
			map[string]any{"target_identity_id": identityID, "reason": "credential exposed in a build log"})
	}},
	{"nhi-decommission", []string{"identities:write"}, func(t *testing.T, h *servedHarness, token, key, identityID string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/decommission", token, key, map[string]any{
			"reason": "owner departed", "signals": []map[string]any{{"type": "departure", "identity_id": identityID}},
		})
	}},
}

// The identity-revoke and credential-rotate playbooks and NHI decommission
// used to call the orchestrator directly, skipping the privileged scope,
// policy and dual-control checks the identity's own revoke and issue take
// (security backlog, 2026-10-23). These tests drive the assembled HTTP handler.
func TestServedOperatorActionsCannotBypassLifecycleGate(t *testing.T) {
	for _, action := range operatorGateActions {
		for _, mode := range []string{"missing_privileged_scope", "policy_denial", "approval_required"} {
			t.Run(action.name+"/"+mode, func(t *testing.T) {
				h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
					if mode == "policy_denial" {
						d.EnablePolicyGate = true
						d.PolicyModule = "package trstctl.policy\ndefault allow := false\n"
					}
					d.RequireApproval = mode == "approval_required"
				})
				identity := operatorGateIdentity(t, h, action.name)
				scopes := append([]string(nil), action.scopes...)
				if mode != "missing_privileged_scope" {
					scopes = append(scopes, "certs:issue")
				}
				token := seedScopedToken(t, h.store, h.tenant, scopes...)
				identitiesBefore, outboxBefore := operatorGateIdentityCount(t, h), bulkRevocationOutboxCount(t, h)

				status, body := action.run(t, h, token, "operator-gate-denied", identity.ID)
				refusal := string(body)
				if action.name == "nhi-decommission" {
					// Decommission is a batch: each identity reports its own outcome.
					var resp struct {
						Summary struct{ Refused, Revoked int }
						Items   []struct{ Action, Error string }
					}
					if status != http.StatusOK || json.Unmarshal(body, &resp) != nil || resp.Summary.Refused != 1 ||
						resp.Summary.Revoked != 0 || len(resp.Items) != 1 || resp.Items[0].Action != "refused" {
						t.Fatalf("decommission bypassed %s: HTTP %d body=%s; want the identity refused", mode, status, body)
					}
					refusal = resp.Items[0].Error
				} else if status != http.StatusForbidden {
					t.Fatalf("%s bypassed %s: HTTP %d body=%s; want 403", action.name, mode, status, body)
				}
				if mode == "approval_required" && !strings.Contains(refusal, "POST /api/v1/identities/{id}/transitions") {
					t.Fatalf("dual-control refusal does not name the route that carries an approval: %s", refusal)
				}
				after, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
				if err != nil || after.Status != string(orchestrator.StateIssued) {
					t.Fatalf("refused %s changed the identity: status=%s error=%v", action.name, after.Status, err)
				}
				if got := operatorGateIdentityCount(t, h); got != identitiesBefore {
					t.Fatalf("refused %s created %d identities", action.name, got-identitiesBefore)
				}
				if got := bulkRevocationOutboxCount(t, h); got != outboxBefore {
					t.Fatalf("refused %s created a revocation effect: before=%d after=%d", action.name, outboxBefore, got)
				}
			})
		}
	}
}

// With the privileged scope, a permitting policy and no dual control, the
// same actions still do their work.
func TestServedOperatorActionsPassTheGateWhenAuthorized(t *testing.T) {
	for _, action := range operatorGateActions {
		t.Run(action.name, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{})
			identity := operatorGateIdentity(t, h, action.name)
			token := seedScopedToken(t, h.store, h.tenant, append(append([]string(nil), action.scopes...), "certs:issue")...)
			status, body := action.run(t, h, token, "operator-gate-allowed", identity.ID)
			if status != http.StatusCreated && status != http.StatusOK {
				t.Fatalf("authorized %s = HTTP %d body=%s", action.name, status, body)
			}
			after, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
			if err != nil || after.Status != string(orchestrator.StateRevoked) {
				t.Fatalf("authorized %s left status=%s error=%v body=%s", action.name, after.Status, err, body)
			}
		})
	}
}

func operatorGateIdentity(t *testing.T, h *servedHarness, name string) store.Identity {
	t.Helper()
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "team", "operator-gate-"+name, "lab@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: name + ".operator-gate.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Event-sourced fixture setup is independent of the gated public action.
	if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
		t.Fatal(err)
	}
	return identity
}

func operatorGateIdentityCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM identities WHERE tenant_id = $1`, h.tenant).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
