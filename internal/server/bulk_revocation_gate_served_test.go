// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestServedBulkRevocationPermitsAuthorizedIdentityAndBindsRetries(t *testing.T) {
	for _, path := range []string{"/api/v1/identities/bulk-revoke", "/api/v1/certificates/bulk-revoke"} {
		t.Run(path, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.EnablePolicyGate = true // the real base policy permits revocation
			})
			owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "team", "authorized-bulk-lab", "lab@example.test")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
				Kind: store.KindX509Certificate, Name: "authorized-bulk.example.test", OwnerID: owner.ID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
				t.Fatal(err)
			}
			token := seedScopedToken(t, h.store, h.tenant, "identities:write", "certs:issue")
			request := map[string]any{"identity_ids": []string{identity.ID}, "reason": "cessationOfOperation"}
			status, first := secretsReqKey(t, h, http.MethodPost, path, token, "authorized-bulk-command", request)
			if status != http.StatusOK || !bytes.Contains(first, []byte(`"total_revoked":1`)) {
				t.Fatalf("authorized bulk revoke failed: HTTP %d body=%s", status, first)
			}
			status, replay := secretsReqKey(t, h, http.MethodPost, path, token, "authorized-bulk-command", request)
			if status != http.StatusOK || !bytes.Equal(first, replay) {
				t.Fatalf("same command did not replay the original result: HTTP %d body=%s", status, replay)
			}
			request["reason"] = "keyCompromise"
			status, _ = secretsReqKey(t, h, http.MethodPost, path, token, "authorized-bulk-command", request)
			if status != http.StatusConflict {
				t.Fatalf("changed reason reused the original command: HTTP %d", status)
			}
			if got := bulkRevocationOutboxCount(t, h); got != 1 {
				t.Fatalf("one authorized request produced %d revocation outbox intents", got)
			}
		})
	}
}

// Both public aliases used to call the orchestrator directly, bypassing the
// privileged scope, policy and exact-approval checks on an individual revoke.
// These tests drive the assembled HTTP handler, not a gate helper.
func TestServedBulkRevocationCannotBypassLifecycleGate(t *testing.T) {
	for _, path := range []string{"/api/v1/identities/bulk-revoke", "/api/v1/certificates/bulk-revoke"} {
		for _, mode := range []string{"missing_privileged_scope", "policy_denial", "approval_required"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
					if mode == "policy_denial" {
						d.EnablePolicyGate = true
						d.PolicyModule = "package trstctl.policy\ndefault allow := false\n"
					}
					d.RequireApproval = mode == "approval_required"
				})
				owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "team", "bulk-revocation-lab", "lab@example.test")
				if err != nil {
					t.Fatal(err)
				}
				identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
					Kind: store.KindX509Certificate, Name: "bulk-revocation.example.test", OwnerID: owner.ID,
				})
				if err != nil {
					t.Fatal(err)
				}
				// Event-sourced fixture setup is independent of the denied public
				// action. Do not weaken the served gate to create the fixture.
				if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
					t.Fatal(err)
				}
				scopes := []string{"identities:write"}
				if mode != "missing_privileged_scope" {
					scopes = append(scopes, "certs:issue")
				}
				token := seedScopedToken(t, h.store, h.tenant, scopes...)
				before := bulkRevocationOutboxCount(t, h)
				status, body := secretsReqKey(t, h, http.MethodPost, path, token, "bulk-gate-denied", map[string]any{
					"identity_ids": []string{identity.ID}, "reason": "keyCompromise",
				})
				if status != http.StatusForbidden {
					t.Fatalf("bulk revoke bypassed %s: HTTP %d body=%s; want 403", mode, status, body)
				}
				after, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
				if err != nil || after.Status != string(orchestrator.StateIssued) {
					t.Fatalf("denied bulk revoke changed identity: status=%s error=%v", after.Status, err)
				}
				if got := bulkRevocationOutboxCount(t, h); got != before {
					t.Fatalf("denied bulk revoke created an external effect: before=%d after=%d", before, got)
				}
			})
		}
	}
}

func bulkRevocationOutboxCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'revocation.publish'`,
		h.tenant).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
