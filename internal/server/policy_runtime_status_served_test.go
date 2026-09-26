// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestServedPolicyRuntimeStatusReflectsDeployment(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) { d.EnablePolicyGate = enabled })
			registerServedTenant(t, h, "Policy runtime fixture")
			token := seedScopedTokenSubject(t, h.store, h.tenant, "policy-status-reviewer", "policy:read", "policy:write", "capabilities:read")
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/policy/versions", token, nil)
			if status != http.StatusOK {
				t.Fatalf("list: %d %s", status, raw)
			}
			var got struct {
				Enforcement *struct {
					Enabled bool   `json:"enabled"`
					Hash    string `json:"module_sha256"`
				} `json:"enforcement"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Enforcement == nil || got.Enforcement.Enabled != enabled || (got.Enforcement.Hash != "") != enabled {
				t.Fatalf("runtime posture: %s", raw)
			}
			status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/capabilities", token, nil)
			if status != http.StatusOK {
				t.Fatalf("capabilities: %d %s", status, raw)
			}
			var caps struct {
				Operations []struct {
					ID    string `json:"operation_id"`
					State string `json:"state"`
					Code  string `json:"code"`
				} `json:"operations"`
			}
			if err := json.Unmarshal(raw, &caps); err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, op := range caps.Operations {
				switch op.ID {
				case "createPolicyVersion", "activatePolicyVersion", "rollbackPolicyVersion":
					found++
					if enabled && op.State != "allowed" {
						t.Errorf("configured %s: %+v", op.ID, op)
					}
					if !enabled && op.Code != "dependency_not_configured" {
						t.Errorf("disabled %s: %+v", op.ID, op)
					}
				}
			}
			if found != 3 {
				t.Fatalf("missing policy operations: %d", found)
			}
		})
	}
}
