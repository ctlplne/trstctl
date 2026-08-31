// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedBrokerCapabilityUsesRunningServiceNotWrapperPresence(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled-without-tenant-trust"}[enabled], func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.AgentBroker = AgentBrokerConfig{Enabled: enabled, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
			})
			token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "capabilities:read")
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/capabilities", token, nil)
			var result struct {
				Operations []struct {
					ID    string `json:"operation_id"`
					State string `json:"state"`
					Code  string `json:"code"`
				} `json:"operations"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &result) != nil {
				t.Fatalf("capabilities status=%d", status)
			}
			found := 0
			for _, operation := range result.Operations {
				if operation.ID != "previewBrokerAgentIdentity" && operation.ID != "issueBrokerAgentIdentity" {
					continue
				}
				found++
				if enabled {
					if operation.State != "allowed" && operation.State != "scoped" {
						t.Fatalf("configured broker marked unavailable: %+v", operation)
					}
				} else if operation.State != "unavailable" || operation.Code != "dependency_not_configured" {
					t.Fatalf("disabled broker advertised runnable because its wrapper exists: %+v", operation)
				}
			}
			if found != 2 {
				t.Fatalf("found %d broker operations, want preview and issue", found)
			}
		})
	}
}
