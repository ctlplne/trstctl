// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A46: reading a deployment target reports whether a rollback would find a
// predecessor to restore, with the reason it would not, so an operator learns
// a target is not rollable before an incident rather than from a refused
// rollback.
func TestServedConnectorTargetReportsRollbackReadiness(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	create := func(name, connector string, cfg map[string]any) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
			"name": name, "connector": connector, "config": cfg, "enabled": true,
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s target = %d %s", connector, status, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			t.Fatalf("decode target: %v %s", err, body)
		}
		return created.ID
	}
	readiness := func(id string) (model string, ready bool, reason string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+id, token, nil)
		if status != http.StatusOK {
			t.Fatalf("get target = %d %s", status, body)
		}
		var target struct {
			RollbackReadiness *struct {
				Model  string `json:"model"`
				Ready  bool   `json:"ready"`
				Reason string `json:"reason"`
			} `json:"rollback_readiness"`
		}
		if err := json.Unmarshal(body, &target); err != nil || target.RollbackReadiness == nil {
			t.Fatalf("target carries no rollback_readiness: %v %s", err, body)
		}
		return target.RollbackReadiness.Model, target.RollbackReadiness.Ready, target.RollbackReadiness.Reason
	}
	const agentID = "46460000-0000-4000-8000-000000000046"
	if err := h.store.UpsertAgent(t.Context(), store.Agent{ID: agentID, TenantID: h.tenant, Name: "a46-host", Status: "active", Roles: []string{mtls.AgentRoleHost}}); err != nil {
		t.Fatal(err)
	}
	host := create("a46-nginx", "nginx", map[string]any{
		"executor": "agent", "profile": "default", "cert_path": "/etc/nginx/a.crt", "key_path": "/etc/nginx/a.key",
		"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
	})
	if model, ready, reason := readiness(host); model != "host" || ready || reason == "" {
		t.Fatalf("host target before any deploy = %q %v %q; want host model, not ready, with a reason", model, ready, reason)
	}
	f5 := create("a46-f5", "f5", map[string]any{"endpoint": "https://bigip.example.test", "client_ssl_profile": "clientssl", "username": "trstctl", "password_ref": "secret://connectors/f5"})
	if model, ready, reason := readiness(f5); model != "re-bind" || ready || reason == "" {
		t.Fatalf("f5 target without a bound identity = %q %v %q; want re-bind model, not ready", model, ready, reason)
	}
	fortigate := create("a46-fgt", "fortigate", map[string]any{"endpoint": "https://fgt.example.test", "token_ref": "secret://connectors/fgt"})
	if model, ready, reason := readiness(fortigate); model != "re-bind" || ready || reason == "" {
		t.Fatalf("fortigate target without bind_to = %q %v %q; want not ready naming the binding", model, ready, reason)
	}
	// A122: a cisco target without its ISE node is a re-bind model that is
	// not ready and says why; one with the node and roles waits for an identity.
	cisco := create("a46-cisco", "cisco", map[string]any{"endpoint": "https://ios.example.test", "username": "trstctl", "password_ref": "secret://connectors/ios"})
	if model, ready, reason := readiness(cisco); model != "re-bind" || ready || !strings.Contains(reason, "node_hostname") {
		t.Fatalf("cisco target without an ISE node = %q %v %q; want not ready naming node_hostname", model, ready, reason)
	}
	ise := create("a46-ise", "cisco", map[string]any{"endpoint": "https://ise.example.test", "username": "trstctl",
		"password_ref": "secret://connectors/ise", "node_hostname": "ise-01", "certificate_roles": []string{"eap"}})
	if model, ready, reason := readiness(ise); model != "re-bind" || ready || strings.Contains(reason, "node_hostname") {
		t.Fatalf("cisco ISE target = %q %v %q; want re-bind waiting for an identity", model, ready, reason)
	}
}
