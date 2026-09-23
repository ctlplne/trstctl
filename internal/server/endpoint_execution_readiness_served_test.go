// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

// This test file uses only pre-repair APIs, so baseline failures must be
// behavioral refusals, not missing-symbol compilation failures.
func TestEndpointEnrollmentRequiresRunnableHostIssuance(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		channel  bool
		kinds    []string
		ready    bool
		withdraw bool
	}{
		{name: "channel missing", kinds: []string{"endpoint.renew"}},
		{name: "deployment alone does not allow issuance", channel: true, kinds: []string{"connector.deploy"}},
		{name: "empty allowlist", channel: true},
		{name: "control-plane kind is not host authority", channel: true, kinds: []string{"ca.issue"}},
		{name: "host issuance enabled", channel: true, kinds: []string{"endpoint.renew"}, ready: true},
		{name: "channel withdrawn after review", channel: true, kinds: []string{"endpoint.renew"}, ready: true, withdraw: true},
	} {
		for _, operation := range []string{"preview", "execute"} {
			t.Run(scenario.name+"/"+operation, func(t *testing.T) {
				h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
					if scenario.channel {
						withAgentChannel(d)
					}
					d.AgentClaimableJobKinds = scenario.kinds
				})
				registerServedTenant(t, h, "endpoint execution readiness")
				token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue")
				create := func(path string, input any) string {
					t.Helper()
					code, body := secretsReq(t, h, http.MethodPost, path, token, input)
					if code != http.StatusCreated {
						t.Fatalf("create %s: %d %s", path, code, body)
					}
					var item struct {
						ID string `json:"id"`
					}
					if err := json.Unmarshal(body, &item); err != nil {
						t.Fatal(err)
					}
					return item.ID
				}
				owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "Host lifecycle owner"})
				target := create("/api/v1/connectors/targets", map[string]any{
					"name": "Host lifecycle", "connector": "nginx", "enabled": true,
					"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
						"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "readiness.example.test"},
				})
				request := map[string]any{"owner_id": owner, "identity_name": "readiness.example.test", "target_id": target,
					"issuer": map[string]string{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "review real host execution prerequisites"}
				head, err := h.log.LastSequence(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				path := "/api/v1/lifecycle/endpoint-bindings/preview"
				want := http.StatusOK
				if operation == "execute" {
					path = "/api/v1/lifecycle/endpoint-bindings"
					request["preview_fingerprint"] = strings.Repeat("0", 64)
					if scenario.ready {
						code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
						if code != http.StatusOK {
							t.Fatalf("ready review: %d %s", code, body)
						}
						var preview struct {
							Fingerprint string `json:"request_fingerprint"`
						}
						if err := json.Unmarshal(body, &preview); err != nil {
							t.Fatal(err)
						}
						request["preview_fingerprint"] = preview.Fingerprint
					}
					want = http.StatusCreated
				}
				if scenario.withdraw {
					if operation == "preview" {
						code, body := secretsReq(t, h, http.MethodPost, path, token, request)
						if code != http.StatusOK {
							t.Fatalf("initial preview: %d %s", code, body)
						}
					}
					// Requests are sequential and this fixture never starts the gRPC
					// listener. Model loss of the mounted service, not an allowlist
					// mutation racing with a background claim.
					service := h.srv.agentSvc
					h.srv.agentSvc = nil
					t.Cleanup(func() { h.srv.agentSvc = service })
				}
				readyNow := scenario.ready && !scenario.withdraw
				if !readyNow {
					want = http.StatusServiceUnavailable
				}
				code, body := secretsReqKey(t, h, http.MethodPost, path, token, "host-readiness", request)
				if code != want {
					t.Fatalf("%s readiness: want %d got %d %s", operation, want, code, body)
				}
				if !readyNow && !strings.Contains(string(body), "endpoint.renew") {
					t.Fatalf("missing exact disabled kind: %s", body)
				}
				if readyNow && operation == "execute" {
					acceptedHead, err := h.log.LastSequence(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					service := h.srv.agentSvc
					h.srv.agentSvc = nil
					t.Cleanup(func() { h.srv.agentSvc = service })
					replayCode, replayBody := secretsReqKey(t, h, http.MethodPost, path, token, "host-readiness", request)
					if replayCode != code || !bytes.Equal(replayBody, body) {
						t.Fatalf("accepted result was not replayed after channel loss: %d %s", replayCode, replayBody)
					}
					after, err := h.log.LastSequence(t.Context())
					if err != nil || after != acceptedHead {
						t.Fatalf("accepted replay changed lifecycle events: %d -> %d %v", acceptedHead, after, err)
					}
				}
				if !readyNow || operation == "preview" {
					after, err := h.log.LastSequence(t.Context())
					if err != nil || after != head {
						t.Fatalf("refusal/preview changed events: %d -> %d %v", head, after, err)
					}
					if _, found, err := h.store.FindIdentityByName(t.Context(), h.tenant, "readiness.example.test"); err != nil || found {
						t.Fatalf("refusal/preview created identity: %v %v", found, err)
					}
					rows, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range rows {
						if row.Destination == "ca.issue" || row.Destination == "endpoint.renew" {
							t.Fatalf("refusal/preview queued %s", row.Destination)
						}
					}
				}
			})
		}
	}
}
