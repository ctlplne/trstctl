// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestEndpointPreviewValidatesCertificateProfileMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, protocol, denial string
	}{
		{"allowed", "partner-lab.example.com", "api", ""},
		{"wrong hostname", "mail.partner-lab.example.com", "api", "DNS SAN"},
		{"wrong protocol", "partner-lab.example.com", "acme", "enrollment protocol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.DefaultProfile = "endpoint-metadata" })
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "profiles:write", "connectors:write", "certs:issue")
			create := func(path string, request any) string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, path, token, request)
				if code != http.StatusCreated {
					t.Fatalf("create %s: %d %s", path, code, body)
				}
				var result struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatal(err)
				}
				return result.ID
			}
			create("/api/v1/profiles", map[string]any{"name": "endpoint-metadata", "spec": map[string]any{
				"max_validity": "12m", "allowed_protocols": []string{tc.protocol},
				"allowed_dns_suffixes": []string{tc.suffix}, "allowed_key_algorithms": []string{"ECDSA"},
			}})
			owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "Java application"})
			// Policy admission applies before connector-specific key packaging.
			// Use a file destination so this test needs no credential fixture.
			target := create("/api/v1/connectors/targets", map[string]any{
				"name": "Application TLS", "connector": "nginx", "enabled": true,
				"config": map[string]any{"executor": "agent", "required_agent_role": "host",
					"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key",
					"verify_address": "127.0.0.1:8443", "verify_server_name": "java.partner-lab.example.com"},
			})
			request := map[string]any{"owner_id": owner, "identity_name": "java.partner-lab.example.com", "target_id": target,
				"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "review exact profile"}
			code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
			if tc.denial == "" {
				if code != http.StatusOK {
					t.Fatalf("allowed preview: %d %s", code, body)
				}
			} else {
				if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.denial) {
					t.Fatalf("preview must refuse %s before issuance: %d %s", tc.denial, code, body)
				}
				request["preview_fingerprint"] = strings.Repeat("0", 64)
				code, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, request)
				if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.denial) {
					t.Fatalf("direct execution must also refuse %s: %d %s", tc.denial, code, body)
				}
			}
			if _, found, err := h.store.FindIdentityByName(context.Background(), h.tenant, "java.partner-lab.example.com"); err != nil || found {
				t.Fatalf("preview/refusal created an identity: found=%v err=%v", found, err)
			}
			pending, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range pending {
				if entry.Destination == "ca.issue" || entry.Destination == "endpoint.renew" {
					t.Fatalf("preview/refusal queued issuance: %+v", entry.ID)
				}
			}
		})
	}
}
