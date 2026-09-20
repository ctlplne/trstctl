// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
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
				"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
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

// Selecting an endpoint profile must change the reviewed signing policy, not
// merely its display label. The configured default deliberately rejects this
// hostname so silently ignoring the selection cannot pass.
func TestEndpointEnrollmentSelectsAndRetainsProfile(t *testing.T) {
	for _, scenario := range []string{"issue and replay", "changed revision", "selected approval", "unknown profile", "existing policy conflict"} {
		t.Run(scenario, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.DefaultProfile = "mail-only" })
			registerServedTenant(t, h, "endpoint profile selection tenant")
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "profiles:write", "connectors:write", "certs:issue", "identities:write")
			create := func(path string, request any) string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, path, token, request)
				if path == "/api/v1/profiles" && code == http.StatusAccepted {
					var pending struct {
						ApprovalID string `json:"approval_id"`
					}
					if err := json.Unmarshal(body, &pending); err != nil || pending.ApprovalID == "" {
						t.Fatalf("profile approval: %s %v", body, err)
					}
					reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "profile-selection-reviewer", "profiles:write")
					code, body = secretsReq(t, h, http.MethodPost, "/api/v1/profiles/approvals/"+pending.ApprovalID+"/approvals", reviewer, map[string]string{"reason": "review endpoint DNS and approval policy"})
					if code != http.StatusOK || !strings.Contains(string(body), `"state":"issued"`) {
						t.Fatalf("approve profile: %d %s", code, body)
					}
					return ""
				}
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
			createProfile := func(name, suffix, ttl string, approval bool) {
				t.Helper()
				create("/api/v1/profiles", map[string]any{"name": name, "spec": map[string]any{
					"max_validity": ttl, "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{suffix},
					"requires_approval": approval,
				}})
			}
			createProfile("mail-only", "mail.partner-lab.example.com", "10m", false)
			createProfile("java-jks", "java-jks.partner-lab.example.com", "12m", scenario == "selected approval")
			owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "JKS application"})
			target := create("/api/v1/connectors/targets", map[string]any{
				"name": "JKS profile admission", "connector": "nginx", "enabled": true,
				"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
					"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "java-jks.partner-lab.example.com"},
			})
			if scenario == "existing policy conflict" {
				create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "java-jks.partner-lab.example.com", "owner_id": owner,
					"attributes": map[string]string{"profile_name": "mail-only"}})
			}
			request := map[string]any{"owner_id": owner, "identity_name": "java-jks.partner-lab.example.com", "target_id": target, "profile_name": "java-jks",
				"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "select the endpoint policy explicitly"}
			if scenario == "unknown profile" {
				request["profile_name"] = "not-in-this-tenant"
			}
			code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
			if scenario == "unknown profile" || scenario == "existing policy conflict" {
				want := http.StatusNotFound
				if scenario == "existing policy conflict" {
					want = http.StatusConflict
				}
				if code != want {
					t.Fatalf("profile refusal: want=%d got=%d %s", want, code, body)
				}
				return
			}
			if code != http.StatusOK {
				t.Fatalf("selected profile preview: %d %s", code, body)
			}
			var preview struct {
				RequestFingerprint string                                  `json:"request_fingerprint"`
				Issuance           *store.OperationApprovalIssuanceBinding `json:"issuance"`
				ApprovalRequired   bool                                    `json:"approval_required"`
			}
			if err := json.Unmarshal(body, &preview); err != nil {
				t.Fatal(err)
			}
			if preview.Issuance == nil || preview.Issuance.ProfileName != "java-jks" || preview.Issuance.ProfileVersion != 1 || preview.Issuance.EffectiveTTLSeconds != 720 || preview.ApprovalRequired != (scenario == "selected approval") {
				t.Fatalf("wrong reviewed profile: %s", body)
			}
			request["preview_fingerprint"] = preview.RequestFingerprint
			if scenario == "changed revision" {
				createProfile("java-jks", "java-jks.partner-lab.example.com", "9m", false)
			}
			const key = "selected-profile-enrollment"
			code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			want := http.StatusCreated
			if scenario == "changed revision" {
				want = http.StatusConflict
			}
			if scenario == "selected approval" {
				want = http.StatusForbidden
			}
			if code != want {
				t.Fatalf("execute: want=%d got=%d %s", want, code, body)
			}
			pending, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			var jobs []orchestrator.Record
			for _, row := range pending {
				if row.Destination == "ca.issue" {
					jobs = append(jobs, row)
				}
			}
			if scenario != "issue and replay" {
				if len(jobs) != 0 {
					t.Fatalf("refused profile queued issuance: %d", len(jobs))
				}
				return
			}
			if len(jobs) != 1 {
				t.Fatalf("issuance jobs: %d", len(jobs))
			}
			var intent struct {
				Issuance *store.OperationApprovalIssuanceBinding `json:"issuance"`
			}
			if err := json.Unmarshal(jobs[0].Payload, &intent); err != nil {
				t.Fatal(err)
			}
			if intent.Issuance == nil || *intent.Issuance != *preview.Issuance {
				t.Fatalf("selected revision was lost: %+v", intent.Issuance)
			}
			identity, found, err := h.store.FindIdentityByName(t.Context(), h.tenant, "java-jks.partner-lab.example.com")
			if err != nil || !found {
				t.Fatalf("identity: found=%v err=%v", found, err)
			}
			var attrs map[string]any
			if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
				t.Fatal(err)
			}
			if attrs["profile_name"] != "java-jks" {
				t.Fatalf("selected profile not retained for renewal: %s", identity.Attributes)
			}
			retained, err := h.srv.orch.ProfileApprovalRequirement(t.Context(), h.tenant, identity.ID)
			if err != nil || retained.ProfileName != "java-jks" {
				t.Fatalf("later policy lookup: %+v %v", retained, err)
			}
			head, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			code, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusCreated || string(replay) != string(body) {
				t.Fatalf("replay changed receipt: %d %s", code, replay)
			}
			after, err := h.log.LastSequence(t.Context())
			if err != nil || head != after {
				t.Fatalf("replay emitted new work: %d -> %d %v", head, after, err)
			}
			request["profile_name"] = "mail-only"
			code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusConflict {
				t.Fatalf("same key accepted a different profile: %d %s", code, body)
			}
		})
	}
}
