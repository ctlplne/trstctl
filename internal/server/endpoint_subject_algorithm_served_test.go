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
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// HTTP, real PostgreSQL/NATS and the production authorization path. No CA or
// endpoint effect is dispatched: preview/queue proof is distinct from the
// managed listener lifecycle that must still be exercised in the installed lab.
func TestEndpointEnrollmentRetainsExactSubjectAlgorithm(t *testing.T) {
	for _, algorithm := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(algorithm, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				withAgentChannel(d)
				d.AgentClaimableJobKinds = []string{"endpoint.renew", "connector.deploy"}
				d.LicensedCSRParser = pqc.ParsePureMLDSACSR
				d.LicensedCSRInspector = pqc.InspectHybridCSR
				d.LicensedLeafSigner = pqc.SignLicensedLeafFromCSRWithProfile
				d.PreparedSubjectLeafSigner = pqc.SignPQCLeafFromCSRWithPreparation
			})
			registerServedTenant(t, h, "endpoint algorithm selection")
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue")
			create := func(path string, input any) string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, path, token, input)
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
			owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "PQC endpoint owner"})
			target := create("/api/v1/connectors/targets", map[string]any{
				"name": "PQC endpoint", "connector": "nginx", "enabled": true,
				"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
					"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "pqc.example.test"},
			})
			request := map[string]any{"owner_id": owner, "identity_name": "pqc.example.test", "target_id": target, "subject_key_algorithm": algorithm,
				"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "select exact endpoint subject algorithm"}
			preview := func() string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
				if code != http.StatusOK {
					t.Fatalf("preview: %d %s", code, body)
				}
				var got struct {
					Fingerprint string `json:"request_fingerprint"`
					Algorithm   string `json:"subject_key_algorithm"`
				}
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				if got.Algorithm != request["subject_key_algorithm"] {
					t.Fatalf("preview lost subject choice: %s", body)
				}
				return got.Fingerprint
			}
			fingerprint := preview()
			request["subject_key_algorithm"] = "ECDSA-P256"
			if preview() == fingerprint {
				t.Fatal("algorithm change did not change reviewed fingerprint")
			}
			request["preview_fingerprint"] = fingerprint
			code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, "stale-algorithm", request)
			if code != http.StatusConflict {
				t.Fatalf("stale algorithm review accepted: %d %s", code, body)
			}
			if _, found, err := h.store.FindIdentityByName(t.Context(), h.tenant, "pqc.example.test"); err != nil || found {
				t.Fatalf("refusal created identity: %v %v", found, err)
			}
			request["subject_key_algorithm"] = algorithm
			const key = "reviewed-endpoint-algorithm"
			code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusCreated {
				t.Fatalf("execute: %d %s", code, body)
			}
			identity, found, err := h.store.FindIdentityByName(t.Context(), h.tenant, "pqc.example.test")
			if err != nil || !found {
				t.Fatalf("identity: %v %v", found, err)
			}
			var attrs map[string]string
			if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
				t.Fatal(err)
			}
			if attrs["subject_key_algorithm"] != algorithm || attrs["issuing_authority_id"] != "trstctl-issuing-ca" || attrs["deployment_target_id"] != target {
				t.Fatalf("lost renewal/issuer/target intent: %s", identity.Attributes)
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
				t.Fatalf("replay emitted work: %d -> %d %v", head, after, err)
			}
			rows, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, row := range rows {
				if row.Destination == "ca.issue" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("queued issuance count: %d", count)
			}
			request["subject_key_algorithm"] = "ECDSA-P256"
			code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusConflict {
				t.Fatalf("same key accepted another algorithm: %d %s", code, body)
			}
		})
	}
}

func TestEndpointSubjectChoiceRefusesUnsupportedAndDisallowedAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		name, algorithm   string
		host, denyProfile bool
		status            int
	}{
		{"unsupported", "RSA-1024", true, false, http.StatusBadRequest},
		{"host custody required", "ML-DSA-65", false, false, http.StatusUnprocessableEntity},
		{"profile excludes subject", "ML-DSA-65", true, true, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				withAgentChannel(d)
				d.AgentClaimableJobKinds = []string{"endpoint.renew", "connector.deploy"}
				if tc.denyProfile {
					d.DefaultProfile = "classical-only"
				}
			})
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "profiles:write")
			create := func(path string, input any) string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, path, token, input)
				if code != http.StatusCreated {
					t.Fatalf("create %s: %d %s", path, code, body)
				}
				var out struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &out); err != nil {
					t.Fatal(err)
				}
				return out.ID
			}
			if tc.denyProfile {
				create("/api/v1/profiles", map[string]any{"name": "classical-only", "spec": map[string]any{"max_validity": "12m", "allowed_key_algorithms": []string{"ECDSA"}, "allowed_protocols": []string{"api"}}})
			}
			owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "algorithm refusal owner"})
			cfg := map[string]any{"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "pqc.example.test"}
			if tc.host {
				cfg["executor"] = "agent"
				cfg["required_agent_role"] = "host"
				cfg["required_agent_id"] = seedDestinationHost(t, h.store, h.tenant)
			}
			target := map[string]any{"name": "algorithm refusal target", "connector": "nginx", "enabled": true, "config": cfg}
			request := map[string]any{"owner_id": owner, "identity_name": "pqc.example.test", "subject_key_algorithm": tc.algorithm, "issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
			if tc.host {
				request["target_id"] = create("/api/v1/connectors/targets", target)
			} else {
				// Use the public inline destination path: saving an invalid host
				// target already fails before enrollment can be exercised.
				request["target"] = target
			}
			for _, path := range []string{"/api/v1/lifecycle/endpoint-bindings/preview", "/api/v1/lifecycle/endpoint-bindings"} {
				request["preview_fingerprint"] = strings.Repeat("0", 64)
				code, body := secretsReq(t, h, http.MethodPost, path, token, request)
				if code != tc.status {
					t.Fatalf("%s must refuse before issuance: %d %s", path, code, body)
				}
			}
			if _, found, err := h.store.FindIdentityByName(t.Context(), h.tenant, "pqc.example.test"); err != nil || found {
				t.Fatalf("refusal created identity: %v %v", found, err)
			}
			rows, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Destination == "ca.issue" || row.Destination == "endpoint.renew" {
					t.Fatalf("refusal queued issuance: %s", row.Destination)
				}
			}
		})
	}
}

// The original lifecycle is seeded with events and acknowledged test effects.
// This proves served review, command recovery and rebuild, not live deployment.
func TestEndpointReplacementRetainsReviewedSubjectAlgorithm(t *testing.T) {
	for _, requested := range []string{"", "ML-DSA-87", "ECDSA-P256"} {
		name := requested
		if name == "" {
			name = "omitted-preserves-original"
		}
		t.Run(name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				withAgentChannel(d)
				d.AgentClaimableJobKinds = []string{"endpoint.renew"}
			})
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue")
			owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "workload", "replacement subject owner", "")
			if err != nil {
				t.Fatal(err)
			}
			targetConfig, err := json.Marshal(map[string]any{
				"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
				"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "pqc-replacement.example.test",
			})
			if err != nil {
				t.Fatal(err)
			}
			target, err := h.srv.orch.UpsertDeploymentTarget(t.Context(), h.tenant, store.DeploymentTarget{Name: "PQC replacement target", Type: "nginx", Config: targetConfig, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			original, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "pqc-replacement.example.test", OwnerID: owner.ID, Attributes: json.RawMessage(`{"subject_key_algorithm":"ML-DSA-65"}`)})
			if err != nil {
				t.Fatal(err)
			}
			issuer := store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "platform", ID: "trstctl-issuing-ca", Name: "trstctl issuing CA", PreviewFingerprint: strings.Repeat("a", 64)}
			if _, err := h.srv.orch.BindIdentityEndpoint(t.Context(), h.tenant, original.ID, target, issuer); err != nil {
				t.Fatal(err)
			}
			for _, state := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed} {
				if err := h.srv.orch.Transition(t.Context(), h.tenant, original.ID, state, "seed reviewed replacement source"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := orchestrator.NewOutbox(h.store).Dispatch(t.Context(), orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })); err != nil {
				t.Fatal(err)
			}
			original, originalVersion, err := h.store.IdentityApprovalTarget(t.Context(), h.tenant, original.ID)
			if err != nil {
				t.Fatal(err)
			}
			expected := requested
			if expected == "" {
				expected = "ML-DSA-65"
			}
			request := map[string]any{"owner_id": owner.ID, "identity_name": original.Name, "target_id": target.ID,
				"replace_identity_id": original.ID, "issuer": map[string]string{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "review replacement subject algorithm"}
			if requested != "" {
				request["subject_key_algorithm"] = requested
			}
			code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
			if code != http.StatusOK {
				t.Fatalf("replacement preview: %d %s", code, body)
			}
			var preview struct {
				Fingerprint string `json:"request_fingerprint"`
				Algorithm   string `json:"subject_key_algorithm"`
			}
			if err := json.Unmarshal(body, &preview); err != nil {
				t.Fatal(err)
			}
			if preview.Algorithm != expected {
				t.Fatalf("replacement preview changed algorithm: %s", body)
			}
			request["preview_fingerprint"] = preview.Fingerprint
			const key = "reviewed-subject-replacement"
			code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusCreated {
				t.Fatalf("replacement execute: %d %s", code, body)
			}
			var accepted struct {
				Identity struct {
					ID string `json:"id"`
				} `json:"identity"`
			}
			if err := json.Unmarshal(body, &accepted); err != nil {
				t.Fatal(err)
			}
			if accepted.Identity.ID == "" || accepted.Identity.ID == original.ID {
				t.Fatalf("missing distinct successor: %s", body)
			}
			head, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			code, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, key, request)
			if code != http.StatusCreated || string(replay) != string(body) {
				t.Fatalf("replacement retry changed receipt: %d %s", code, replay)
			}
			after, err := h.log.LastSequence(t.Context())
			if err != nil || after != head {
				t.Fatalf("replacement retry emitted work: %d -> %d %v", head, after, err)
			}
			assertRetained := func() {
				t.Helper()
				successor, err := h.store.GetIdentity(t.Context(), h.tenant, accepted.Identity.ID)
				if err != nil {
					t.Fatal(err)
				}
				var attrs map[string]string
				if err := json.Unmarshal(successor.Attributes, &attrs); err != nil {
					t.Fatal(err)
				}
				if attrs["subject_key_algorithm"] != expected || attrs["endpoint_replaces_identity_id"] != original.ID || attrs["deployment_target_id"] != target.ID || attrs["issuing_authority_id"] != "trstctl-issuing-ca" {
					t.Fatalf("successor lost reviewed renewal binding: %s", successor.Attributes)
				}
				current, version, err := h.store.IdentityApprovalTarget(t.Context(), h.tenant, original.ID)
				if err != nil || version != originalVersion || current.Status != original.Status || string(current.Attributes) != string(original.Attributes) {
					t.Fatalf("replacement changed original: version=%d err=%v", version, err)
				}
			}
			assertRetained()
			if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
				t.Fatal(err)
			}
			assertRetained()
		})
	}
}

// Missing intent is a legacy default; an explicitly null/blank saved choice is
// invalid to the worker and must not pass the operator's preview as a default.
func TestEndpointPreviewRefusesInvalidSavedSubjectIntent(t *testing.T) {
	for _, raw := range []string{`{"subject_key_algorithm":null}`, `{"subject_key_algorithm":""}`} {
		t.Run(raw, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				withAgentChannel(d)
				d.AgentClaimableJobKinds = []string{"endpoint.renew"}
			})
			token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "certs:issue")
			owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "workload", "invalid subject owner", "")
			if err != nil {
				t.Fatal(err)
			}
			targetConfig, err := json.Marshal(map[string]any{
				"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
				"cert_path": "/app/tls/server.crt", "key_path": "/app/tls/server.key", "verify_address": "127.0.0.1:8443", "verify_server_name": "invalid-subject.example.test",
			})
			if err != nil {
				t.Fatal(err)
			}
			target, err := h.srv.orch.UpsertDeploymentTarget(t.Context(), h.tenant, store.DeploymentTarget{Name: "invalid subject target", Type: "nginx", Config: targetConfig, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "invalid-subject.example.test", OwnerID: owner.ID, Attributes: json.RawMessage(raw)})
			if err != nil {
				t.Fatal(err)
			}
			before, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request := map[string]any{"owner_id": owner.ID, "identity_name": identity.Name, "target_id": target.ID, "issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "preview_fingerprint": strings.Repeat("a", 64)}
			for _, path := range []string{"/api/v1/lifecycle/endpoint-bindings/preview", "/api/v1/lifecycle/endpoint-bindings"} {
				code, body := secretsReq(t, h, http.MethodPost, path, token, request)
				if code != http.StatusConflict || !strings.Contains(string(body), "subject_key_algorithm") {
					t.Fatalf("invalid saved choice admitted: %d %s", code, body)
				}
			}
			after, err := h.log.LastSequence(t.Context())
			if err != nil || after != before {
				t.Fatalf("invalid choice emitted events: %d -> %d %v", before, after, err)
			}
			got, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != identity.Status {
				t.Fatalf("invalid choice advanced lifecycle: %s -> %s", identity.Status, got.Status)
			}
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(got.Attributes, &attrs); err != nil {
				t.Fatal(err)
			}
			if _, bound := attrs["deployment_target_id"]; bound {
				t.Fatal("invalid choice bound a destination")
			}
			rows, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Destination == "ca.issue" || row.Destination == "endpoint.renew" {
					t.Fatal("invalid choice queued issuance")
				}
			}
		})
	}
}
