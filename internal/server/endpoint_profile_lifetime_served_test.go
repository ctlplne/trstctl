// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestEndpointPreviewAndEnrollmentRejectUnusablePlatformLifetime(t *testing.T) {
	for _, tc := range []struct {
		name, ttl, source, denial string
	}{
		{"short platform", "2m", "platform", "leaves no usable lifetime"},
		{"exact skew platform", "5m", "platform", "leaves no usable lifetime"},
		{"usable platform", "7m", "platform", ""},
		{"short private", "2m", "private", "leaves no usable lifetime"},
		{"usable private", "7m", "private", ""},
		{"external has own skew", "2m", "external", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, err := digicertfake.NewServer()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(upstream.Close)
			h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
				d.ExternalCAs = []ExternalCA{{ID: "external-short", Type: "digicert", Name: "External short CA", CA: digicert.New("external-short", upstream.URL(), []byte(upstream.APIKey()))}}
				withAgentChannel(d)
				d.AgentClaimableJobKinds = []string{"endpoint.renew"}
				d.DefaultProfile = "endpoint-metadata"
			})
			registerServedTenant(t, h, "profile lifetime admission")
			token := seedScopedToken(t, h.store, h.tenant, "owners:write", "profiles:write", "connectors:write", "certs:issue", "issuers:write")
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
				"max_validity": tc.ttl, "allowed_protocols": []string{"api"},
				"allowed_dns_suffixes": []string{"partner-lab.example.com"}, "allowed_key_algorithms": []string{"ECDSA"},
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
			issuerID := "trstctl-issuing-ca"
			if tc.source == "external" {
				issuerID = "external-short"
			}
			if tc.source == "private" {
				custodian := seedScopedTokenSubject(t, h.store, h.tenant, "lifetime-custodian", "issuers:write")
				spec := map[string]any{"common_name": "Lifetime private CA", "signature_algorithm": "ecdsa-p256", "ttl_seconds": 86400}
				ceremony := createCACeremony(t, h, token, "create_root", "", spec, 1, "lifetime-ceremony")
				approveCACeremony(t, h, custodian, ceremony.ID, 1, "lifetime-approve")
				issuerID = createRootCA(t, h, token, ceremony.ID, spec, "lifetime-root").ID
			}
			request := map[string]any{"owner_id": owner, "identity_name": "java.partner-lab.example.com", "target_id": target,
				"issuer": map[string]any{"source": tc.source, "id": issuerID}, "reason": "review exact profile"}
			code, body := secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
			if tc.denial == "" {
				if code != http.StatusOK {
					t.Fatalf("allowed preview: %d %s", code, body)
				}
			} else {
				if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.denial) || !strings.Contains(string(body), "NotBefore backdate") || !strings.Contains(string(body), "nothing was queued") {
					t.Fatalf("preview must refuse %s before issuance: %d %s", tc.denial, code, body)
				}
				request["preview_fingerprint"] = strings.Repeat("0", 64)
				code, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, request)
				if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.denial) || !strings.Contains(string(body), "NotBefore backdate") || !strings.Contains(string(body), "nothing was queued") {
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

func TestRequesterIssuanceRejectsUnusableProfileBeforeQueue(t *testing.T) {
	for _, ttl := range []string{"2m", "7m"} {
		t.Run(ttl, func(t *testing.T) {
			h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
			registerServedTenant(t, h, "requester profile lifetime")
			token := seedScopedToken(t, h.store, h.tenant, "profiles:write", "owners:write", "identities:write", "certs:issue", "certs:read")
			create := func(path string, req any) string {
				t.Helper()
				code, body := secretsReq(t, h, http.MethodPost, path, token, req)
				if code != http.StatusCreated {
					t.Fatalf("create %s: %d %s", path, code, body)
				}
				var v struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &v); err != nil {
					t.Fatal(err)
				}
				return v.ID
			}
			create("/api/v1/profiles", map[string]any{"name": "requester-lifetime", "spec": map[string]any{"max_validity": ttl, "allowed_protocols": []string{"api"}}})
			owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "Requester lifetime"})
			id := create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "requester-lifetime.example.test", "owner_id": owner, "attributes": map[string]string{"profile_name": "requester-lifetime"}})
			before, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			previewCode, previewBody := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions/preview", token, map[string]any{"to": "issued", "reason": "review lifetime"})
			if ttl == "2m" {
				if previewCode != http.StatusUnprocessableEntity || !strings.Contains(string(previewBody), "leaves no usable lifetime") {
					t.Fatalf("unusable requester preview accepted: %d %s", previewCode, previewBody)
				}
			} else if previewCode != http.StatusOK {
				t.Fatalf("usable preview: %d %s", previewCode, previewBody)
			}
			code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "lifetime-requester-issue", map[string]any{"to": "issued", "reason": "requester profile review", "subject_csr_pem": string(subjectCSR(t, "requester-lifetime.example.test"))})
			if ttl == "2m" {
				if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "leaves no usable lifetime") {
					t.Fatalf("unusable requester profile accepted: %d %s", code, body)
				}
				after, err := h.log.LastSequence(t.Context())
				if err != nil || after != before {
					t.Fatalf("refusal appended work: %d -> %d %v", before, after, err)
				}
				pending, err := orchestrator.NewOutbox(h.store).Pending(t.Context(), h.tenant)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range pending {
					if row.Destination == "ca.issue" {
						t.Fatal("refusal queued signing")
					}
				}
				// Model a command admitted by an older binary through the real
				// orchestrator, retaining its exact immutable profile binding.
				requirement, err := h.srv.orch.ProfileApprovalRequirement(t.Context(), h.tenant, id)
				if err != nil {
					t.Fatal(err)
				}
				const legacyKey = "legacy-short-profile"
				if err := h.srv.orch.TransitionWithSubjectCSR(t.Context(), h.tenant, id, orchestrator.StateIssued, "previously accepted short profile", legacyKey, string(subjectCSR(t, "requester-lifetime.example.test")), requirement.IssuanceBinding()); err != nil {
					t.Fatal(err)
				}
				worker := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
				claimed, err := worker.DispatchOneScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
				if err != nil || !claimed {
					t.Fatalf("legacy dispatch: %v %v", claimed, err)
				}
				pending, err = worker.Pending(t.Context(), h.tenant)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, row := range pending {
					if row.IdempotencyKey == "transition:"+legacyKey {
						found = true
						if row.Status != "failed" || row.LastError != "certificate_profile_validity_refused" {
							t.Errorf("legacy refusal lost diagnosis: status=%s class=%s", row.Status, row.LastError)
						}
					}
				}
				if !found {
					t.Fatal("missing legacy refusal")
				}
				code, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/issuance-result?request_key="+legacyKey, token, nil)
				var outcome struct {
					State string `json:"state"`
					Retry struct {
						Allowed bool   `json:"allowed"`
						Reason  string `json:"reason"`
					} `json:"retry"`
				}
				if err := json.Unmarshal(body, &outcome); err != nil {
					t.Fatal(err)
				}
				if code != http.StatusOK || outcome.State != "failed" || outcome.Retry.Allowed || !strings.Contains(outcome.Retry.Reason, "pinned") || !strings.Contains(outcome.Retry.Reason, "backdate") {
					t.Fatalf("legacy recovery lacks actionable refusal: %d %s", code, body)
				}

				return
			}
			if code != http.StatusOK {
				t.Fatalf("usable requester refused: %d %s", code, body)
			}
			if err := h.srv.Drain(t.Context()); err != nil {
				t.Fatalf("usable profile signing: %v", err)
			}
			code, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", token, nil)
			if code != http.StatusOK || !strings.Contains(string(body), "requester-lifetime.example.test") {
				t.Fatalf("usable profile produced no certificate: %d %s", code, body)
			}
		})
	}
}
