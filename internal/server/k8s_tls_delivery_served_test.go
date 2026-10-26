// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type kubernetesTLSRun struct {
	Status        string `json:"status"`
	Error         string `json:"error"`
	TargetResults []struct {
		Target string `json:"target"`
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"target_results"`
}

func runKubernetesTLSSource(t *testing.T, h *servedHarness, tok, sourceID string) kubernetesTLSRun {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": sourceID})
	if status != http.StatusCreated {
		t.Fatalf("start run = %d %s", status, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" {
		t.Fatalf("decode run: %v %s", err, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read run = %d %s", status, body)
	}
	var run kubernetesTLSRun
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode run: %v %s", err, body)
	}
	return run
}

func createKubernetesTLSSource(t *testing.T, h *servedHarness, tok string, cfg map[string]any) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "k8s-delivery", "kind": "k8s_ingress_gateway", "config": cfg,
	})
	if status != http.StatusCreated {
		t.Fatalf("create source = %d %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
		t.Fatalf("decode source: %v %s", err, body)
	}
	return source.ID
}

type queuedClusterRenewal struct {
	intent          RelayDeployIntent
	requiredAgentID string
}

func queuedClusterRenewals(t *testing.T, h *servedHarness) map[string]queuedClusterRenewal {
	t.Helper()
	rows, err := h.store.SystemPool().Query(t.Context(),
		`SELECT payload, coalesce(required_agent_id::text, '') FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, agentJobKindEndpointRenew)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]queuedClusterRenewal{}
	for rows.Next() {
		var payload []byte
		var required string
		if err := rows.Scan(&payload, &required); err != nil {
			t.Fatal(err)
		}
		var intent RelayDeployIntent
		if err := json.Unmarshal(payload, &intent); err != nil {
			t.Fatal(err)
		}
		if _, dup := out[intent.SubjectCommonName]; dup {
			t.Fatalf("two renewal jobs were queued for %s", intent.SubjectCommonName)
		}
		out[intent.SubjectCommonName] = queuedClusterRenewal{intent: intent, requiredAgentID: required}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A source bound to the agent running in the cluster turns each Ingress or
// Gateway TLS block into delivery the cert-manager way: a k8s_secret target
// for the Secret it names, an identity for its hosts, and a renewal job for
// that agent to generate the key in the cluster and write the Secret. The
// control plane mints nothing and holds no key, and a rerun converges.
func TestServedKubernetesTLSRunQueuesDeliveryToTheClusterAgent(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read", "identities:read")
	agent := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "cluster-agent", Status: "active", Roles: []string{"host"}}
	if err := h.store.UpsertAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Payments Team", "payments@example.test")
	if err != nil {
		t.Fatal(err)
	}
	sourceID := createKubernetesTLSSource(t, h, tok, map[string]any{
		"cluster_agent_id": agent.ID, "owner_id": owner.ID,
		"verify_address": "ingress-nginx-controller.ingress-nginx.svc:443",
		"resources": []map[string]any{
			{"kind": "Ingress", "namespace": "payments", "name": "web", "tls_secret_name": "web-tls",
				"hosts": []string{"web.example.test", "api.example.test"}},
			{"kind": "Gateway", "namespace": "edge", "name": "gw", "tls_secret_name": "gw-tls",
				"hosts": []string{"gw.example.test"}},
		},
	})

	for round := 1; round <= 2; round++ {
		run := runKubernetesTLSSource(t, h, tok, sourceID)
		if run.Status != "succeeded" || len(run.TargetResults) != 2 {
			t.Fatalf("round %d: run = %+v, want both resources queued for delivery", round, run)
		}
		for _, result := range run.TargetResults {
			if result.Status != "delivery_queued" {
				t.Fatalf("round %d: %s = %s (%s), want delivery_queued", round, result.Target, result.Status, result.Error)
			}
		}
		jobs := queuedClusterRenewals(t, h)
		if len(jobs) != 2 {
			t.Fatalf("round %d: %d renewal jobs, want exactly one per resource", round, len(jobs))
		}
		web := jobs["web.example.test"]
		if web.intent.Connector != "k8s_secret" || web.requiredAgentID != agent.ID ||
			!slices.Equal(web.intent.SubjectDNSNames, []string{"web.example.test", "api.example.test"}) ||
			web.intent.VerifyAddress != "ingress-nginx-controller.ingress-nginx.svc:443" || web.intent.VerifyServerName != "web.example.test" {
			t.Fatalf("round %d: web job = %+v (agent %q)", round, web.intent, web.requiredAgentID)
		}
		var target map[string]string
		if err := json.Unmarshal(web.intent.TargetConfig, &target); err != nil || target["namespace"] != "payments" ||
			target["secret_name"] != "web-tls" || target["executor"] != "agent" || target["required_agent_id"] != agent.ID {
			t.Fatalf("round %d: web target config = %s", round, web.intent.TargetConfig)
		}
		if gw := jobs["gw.example.test"]; gw.intent.Connector != "k8s_secret" || !slices.Equal(gw.intent.SubjectDNSNames, []string{"gw.example.test"}) {
			t.Fatalf("round %d: gateway job = %+v", round, gw.intent)
		}
	}

	var certificates int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1`, h.tenant).Scan(&certificates); err != nil || certificates != 0 {
		t.Fatalf("certificates recorded before the agent delivered = %d (%v), want none", certificates, err)
	}
	var attributes []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT attributes FROM identities WHERE tenant_id = $1 AND name = 'web.example.test'`, h.tenant).Scan(&attributes); err != nil {
		t.Fatalf("the web identity was not created: %v", err)
	}
	if !strings.Contains(string(attributes), `"Ingress:payments/web"`) || !strings.Contains(string(attributes), `"api.example.test"`) {
		t.Fatalf("web identity attributes = %s, want the resource and its hosts", attributes)
	}
}

// An agent that cannot write the Secret is named, not guessed past: a bound
// agent without the host role leaves every resource not delivered with the
// reason, and nothing is queued.
func TestServedKubernetesTLSRunRefusesAnAgentThatCannotDeliver(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	relay := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "network-relay", Status: "active", Roles: []string{"network"}}
	if err := h.store.UpsertAgent(ctx, relay); err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Payments Team", "payments@example.test")
	if err != nil {
		t.Fatal(err)
	}
	sourceID := createKubernetesTLSSource(t, h, tok, map[string]any{
		"cluster_agent_id": relay.ID, "owner_id": owner.ID,
		"resources": []map[string]any{{"kind": "Ingress", "namespace": "payments", "name": "web",
			"tls_secret_name": "web-tls", "hosts": []string{"web.example.test"}}},
	})
	run := runKubernetesTLSSource(t, h, tok, sourceID)
	if run.Status != "partial" || len(run.TargetResults) != 1 || run.TargetResults[0].Status != "not_delivered" ||
		!strings.Contains(run.TargetResults[0].Error, "host role") {
		t.Fatalf("run = %+v, want the resource not delivered because the agent lacks the host role", run)
	}
	if jobs := queuedClusterRenewals(t, h); len(jobs) != 0 {
		t.Fatalf("%d renewal jobs queued for an agent that cannot deliver", len(jobs))
	}
}
