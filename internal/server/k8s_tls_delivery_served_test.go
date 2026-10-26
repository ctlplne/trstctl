// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
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

// A Kubernetes Secret target is delivered only by the agent inside the cluster,
// which generates the key there. Saved without executor=agent it would route
// through control-plane key generation and ship a key into the cluster, so the
// target is refused with what to set instead.
func TestServedKubernetesSecretTargetRequiresTheClusterAgentToGenerateTheKey(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	agent := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "cluster-agent", Status: "active", Roles: []string{"host"}}
	if err := h.store.UpsertAgent(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	create := func(cfg map[string]any) (int, []byte) {
		t.Helper()
		return secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": "payments-web-tls", "connector": "k8s_secret", "config": cfg, "enabled": true,
		})
	}
	cfg := map[string]any{"namespace": "payments", "secret_name": "web-tls", "required_agent_id": agent.ID}
	status, body := create(cfg)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), `executor`) {
		t.Fatalf("k8s_secret target without executor=agent = %d %s, want 422 naming the executor", status, body)
	}
	cfg["executor"] = "agent"
	if status, body := create(cfg); status != http.StatusCreated {
		t.Fatalf("k8s_secret target with executor=agent = %d %s", status, body)
	}
}

// With ownership attestation enforced, as it is by default, a resource whose
// owner has not attested is not delivered, with the ownership reason, and
// nothing reaches the agent; once the owner attests, the next run queues it.
func TestServedKubernetesTLSRunWaitsForAnAttestedOwner(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OwnershipAttestationCadence = 90 * 24 * time.Hour
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "owners:write")
	agent := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "cluster-agent", Status: "active", Roles: []string{"host"}}
	if err := h.store.UpsertAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "team", "name": "Payments Team", "email": "payments@example.test",
		"application_id": "payments", "environment": "production",
	})
	var owner struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &owner) != nil || owner.ID == "" {
		t.Fatalf("create owner = %d %s", status, body)
	}
	sourceID := createKubernetesTLSSource(t, h, tok, map[string]any{
		"cluster_agent_id": agent.ID, "owner_id": owner.ID,
		"resources": []map[string]any{{"kind": "Ingress", "namespace": "payments", "name": "web",
			"tls_secret_name": "web-tls", "hosts": []string{"web.example.test"}}},
	})

	run := runKubernetesTLSSource(t, h, tok, sourceID)
	if run.Status != "partial" || len(run.TargetResults) != 1 || run.TargetResults[0].Status != "not_delivered" {
		t.Fatalf("run = %+v, want the resource not delivered for the owner's ownership readiness", run)
	}
	// The reason says what to do, about which owner, in the operator's terms.
	reason := run.TargetResults[0].Error + " " + run.Error
	for _, want := range []string{"owner " + owner.ID, "has not attested", "trstctl-cli owners attest " + owner.ID, "run the source again"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("not-delivered reason %q does not say %q", reason, want)
		}
	}
	if strings.Contains(reason, "store:") || strings.Contains(reason, "ownership_attestation_is_missing_or_stale") {
		t.Fatalf("not-delivered reason %q leaks an internal error", reason)
	}
	if jobs := queuedClusterRenewals(t, h); len(jobs) != 0 {
		t.Fatalf("%d renewal jobs queued for an unattested owner", len(jobs))
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners/"+owner.ID+"/attest", tok, nil); status != http.StatusOK {
		t.Fatalf("attest owner = %d %s", status, body)
	}
	run = runKubernetesTLSSource(t, h, tok, sourceID)
	if run.Status != "succeeded" || len(run.TargetResults) != 1 || run.TargetResults[0].Status != "delivery_queued" {
		t.Fatalf("run after attestation = %+v, want the resource queued for delivery", run)
	}
	if jobs := queuedClusterRenewals(t, h); len(jobs) != 1 {
		t.Fatalf("%d renewal jobs after attestation, want 1", len(jobs))
	}
}

// The run reports what the cluster agent signed. An attempt the agent reports
// failed is not delivered, in the receipt's words, even while the job is
// retried; once a later attempt delivers and verifies, the resource is
// delivered.
func TestServedKubernetesTLSRunReportsTheClusterAgentsSignedOutcome(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "cluster-agent-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	agentID := agentRowID(h.tenant, h.agent)
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Payments Team", "payments@example.test")
	if err != nil {
		t.Fatal(err)
	}
	sourceID := createKubernetesTLSSource(t, h.servedHarness, tok, map[string]any{
		"cluster_agent_id": agentID, "owner_id": owner.ID,
		"verify_address": "ingress-nginx-controller.ingress-nginx.svc:443",
		"resources": []map[string]any{{"kind": "Ingress", "namespace": "payments", "name": "web",
			"tls_secret_name": "web-tls", "hosts": []string{"web.example.test"}}},
	})
	statusOf := func(want string) kubernetesTLSRun {
		t.Helper()
		run := runKubernetesTLSSource(t, h.servedHarness, tok, sourceID)
		if len(run.TargetResults) != 1 || run.TargetResults[0].Status != want {
			t.Fatalf("run = %+v, want the resource %s", run, want)
		}
		return run
	}
	statusOf("delivery_queued")

	// The agent refuses before generating any key.
	job := claimOneRenewal(t, ctx, h)
	refusal := `this agent's profile does not allow writing Secrets in namespace "payments"`
	if accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, refusal, "")); err != nil || !accepted.Accepted {
		t.Fatalf("failed report = %+v, %v", accepted, err)
	}
	run := statusOf("not_delivered")
	if run.Status != "partial" || !strings.Contains(run.TargetResults[0].Error+" "+run.Error, refusal) {
		t.Fatalf("run = %+v, want the agent's refusal as the reason", run)
	}

	// The retried job generates the key in the cluster, writes and verifies.
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox SET agent_next_attempt_at = now() WHERE id = $1`, job.JobID); err != nil {
		t.Fatal(err)
	}
	job = claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("web.example.test", []string{"web.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatalf("sign the cluster agent's CSR: %v", err)
	}
	detail, digest := simulatedHostVerification(t, h, job, issued.Fingerprint, transport.JobOutcomeVerified)
	id := h.identity.Identity()
	report, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeVerified, detail, digest, issued.Fingerprint, custody.Record{
			Origin: custody.OriginHostAgent, Storage: custody.StorageKubernetesSecret,
			Exportable: custody.Exportable, GeneratedBy: id.CommonName(),
		}, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := h.client.ReportJobResult(ctx, report); err != nil || !accepted.Accepted {
		t.Fatalf("verified report = %+v, %v", accepted, err)
	}
	if run := statusOf("delivered"); run.Status != "succeeded" {
		t.Fatalf("run = %+v, want succeeded once the agent delivered", run)
	}
}
