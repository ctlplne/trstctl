// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// Two real enrolled host identities compete for the same served queue. Neither
// a preview nor an expired lease may move work to the unrelated machine.
func TestHostTargetAssignmentSurvivesCompetingHostAndExpiredLease(t *testing.T) {
	ctx := t.Context()
	registry := connector.NewRegistry()
	if err := registry.RegisterFactory("nginx", func(context.Context, connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
		return nil, nil, func() {}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.DeclareTargetVantage("nginx", connector.VantageHostAgent); err != nil {
		t.Fatal(err)
	}
	kinds := []string{"connector.test", "endpoint.renew", "connector.deploy"}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, kinds, func(d *Deps) { d.ConnectorRegistry = registry })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	other := enrollAgentWithRoles(t, h.servedHarness, "unrelated-mail-host", h.serverName, []string{mtls.AgentRoleHost})
	credentials, err := other.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	otherClient := transport.NewAgentClient(conn)
	if _, err := otherClient.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "unrelated-mail-host", Version: "test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]string{"executor": "agent", "required_agent_id": agentRowID(h.tenant, h.agent), "cert_path": "/app/tls/cert.pem", "key_path": "/app/tls/key.pem"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "Application host", Type: "nginx", Config: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.connectorTestEnqueuer(map[string]bool{"connector.test": true})(ctx, h.tenant, target, "assigned-preview"); err != nil {
		t.Fatal(err)
	}
	d := &issuanceDispatcher{store: h.store, outbox: h.srv.outbox, connectorRegistry: registry}
	identity := store.Identity{ID: "44444444-4444-4444-8444-44444444a079", Name: "application.example.test"}
	if err := d.enqueueHostRenewal(ctx, h.tenant, identity, target, identity.Name, []string{identity.Name}, "", "", nil, "assigned-renewal"); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(connector.DeployPayload{Connector: target.Type, TargetID: target.ID, TargetConfig: target.Config, IdentityID: identity.ID, Fingerprint: "assigned-fingerprint"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.enqueueCredentialDeploy(ctx, h.tenant, identity.ID, "assigned-fingerprint", payload); err != nil {
		t.Fatal(err)
	}
	claim := func(client *transport.AgentClient) []transport.ClaimedJob {
		t.Helper()
		result, err := client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: kinds, Limit: 10, LeaseSeconds: 60})
		if err != nil {
			t.Fatal(err)
		}
		return result.Jobs
	}
	if jobs := claim(otherClient); len(jobs) != 0 {
		t.Fatalf("unrelated host received %d assigned jobs", len(jobs))
	}
	jobs := claim(h.client)
	if len(jobs) != 3 {
		t.Fatalf("assigned host received %d jobs, want preview, renewal, and deploy", len(jobs))
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET claim_expires_at = $2 WHERE tenant_id = $1 AND claimed_by_agent_id = $3`, h.tenant, time.Now().Add(-time.Minute), agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if jobs := claim(otherClient); len(jobs) != 0 {
		t.Fatalf("expired lease moved %d jobs to an unrelated host", len(jobs))
	}
	if jobs := claim(h.client); len(jobs) != 3 {
		t.Fatalf("assigned host cannot reclaim its own jobs: %d", len(jobs))
	}
	// Pre-assignment host rows are held. Still older rows without a role stamp
	// cannot redeem host credentials even if their legacy claim was acquired.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role) VALUES ($1, 'connector.test', $2, 'legacy-host-unassigned', 'host'), ($1, 'connector.test', $2, 'legacy-before-role', '')`, h.tenant, []byte(`{"connector":"nginx"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	legacy := claim(h.client)
	if len(legacy) != 1 || legacy[0].IdempotencyKey != "legacy-before-role" {
		t.Fatalf("unassigned host work escaped: %+v", legacy)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: legacy[0].JobID, Attempt: legacy[0].Attempt}); err == nil || !strings.Contains(err.Error(), "exact destination assignment") {
		t.Fatalf("legacy host credential redemption: %v", err)
	}
}

// Admission tests need an enrolled-host projection, not a fake deployment result.
func seedDestinationHost(t *testing.T, s *store.Store, tenantID string) string {
	t.Helper()
	id := "44444444-4444-4444-8444-44444444a001"
	if err := s.UpsertAgent(t.Context(), store.Agent{ID: id, TenantID: tenantID, Name: "destination-host", Status: "active", Roles: []string{"host"}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func registeredRoleAgentID(t *testing.T, h *roleHarness) string {
	t.Helper()
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	return agentRowID(h.tenant, h.agent)
}

func TestHostTargetAssignmentAdmissionIsTenantScopedAndFailClosed(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.test")
	ctx := t.Context()
	hostID := registeredRoleAgentID(t, h)
	const otherTenant = "22222222-2222-4222-8222-222222222222"
	const foreignID = "44444444-4444-4444-8444-44444444a002"
	const networkID = "44444444-4444-4444-8444-44444444a003"
	const retiredID = "44444444-4444-4444-8444-44444444a004"
	const offlineID = "44444444-4444-4444-8444-44444444a005"
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: otherTenant, Name: "other tenant"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []store.Agent{
		{ID: foreignID, TenantID: otherTenant, Name: "foreign host", Status: "active", Roles: []string{"host"}},
		{ID: networkID, TenantID: h.tenant, Name: "network only", Status: "active", Roles: []string{"network"}},
		{ID: retiredID, TenantID: h.tenant, Name: "retired host", Status: "active", Roles: []string{"host"}},
		{ID: offlineID, TenantID: h.tenant, Name: "offline host", Status: "offline", Roles: []string{"host"}},
	} {
		if err := h.store.UpsertAgent(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.srv.orch.OffboardAgent(ctx, h.tenant, retiredID, "retire fixture host"); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "owners:write", "certs:issue")
	code, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", token, map[string]any{"kind": "workload", "name": "assignment admission"})
	if code != http.StatusCreated {
		t.Fatalf("owner: %d %s", code, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id string
		allowed  bool
	}{
		{"missing", "", false}, {"invalid UUID", "not-an-agent", false},
		{"other tenant", foreignID, false}, {"network only", networkID, false},
		{"offboarded", retiredID, false}, {"enrolled", hostID, true}, {"offline retains assignment", offlineID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{"executor": "agent", "required_agent_id": tc.id, "cert_path": "/app/server.crt", "key_path": "/app/server.key", "verify_server_name": "application.example.test"}
			code, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{"name": tc.name, "connector": "nginx", "enabled": true, "config": config})
			expected := http.StatusUnprocessableEntity
			if tc.allowed {
				expected = http.StatusCreated
			}
			if code != expected {
				t.Fatalf("destination: %d %s; want %d", code, body, expected)
			}
			// A pre-upgrade destination bypasses create-time admission. Preview must
			// independently refuse it before creating an identity or issuance job.
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "legacy " + tc.name, Type: "nginx", Config: raw, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			request := map[string]any{"owner_id": owner.ID, "identity_name": "application.example.test", "target_id": target.ID, "issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
			code, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, request)
			if tc.allowed {
				expected = http.StatusOK
			}
			if code != expected {
				t.Fatalf("preview: %d %s; want %d", code, body, expected)
			}
			if _, found, err := h.store.FindIdentityByName(ctx, h.tenant, "application.example.test"); err != nil || found {
				t.Fatalf("admission created identity: %v %v", found, err)
			}
		})
	}
}
