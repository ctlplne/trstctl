// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A CA migration requires every member target to be marked executor=agent, an
// appliance included, with the network relay that fronts it pinned (A33).
// Outside a migration the same marker read as "the host generates this key":
// the identity's issuance went to endpoint.renew for a HOST agent with no agent
// ID, a job no agent can ever claim, so the appliance never received its
// certificate and nothing said why, and the custody readout claimed a
// host-generated key. A host agent cannot generate an appliance's key: the
// control plane generates it under the tenant's switch and queues the sealed
// deploy for the pinned relay, as for any appliance, and the readout says so.
func TestServedApplianceMarkedAgentExecutedIssuesThroughItsRelay(t *testing.T) {
	ctx := context.Background()
	device := f5test.New("admin", "appliance-secret")
	t.Cleanup(device.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(device.Client()) })
	registry.Register(f5.New(device.URL(), "clientssl-edge"))
	if err := registry.DeclareTargetVantage("f5", connector.VantageNetworkRelay); err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"},
		func(d *Deps) { d.DefaultProfile = "appliance-api"; d.ConnectorRegistry = registry })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "appliance-relay", Status: "active"}); err != nil {
		t.Fatalf("register network relay: %v", err)
	}
	spec, _ := json.Marshal(map[string]any{"name": "appliance-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "appliance-api", spec); err != nil {
		t.Fatal(err)
	}
	operator := events.ContextWithActor(ctx, events.Actor{Subject: "ops@example.test"})
	if _, err := h.srv.orch.SetControlPlaneKeygen(operator, h.tenant, projections.ControlPlaneKeygenSet{
		Enabled: true, Source: store.ControlPlaneKeygenSourceOperator, Reason: "appliances take control-plane keys", SetBy: "ops@example.test",
	}); err != nil {
		t.Fatal(err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	config, _ := json.Marshal(map[string]any{
		"executor": "agent", "endpoint": "https://f5.example.internal",
		"required_agent_role": mtls.AgentRoleNetwork, "required_agent_id": relayID,
	})
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "/Common/edge", Type: "f5", Config: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "appliance owner", "")
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": "f5", "target": target.Name, "profile_name": "appliance-api"})
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "edge.example.test", OwnerID: owner.ID, Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "identities:read", "identities:write", "certs:read", "certs:issue")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, "appliance-issue",
		map[string]any{"to": "issued", "reason": "first certificate for the appliance"}); status != http.StatusOK {
		t.Fatalf("issue = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	type job struct{ destination, role, agent string }
	var jobs []job
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT destination, required_agent_role, COALESCE(required_agent_id::text, '') FROM outbox WHERE tenant_id = $1 ORDER BY id`, h.tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var j job
			if err := rows.Scan(&j.destination, &j.role, &j.agent); err != nil {
				return err
			}
			jobs = append(jobs, j)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	var deploy bool
	for _, j := range jobs {
		if j.destination == "endpoint.renew" {
			t.Fatalf("the appliance's issuance was handed to a host agent: %+v (all jobs %+v)", j, jobs)
		}
		if j.destination == "connector.deploy" && j.role == mtls.AgentRoleNetwork {
			deploy = true
		}
	}
	if !deploy {
		t.Fatalf("no sealed deploy was queued for the relay: %+v", jobs)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/endpoints/key-custody", tok, nil)
	var custodyList struct {
		Items []struct {
			TargetID string `json:"target_id"`
			Origin   string `json:"origin"`
			Executor string `json:"executor"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &custodyList) != nil {
		t.Fatalf("key custody = %d %s", status, body)
	}
	for _, item := range custodyList.Items {
		if item.TargetID == target.ID && (item.Origin != "control_plane" || item.Executor != "control_plane") {
			t.Fatalf("custody readout for the appliance = %+v, want control-plane generated", item)
		}
	}
}
