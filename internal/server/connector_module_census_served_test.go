// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/plugincensus"
)

// A242 through the served API: a relay's signed census reports each connector
// module's version, state, actions, setup inputs and health. A module awaiting
// its operator's approval is listed but not carried, so no target or deploy
// routes to it; a module's targets are checked against its setup inputs, and a
// secret input takes a reference, never a value.
func TestServedConnectorModuleCensusAndSetupInputsA242(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"}, func(*Deps) {})
	reportPartnerModules(t, h)
	if carries, err := h.store.TenantNetworkRelayCarriesPlugin(ctx, h.tenant, "partner-lb"); err != nil || !carries {
		t.Fatalf("the loaded module is not carried: %v %v", carries, err)
	}
	if carries, err := h.store.TenantNetworkRelayCarriesPlugin(ctx, h.tenant, "partner-fw"); err != nil || carries {
		t.Fatalf("a module awaiting approval counts as carried: %v %v", carries, err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "connectors:write")
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/catalog", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("catalog: %d %s", status, body)
	}
	var catalog struct {
		RelayPlugins []struct {
			Plugins []plugincensus.Entry `json:"plugins"`
		} `json:"relay_plugins"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil || len(catalog.RelayPlugins) != 1 || len(catalog.RelayPlugins[0].Plugins) != 2 {
		t.Fatalf("catalog relay plugins: %v %s", err, body)
	}
	for _, entry := range catalog.RelayPlugins[0].Plugins {
		m := entry.Module
		if m == nil || m.Version != "1.2.0" || len(m.Inputs) != 3 || m.Health.LastFailure != "timeout" {
			t.Fatalf("catalog module metadata for %s: %+v", entry.Name, m)
		}
		if entry.Name == "partner-fw" && (m.State != "awaiting-approval" || len(m.PendingPermissions) != 2 || len(entry.Grants) != 0) {
			t.Fatalf("the waiting module reads as %+v with grants %v", m, entry.Grants)
		}
	}

	create := func(connector string, config map[string]any) (int, string) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": "lb/" + connector + "-" + time.Now().Format("150405.000000"), "connector": connector, "config": config,
		})
		return status, string(body)
	}
	for _, tc := range []struct {
		connector string
		config    map[string]any
		want      int
		says      string
	}{
		{"partner-lb", map[string]any{"endpoint": "https://lb.internal"}, http.StatusUnprocessableEntity, "setup input partition is required"},
		{"partner-lb", map[string]any{"partition": "edge", "admin_ref": "hunter2"}, http.StatusUnprocessableEntity, "give a reference"},
		{"partner-lb", map[string]any{"partition": "edge", "port": "443"}, http.StatusUnprocessableEntity, "must be an integer"},
		{"partner-fw", map[string]any{"partition": "edge"}, http.StatusUnprocessableEntity, "no enrolled network relay"},
		{"partner-lb", map[string]any{"partition": "edge", "admin_ref": "secret://lb-admin", "port": 8443}, http.StatusCreated, ""},
	} {
		status, body := create(tc.connector, tc.config)
		if status != tc.want || !strings.Contains(body, tc.says) {
			t.Errorf("%s %v: status %d body %s; want %d %q", tc.connector, tc.config, status, body, tc.want, tc.says)
		}
		if strings.Contains(body, "hunter2") {
			t.Errorf("the refusal echoed a secret value: %s", body)
		}
	}
}

// reportPartnerModules heartbeats a signed relay census carrying two connector
// modules (A242): partner-lb loaded, with a required partition, a secret
// admin_ref and an integer port among its setup inputs, and partner-fw
// awaiting its operator's approval.
func reportPartnerModules(t *testing.T, h *roleHarness) {
	t.Helper()
	ctx := context.Background()
	module := func(state string, pending []string) *plugincensus.Module {
		return &plugincensus.Module{
			Version: "1.2.0", State: state, HostAPIMin: 1, HostAPIMax: 1,
			Actions: []string{"deploy", "readback", "test"}, Idempotency: "create-new", Revocation: "delete",
			Credentials: []string{"bearer"}, MemoryPages: 1024, TimeoutMS: 10000, PendingPermissions: pending,
			Inputs: []plugincensus.ModuleInput{
				{Name: "partition", Type: "string", Required: true, Description: "the appliance partition"},
				{Name: "admin_ref", Type: "string", Secret: true},
				{Name: "port", Type: "integer"},
			},
			Health: plugincensus.ModuleHealth{Calls: 4, Failures: 1, LastFailure: "timeout"},
		}
	}
	census := []plugincensus.Entry{
		{
			Name: "partner-lb", Digest: "sha256:" + strings.Repeat("a", 64), Publisher: "sha256:" + strings.Repeat("b", 64),
			ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM,
			Grants:           []plugincensus.Grant{{Capability: "net.http", Constraints: []string{"lb.internal:443"}}},
			Module:           module(plugincensus.ModuleStateLoaded, nil),
		},
		{
			Name: "partner-fw", Digest: "sha256:" + strings.Repeat("c", 64), Publisher: "sha256:" + strings.Repeat("b", 64),
			ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM, Grants: []plugincensus.Grant{},
			Module: module(plugincensus.ModuleStateAwaitingApproval, []string{"capability net.http", "credential bearer"}),
		},
	}
	report, err := transport.SignedPluginCensus(h.identity.Identity(), h.tenant, h.agent, census, time.Now().UTC().Add(-2*time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active", RelayPlugins: report}); err != nil {
		t.Fatalf("heartbeat with module census: %v", err)
	}
}
