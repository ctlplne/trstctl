// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/plugincensus"
)

// A63: a target whose connector is a WASM plugin executes on the network relay
// that reported, in its signed census, that it loaded that plugin. The deploy
// is stamped for the network role from the census, the control plane leaves
// it alone, the relay claims it over the channel and its report becomes the
// receipt. A plugin no relay reports stays with the control plane's own plugin
// surface, which here is not configured and says so in the receipt.
func TestServedPluginBackedTargetDeploysThroughTheRelayThatCarriesIt(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	census := []plugincensus.Entry{{
		Name: "partner-lb", Digest: "sha256:" + strings.Repeat("a", 64), Publisher: "sha256:" + strings.Repeat("b", 64),
		ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM,
		Grants:           []plugincensus.Grant{{Capability: "net.dial", Constraints: []string{"lb.internal:443"}}},
	}}
	report, err := transport.SignedPluginCensus(h.identity.Identity(), h.tenant, h.agent, census, time.Now().UTC().Add(-2*time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active", RelayPlugins: report}); err != nil {
		t.Fatalf("heartbeat with plugin census: %v", err)
	}
	carries, err := h.store.TenantNetworkRelayCarriesPlugin(ctx, h.tenant, "partner-lb")
	if err != nil || !carries {
		t.Fatalf("census projection does not say the relay carries partner-lb: %v %v", carries, err)
	}
	if carries, _ := h.store.TenantNetworkRelayCarriesPlugin(ctx, h.tenant, "orphan-plugin"); carries {
		t.Fatal("a plugin nobody reported counts as carried")
	}

	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)
	createTarget := func(name, family string) string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": name, "connector": family, "config": map[string]any{"endpoint": "https://lb.internal:443"},
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s target: status %d body %s", family, status, body)
		}
		var target struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
			t.Fatalf("decode target: %v %s", err, body)
		}
		return target.ID
	}
	issueTo := func(identityName, targetID string) string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": identityName + "-owner"})
		if status != http.StatusCreated {
			t.Fatalf("create owner: status %d body %s", status, body)
		}
		var owner struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &owner); err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"kind": "x509_certificate", "name": identityName, "owner_id": owner.ID,
		})
		if status != http.StatusCreated {
			t.Fatalf("create identity: status %d body %s", status, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ident); err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", tok, map[string]any{"target_id": targetID})
		if status != http.StatusOK {
			t.Fatalf("bind identity: status %d body %s", status, body)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{"to": "issued", "reason": "a63"})
		if status != http.StatusOK {
			t.Fatalf("issue: status %d body %s", status, body)
		}
		return ident.ID
	}

	// A plugin no relay reports cannot become a target: the control plane
	// has no plugin surface for it and would only ever fail its deploys.
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "lb/orphan", "connector": "orphan-plugin", "config": map[string]any{"endpoint": "https://lb.internal:443"},
	})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "no enrolled network relay in this tenant reports carrying") {
		t.Fatalf("orphan plugin target: status %d body %s", status, body)
	}

	carried := issueTo("a63-carried.served.test", createTarget("lb/partner", "partner-lb"))
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	// The carried plugin's deploy waits for the relay: nothing was recorded
	// by the control plane.
	if before := connectorDeliveriesForIdentity(t, h.servedHarness, tok, carried); len(before.Items) != 0 {
		t.Fatalf("the control plane recorded a delivery for the relay-carried plugin: %+v", before.Items)
	}

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 120})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("relay claimed %d jobs, want only the carried plugin's deploy", len(claimed.Jobs))
	}
	job := claimed.Jobs[0]
	var intent relay.DeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Connector != "partner-lb" || intent.Target != "lb/partner" {
		t.Fatalf("claimed intent = %+v %v, want the partner-lb deploy", intent, err)
	}
	if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "")); err != nil {
		t.Fatalf("report: %v", err)
	}
	after := connectorDeliveriesForIdentity(t, h.servedHarness, tok, carried)
	if len(after.Items) != 1 || after.Items[0].Status != "delivered" || after.Items[0].Connector != "partner-lb" {
		t.Fatalf("delivery after the relay ran the plugin = %+v raw=%s", after.Items, after.Raw)
	}
}
