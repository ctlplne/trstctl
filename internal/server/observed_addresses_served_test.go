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
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/pqc/compatlab"
)

// X3-L2 Done-when: an endpoint behind NAT or a load balancer names where an
// observer sees its traffic. A PQC pilot's canary target is probed at its
// load-balanced address and names its backend 10.0.3.17:8443 as an observed
// address: real clients the observer sees at that backend after the probe
// advance the wave, while the same evidence for a target that names no
// observed address, and traffic at an unrelated backend, do not. A
// malformed observed address is refused on a pilot and on a connector
// target.
func TestServedObserverEvidenceAtAnObservedAddressX3L2(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read", "connectors:write")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	const sni = "lb-backed.pq.example.test"
	const backend = "10.0.3.17:8443"
	endpoint, err := tlsprobe.NewServingTestServer(sni)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.Close)
	info, err := certinfo.Inspect(caCertDER(t, endpoint.LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf := strings.ToLower(info.SHA256Fingerprint)

	start := func(key string, target map[string]any) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, key, map[string]any{
			"name": "observed address " + key, "authority_id": "pq-issuing-ca", "require_observed_traffic": true,
			"observed_traffic_window_seconds": 120, "waves": []map[string]any{{"name": "canary", "targets": []map[string]any{target}}},
		})
	}
	if code, body := start("x3l2-bad", map[string]any{"target_id": "bad-1", "address": endpoint.Addr, "fingerprint": leaf,
		"observed_addresses": []string{"10.0.3.17"}}); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "host:port") {
		t.Fatalf("an observed address without a port = %d %s; want 422", code, body)
	}
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, "x3l2-bad-target", map[string]any{
		"name": "x3l2-bad-target", "connector": "nginx", "config": map[string]any{"verify_address": endpoint.Addr, "observed_addresses": "10.0.3.17:8443"},
	}); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "observed_addresses") {
		t.Fatalf("a connector target with a malformed observed_addresses = %d %s; want 422", code, body)
	}

	get := func(id string) servedTrafficPilot {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/pilots/"+id, token, nil)
		var out servedTrafficPilot
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("get pilot = %d %s", code, body)
		}
		return out
	}
	run := func(key string, target map[string]any) servedTrafficPilot {
		t.Helper()
		code, body := start(key, target)
		var started servedTrafficPilot
		if code != http.StatusCreated || json.Unmarshal(body, &started) != nil {
			t.Fatalf("start pilot %s = %d %s", key, code, body)
		}
		probeWaveAsRelay(t, ctx, h, started.ID, 1)
		if held := get(started.ID); held.Waves[0].Status != "awaiting_traffic" {
			t.Fatalf("pilot %s after its probe = %+v; want the canary awaiting traffic", key, held)
		}
		return started
	}
	behindLB := run("x3l2-lb", map[string]any{"target_id": "lb-1", "address": endpoint.Addr, "server_name": sni, "fingerprint": leaf,
		"observed_addresses": []string{backend}})

	observerAgent := enrollAgentWithRoles(t, h.servedHarness, "edge-observer-x3l2", h.serverName, []string{mtls.AgentRoleObserver})
	creds, err := observerAgent.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	observer := transport.NewAgentClient(conn)
	registerInventoryAgent(t, observer)
	observe := func(address, serverName string) {
		t.Helper()
		meta := map[string]string{"protocol": "tls", "server": address, "server_name": serverName, "tls_version": "TLSv1.3",
			"group": "X25519MLKEM768", "pq_hybrid": "true", "certificate_visible": "false",
			"last_seen": time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339), "payload_stored": "false"}
		inv, err := observer.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: []transport.InventoryFinding{{
			Kind: "tls_handshake", Ref: "tls " + address + " " + serverName, Provenance: "network-observer:eth1", RiskScore: 10, Metadata: meta,
		}}})
		if err != nil || inv.Recorded != 1 {
			t.Fatalf("observer report: %+v %v", inv, err)
		}
	}

	// Traffic at an unrelated backend under another name is not evidence.
	observe("10.0.9.9:8443", "other.example.test")
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if again := get(behindLB.ID); again.Waves[0].Status != "awaiting_traffic" {
		t.Fatalf("traffic at an unrelated backend moved the canary to %q", again.Waves[0].Status)
	}

	// Real clients at the observed backend advance the wave.
	observe(backend, sni)
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	advanced := get(behindLB.ID)
	canary := advanced.Waves[0]
	if canary.Status != "assessed" || len(canary.Results) != 1 || canary.Results[0].Traffic == nil ||
		canary.Results[0].Traffic.Outcome != compatlab.TrafficObserved || canary.Results[0].Traffic.Server != backend {
		t.Fatalf("pilot after clients at the observed backend = %+v; want the canary assessed with the backend's evidence", advanced)
	}

	// The same backend evidence does nothing for a target that names no
	// observed address: the gate never guesses what is behind an address.
	plain := run("x3l2-plain", map[string]any{"target_id": "plain-1", "address": endpoint.Addr, "fingerprint": leaf})
	observe(backend, sni)
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if again := get(plain.ID); again.Waves[0].Status != "awaiting_traffic" {
		t.Fatalf("a target naming no observed address took the backend's traffic: %q", again.Waves[0].Status)
	}
	t.Logf("X3L2_OK pilot=%s backend=%s", behindLB.ID, backend)
}
