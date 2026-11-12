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
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/pqc/compatlab"
	"trstctl.com/trstctl/internal/store"
)

type servedTrafficPilot struct {
	ID                           string          `json:"id"`
	Status                       string          `json:"status"`
	CurrentWave                  int             `json:"current_wave"`
	HaltedAtWave                 string          `json:"halted_at_wave"`
	VerdictSummary               string          `json:"verdict_summary"`
	SignedReport                 json.RawMessage `json:"signed_report"`
	RequireObservedTraffic       bool            `json:"require_observed_traffic"`
	ObservedTrafficWindowSeconds int             `json:"observed_traffic_window_seconds"`
	Waves                        []struct {
		Name             string     `json:"name"`
		Status           string     `json:"status"`
		TrafficCheckedAt *time.Time `json:"traffic_checked_at"`
		Results          []struct {
			TargetID string `json:"target_id"`
			Outcome  string `json:"outcome"`
			Traffic  *struct {
				Outcome    string `json:"outcome"`
				FindingID  string `json:"finding_id"`
				Server     string `json:"server"`
				TLSVersion string `json:"tls_version"`
				Group      string `json:"group"`
				PQHybrid   bool   `json:"pq_hybrid"`
				LastSeen   string `json:"last_seen"`
			} `json:"traffic"`
		} `json:"results"`
		Verdict *struct {
			Ready           bool   `json:"ready"`
			Summary         string `json:"summary"`
			AwaitingTraffic int    `json:"awaiting_traffic"`
			Unobserved      int    `json:"unobserved"`
		} `json:"verdict"`
	} `json:"waves"`
}

// X3-L5: a PQC pilot that requires observed traffic holds each wave after its
// relay probe until an observer agent has seen real clients connect at every
// target. The canary advances only on that evidence — not on a TLS 1.2
// handshake presenting another leaf, nor on traffic seen before the probe —
// and a later wave whose target nobody was seen using within the window
// halts the pilot, with the signed readiness report saying so.
func TestServedPQCPilotWaitsForObservedTrafficX3L5(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	const sni = "pilot-traffic.pq.example.test"
	canaryEndpoint, err := tlsprobe.NewServingTestServer(sni)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(canaryEndpoint.Close)
	broadEndpoint, err := tlsprobe.NewServingTestServer(sni)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broadEndpoint.Close)
	fingerprint := func(pem []byte) string {
		info, err := certinfo.Inspect(caCertDER(t, pem))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ToLower(info.SHA256Fingerprint)
	}
	canaryLeaf, broadLeaf := fingerprint(canaryEndpoint.LeafPEM), fingerprint(broadEndpoint.LeafPEM)
	get := func(id string) servedTrafficPilot {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/pilots/"+id, token, nil)
		if code != http.StatusOK {
			t.Fatalf("get pilot = %d %s", code, body)
		}
		var out servedTrafficPilot
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	noSweepQueued := func(when string) {
		t.Helper()
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 5, LeaseSeconds: 60})
		if err != nil || len(claimed.Jobs) != 0 {
			t.Fatalf("%s: a sweep was dispatched: %+v err=%v", when, claimed, err)
		}
	}

	// A window means nothing without the requirement.
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "x3l5-window-only", map[string]any{
		"name": "window only", "authority_id": "pq-issuing-ca", "observed_traffic_window_seconds": 120,
		"waves": []map[string]any{{"name": "canary", "targets": []map[string]any{{"target_id": "c", "address": canaryEndpoint.Addr, "fingerprint": canaryLeaf}}}},
	}); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "require_observed_traffic") {
		t.Fatalf("a window without the requirement = %d %s; want 422 naming require_observed_traffic", code, body)
	}

	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "x3l5-gated", map[string]any{
		"name": "pq pilot with observed traffic", "authority_id": "pq-issuing-ca",
		"require_observed_traffic": true, "observed_traffic_window_seconds": 120,
		"waves": []map[string]any{
			{"name": "canary", "targets": []map[string]any{{"target_id": "canary-1", "address": canaryEndpoint.Addr, "server_name": sni, "fingerprint": canaryLeaf}}},
			{"name": "broad", "targets": []map[string]any{{"target_id": "broad-1", "address": broadEndpoint.Addr, "server_name": sni, "fingerprint": broadLeaf}}},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("start gated pilot = %d %s", code, body)
	}
	var started servedTrafficPilot
	if err := json.Unmarshal(body, &started); err != nil || !started.RequireObservedTraffic || started.ObservedTrafficWindowSeconds != 120 {
		t.Fatalf("started pilot = %+v err=%v; want the requirement and its window", started, err)
	}

	// The canary's probe negotiates; the wave now waits for real clients.
	probeWaveAsRelay(t, ctx, h, started.ID, 1)
	held := get(started.ID)
	if held.Status != "running" || held.Waves[0].Status != "awaiting_traffic" || held.Waves[1].Status != "pending" ||
		held.Waves[0].Verdict == nil || held.Waves[0].Verdict.AwaitingTraffic != 1 || !strings.HasPrefix(held.Waves[0].Verdict.Summary, "AWAITING TRAFFIC") {
		t.Fatalf("pilot after the canary's probe = %+v; want the canary awaiting traffic and the broad wave pending", held)
	}
	noSweepQueued("a canary awaiting traffic")
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if again := get(started.ID); again.Waves[0].Status != "awaiting_traffic" {
		t.Fatalf("with nothing observed the gate moved the canary to %q", again.Waves[0].Status)
	}

	// An observer agent reports handshakes at the canary's endpoint.
	observerAgent := enrollAgentWithRoles(t, h.servedHarness, "edge-observer-x3l5", h.serverName, []string{mtls.AgentRoleObserver})
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
	observe := func(address, version, group, leaf string, at time.Time) string {
		t.Helper()
		meta := map[string]string{"protocol": "tls", "server": address, "server_name": sni, "tls_version": version, "group": group,
			"pq_hybrid": "false", "certificate_visible": "false", "last_seen": at.UTC().Format(time.RFC3339), "payload_stored": "false"}
		if strings.Contains(strings.ToLower(group), "mlkem") {
			meta["pq_hybrid"] = "true"
		}
		ref := "tls " + address + " " + version + " " + group
		if leaf != "" {
			meta["certificate_visible"] = "true"
			ref += " " + leaf[:16]
		}
		inv, err := observer.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: []transport.InventoryFinding{{
			Kind: "tls_handshake", Ref: ref, Provenance: "network-observer:eth1", Fingerprint: leaf, RiskScore: 10, Metadata: meta,
		}}})
		if err != nil || inv.Recorded != 1 {
			t.Fatalf("observer report: %+v %v", inv, err)
		}
		findings, err := h.store.ListDiscoveryFindingsPage(ctx, h.tenant, inv.RunID, store.ZeroUUID, 10)
		if err != nil || len(findings) != 1 {
			t.Fatalf("observer finding: %+v %v", findings, err)
		}
		return findings[0].ID
	}
	// Neither a TLS 1.2 handshake presenting another leaf nor the pilot's own
	// leaf seen an hour before the probe is evidence for the canary.
	observe(canaryEndpoint.Addr, "TLSv1.2", "x25519", broadLeaf, time.Now().Add(5*time.Second))
	observe(canaryEndpoint.Addr, "TLSv1.2", "x25519", canaryLeaf, time.Now().Add(-time.Hour))
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if again := get(started.ID); again.Waves[0].Status != "awaiting_traffic" {
		t.Fatalf("another leaf or traffic before the probe moved the canary to %q", again.Waves[0].Status)
	}
	noSweepQueued("a canary with no real-client evidence")

	// Real clients negotiate TLS 1.3 with the ML-KEM hybrid after the probe.
	evidence := observe(canaryEndpoint.Addr, "TLSv1.3", "X25519MLKEM768", "", time.Now().Add(5*time.Second))
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	advanced := get(started.ID)
	canary := advanced.Waves[0]
	if advanced.Status != "running" || canary.Status != "assessed" || canary.TrafficCheckedAt == nil || advanced.Waves[1].Status != "probing" ||
		canary.Verdict == nil || !canary.Verdict.Ready || len(canary.Results) != 1 || canary.Results[0].Traffic == nil {
		t.Fatalf("pilot after real clients at the canary = %+v; want the canary assessed with traffic and the broad wave probing", advanced)
	}
	if tr := canary.Results[0].Traffic; tr.Outcome != compatlab.TrafficObserved || tr.FindingID != evidence || tr.Server != canaryEndpoint.Addr ||
		tr.TLSVersion != "TLSv1.3" || tr.Group != "X25519MLKEM768" || !tr.PQHybrid || tr.LastSeen == "" {
		t.Fatalf("canary traffic evidence = %+v; want the TLS 1.3 ML-KEM finding %s", tr, evidence)
	}

	// The broad wave's probe negotiates too, but nobody is seen at its
	// endpoint: once its window ends the pilot halts there.
	probeWaveAsRelay(t, ctx, h, started.ID, 2)
	if waiting := get(started.ID); waiting.Waves[1].Status != "awaiting_traffic" || waiting.Status != "running" {
		t.Fatalf("pilot after the broad wave's probe = %+v; want it awaiting traffic", waiting)
	}
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if early := get(started.ID); early.Status != "running" || early.Waves[1].Status != "awaiting_traffic" {
		t.Fatalf("the gate decided before the window ended: %+v", early)
	}
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(125*time.Second)); err != nil {
		t.Fatal(err)
	}
	halted := get(started.ID)
	broad := halted.Waves[1]
	if halted.Status != "halted" || halted.HaltedAtWave != "broad" || !strings.HasPrefix(halted.VerdictSummary, "NOT READY") ||
		!strings.Contains(halted.VerdictSummary, "broad-1") || broad.Status != "assessed" || broad.Verdict == nil || broad.Verdict.Unobserved != 1 ||
		len(broad.Results) != 1 || broad.Results[0].Traffic == nil || broad.Results[0].Traffic.Outcome != compatlab.TrafficUnobserved {
		t.Fatalf("pilot after the broad wave's window = %+v; want halted at broad with broad-1 unobserved", halted)
	}
	noSweepQueued("a halted pilot")
	if len(halted.SignedReport) == 0 {
		t.Fatal("the halted pilot has no signed readiness report")
	}
	var signed compatlab.SignedReport
	if err := json.Unmarshal(halted.SignedReport, &signed); err != nil {
		t.Fatal(err)
	}
	if !signed.Report.RequireObservedTraffic || signed.Report.Verdict.Ready || signed.Report.Verdict.Unobserved != 1 || signed.Report.Verdict.Negotiated != 2 {
		t.Fatalf("signed report = %+v; want the requirement and one unobserved client", signed.Report)
	}
	marks := map[string]string{}
	for _, r := range signed.Report.Results {
		marks[r.ClientID] = r.Traffic
	}
	if marks["canary-1"] != compatlab.TrafficObserved || marks["broad-1"] != compatlab.TrafficUnobserved {
		t.Fatalf("signed report traffic marks = %v", marks)
	}
	trusted := map[string]crypto.PublicKey{signed.KeyID: {Algorithm: signed.Algorithm, DER: signed.PublicKeyDER}}
	if err := signed.Verify(trusted); err != nil {
		t.Fatalf("signed report does not verify against the signer's readiness key: %v", err)
	}
	// A pass after the halt changes nothing.
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if after := get(started.ID); after.Status != "halted" || after.VerdictSummary != halted.VerdictSummary {
		t.Fatalf("a later pass changed a halted pilot: %+v", after)
	}
}
