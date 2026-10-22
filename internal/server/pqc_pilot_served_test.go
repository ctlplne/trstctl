// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/pqc/compatlab"
)

// refusingListener accepts TCP connections and closes them before any TLS
// handshake completes: a client that reaches the endpoint but is refused.
func refusingListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

// closedPort returns an address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// probeWaveAsRelay claims the pilot's queued sweep as the network relay,
// performs the real handshakes with the relay's own verification engine, and
// reports the signed sweep exactly as the shipped relay does.
func probeWaveAsRelay(t *testing.T, ctx context.Context, h *roleHarness, wantPilot string, wantWave int) {
	t.Helper()
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("relay claim for wave %d = %+v err=%v", wantWave, claimed, err)
	}
	job := claimed.Jobs[0]
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Pilot == nil || intent.Pilot.PilotID != wantPilot || intent.Pilot.Wave != wantWave {
		t.Fatalf("claimed sweep is not pilot %s wave %d: %s err=%v", wantPilot, wantWave, job.Payload, err)
	}
	report := relay.EndpointVerifyReport{}
	var canonical []byte
	for _, want := range intent.Endpoints {
		res, err := verify.Endpoint(ctx, verify.Request{
			Address: want.Address, ServerName: want.ServerName, Vantage: transport.VantageRelay, Timeout: 5 * time.Second,
			Expect: certinfo.Expectation{SHA256Fingerprint: want.Fingerprint},
		})
		if err != nil {
			t.Fatalf("probe %s: %v", want.Address, err)
		}
		report.Results = append(report.Results, relay.EndpointVerifyResult{EndpointID: want.EndpointID, Transcript: res.Transcript, Detail: res.Verdict.Detail})
		canonical = append(canonical, res.Transcript.Canonical()...)
		canonical = append(canonical, '\n')
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), transport.SweepDigest(canonical)))
	if err != nil || !res.Accepted {
		t.Fatalf("signed sweep report for wave %d: %+v err=%v", wantWave, res, err)
	}
}

type servedPQCPilot struct {
	ID             string          `json:"id"`
	Status         string          `json:"status"`
	WaveCount      int             `json:"wave_count"`
	CurrentWave    int             `json:"current_wave"`
	HaltedAtWave   string          `json:"halted_at_wave"`
	VerdictSummary string          `json:"verdict_summary"`
	SignedReport   json.RawMessage `json:"signed_report"`
	Waves          []struct {
		Index   int    `json:"index"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Results []struct {
			TargetID string `json:"target_id"`
			Outcome  string `json:"outcome"`
			ChainB   int    `json:"chain_bytes"`
		} `json:"results"`
		Verdict *struct {
			Ready bool `json:"ready"`
			Halt  bool `json:"halt"`
		} `json:"verdict"`
	} `json:"waves"`
}

func getServedPilot(t *testing.T, h *roleHarness, token, id string) servedPQCPilot {
	t.Helper()
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/pilots/"+id, token, nil)
	if code != http.StatusOK {
		t.Fatalf("get pilot = %d %s", code, body)
	}
	var out servedPQCPilot
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A28/A29: a pilot's waves are relay sweeps dispatched in order; the canary's
// refusal halts the pilot before any later wave is dispatched, and a pilot
// whose every wave negotiates completes with a readiness report signed inside
// the isolated signer that verifies offline against the signer's own key.
func TestServedPQCPilotWavesHaltOnCanaryRefusalAndSignTheReport(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	serving, err := tlsprobe.NewServingTestServer("pilot.pq.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(serving.Close)
	leafInfo, err := certinfo.Inspect(caCertDER(t, serving.LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	refusing := refusingListener(t)
	unreachable := closedPort(t)
	fp := strings.ToLower(leafInfo.SHA256Fingerprint)

	// A pilot names the authority whose leaf it proves; without one there is
	// nothing for the signed report to be about.
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "pilot-no-authority", map[string]any{
		"name": "no authority", "waves": []map[string]any{{"name": "canary", "targets": []map[string]any{{"target_id": "x", "address": serving.Addr, "fingerprint": fp}}}},
	}); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "authority_id") {
		t.Fatalf("pilot without an authority = %d %s; want 422 naming authority_id", code, body)
	}

	// Pilot 1: the canary wave mixes one negotiating client with one that
	// refuses the handshake; the second wave must never be probed.
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "pilot-halt", map[string]any{
		"name": "pq pilot halt", "authority_id": "pq-issuing-ca", "waves": []map[string]any{
			{"name": "canary", "targets": []map[string]any{
				{"target_id": "good-1", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp},
				{"target_id": "refuses-1", "address": refusing, "fingerprint": fp},
			}},
			{"name": "broad", "targets": []map[string]any{
				{"target_id": "never-probed", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp},
			}},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("start pilot = %d %s", code, body)
	}
	var started servedPQCPilot
	if err := json.Unmarshal(body, &started); err != nil || started.Status != "running" || started.CurrentWave != 1 || len(started.Waves) != 2 || started.Waves[0].Status != "probing" {
		t.Fatalf("started pilot = %+v err=%v; want wave 1 probing", started, err)
	}
	// Idempotent start: the same key returns the same pilot, no second sweep.
	if again, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "pilot-halt", map[string]any{"name": "pq pilot halt", "authority_id": "pq-issuing-ca", "waves": []map[string]any{{"name": "canary", "targets": []map[string]any{{"target_id": "good-1", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp}, {"target_id": "refuses-1", "address": refusing, "fingerprint": fp}}}, {"name": "broad", "targets": []map[string]any{{"target_id": "never-probed", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp}}}}}); again != http.StatusCreated || !strings.Contains(string(body), started.ID) {
		t.Fatalf("replayed start = %d %s", again, body)
	}
	probeWaveAsRelay(t, ctx, h, started.ID, 1)
	halted := getServedPilot(t, h, token, started.ID)
	if halted.Status != "halted" || halted.HaltedAtWave != "canary" || !strings.HasPrefix(halted.VerdictSummary, "HALT") {
		t.Fatalf("pilot after the canary = %+v; want halted at the canary", halted)
	}
	outcomes := map[string]string{}
	for _, r := range halted.Waves[0].Results {
		outcomes[r.TargetID] = r.Outcome
	}
	if outcomes["good-1"] != string(compatlab.OutcomeNegotiated) || outcomes["refuses-1"] != string(compatlab.OutcomeRejected) {
		t.Fatalf("canary outcomes = %v; want good-1 negotiated and refuses-1 rejected", outcomes)
	}
	if halted.Waves[1].Status != "skipped" {
		t.Fatalf("second wave after a halt = %q; want skipped", halted.Waves[1].Status)
	}
	if claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 5, LeaseSeconds: 60}); err != nil || len(claimed.Jobs) != 0 {
		t.Fatalf("a halted pilot still dispatched a sweep: %+v err=%v", claimed, err)
	}
	if len(halted.SignedReport) == 0 {
		t.Fatal("a halted pilot has no signed readiness report")
	}
	var haltedReport compatlab.SignedReport
	if err := json.Unmarshal(halted.SignedReport, &haltedReport); err != nil {
		t.Fatal(err)
	}
	if !haltedReport.Report.Verdict.Halt || haltedReport.Report.Verdict.Rejected != 1 || haltedReport.Report.Verdict.NotAttempted != 1 {
		t.Fatalf("halted report verdict = %+v; want halt with one rejection and the never-probed client not attempted", haltedReport.Report.Verdict)
	}

	// Pilot 2: an unreachable canary cannot vouch for a rollout either.
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "pilot-unreachable", map[string]any{
		"name": "pq pilot unreachable", "authority_id": "pq-issuing-ca", "waves": []map[string]any{
			{"name": "canary", "targets": []map[string]any{{"target_id": "dark-1", "address": unreachable, "fingerprint": fp}}},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("start unreachable pilot = %d %s", code, body)
	}
	var dark servedPQCPilot
	_ = json.Unmarshal(body, &dark)
	probeWaveAsRelay(t, ctx, h, dark.ID, 1)
	if got := getServedPilot(t, h, token, dark.ID); got.Status != "halted" || got.Waves[0].Results[0].Outcome != string(compatlab.OutcomeUnreachable) {
		t.Fatalf("unreachable canary pilot = %+v; want halted with an unreachable result", got)
	}

	// Pilot 3: every wave negotiates; the pilot completes and its report is
	// signed by the signer's readiness-report key and verifies offline.
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "pilot-complete", map[string]any{
		"name": "pq pilot complete", "authority_id": "pq-issuing-ca", "waves": []map[string]any{
			{"name": "canary", "targets": []map[string]any{{"target_id": "good-a", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp}}},
			{"name": "broad", "targets": []map[string]any{{"target_id": "good-b", "address": serving.Addr, "server_name": "pilot.pq.example.test", "fingerprint": fp}}},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("start completing pilot = %d %s", code, body)
	}
	var complete servedPQCPilot
	_ = json.Unmarshal(body, &complete)
	probeWaveAsRelay(t, ctx, h, complete.ID, 1)
	if mid := getServedPilot(t, h, token, complete.ID); mid.Status != "running" || mid.CurrentWave != 2 || mid.Waves[1].Status != "probing" {
		t.Fatalf("pilot after a clean canary = %+v; want wave 2 probing", mid)
	}
	probeWaveAsRelay(t, ctx, h, complete.ID, 2)
	done := getServedPilot(t, h, token, complete.ID)
	if done.Status != "completed" || !strings.HasPrefix(done.VerdictSummary, "Ready") || len(done.SignedReport) == 0 {
		t.Fatalf("completed pilot = %+v", done)
	}
	var signed compatlab.SignedReport
	if err := json.Unmarshal(done.SignedReport, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.Report.AuthorityID != "pq-issuing-ca" || !signed.Report.Verdict.Ready || signed.Report.Verdict.Negotiated != 2 || len(signed.Report.Results) != 2 {
		t.Fatalf("signed report = %+v", signed.Report)
	}
	for _, r := range signed.Report.Results {
		if r.HandshakeBytes <= 0 || r.LatencyMS < 0 {
			t.Fatalf("report result carries no handshake cost: %+v", r)
		}
	}
	trusted := map[string]crypto.PublicKey{signed.KeyID: {Algorithm: signed.Algorithm, DER: signed.PublicKeyDER}}
	if err := signed.Verify(trusted); err != nil {
		t.Fatalf("signed report does not verify against the signer's readiness key: %v", err)
	}
	tampered := signed
	tampered.Report.Verdict.Rejected = 0
	tampered.Report.Verdict.Summary = "Ready: edited"
	if err := tampered.Verify(trusted); err == nil {
		t.Fatal("an edited report still verified")
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/pilots", token, nil)
	if code != http.StatusOK || strings.Count(string(body), `"status":"`) < 3 {
		t.Fatalf("list pilots = %d %s", code, body)
	}
}
