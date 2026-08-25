// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func newDiscoveryRelayHarness(t *testing.T, segmentName string) *roleHarness {
	t.Helper()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindDiscoveryRun)
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "discovery-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	if _, err := h.store.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{
		Name: segmentName, Ranges: []string{"10.42.0.0/16", "127.0.0.1"}, StalenessHours: 24,
	}); err != nil {
		t.Fatalf("declare discovery segment: %v", err)
	}
	return h
}

func executeNextDiscoveryRelayJob(t *testing.T, h *roleHarness) relay.DiscoveryReport {
	t.Helper()
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{
		Kinds: []string{relay.KindDiscoveryRun}, Limit: 1,
	})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim discovery job: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	var intent relay.DiscoveryScanIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	report, err := relay.Sweep(t.Context(), intent)
	if err != nil {
		t.Fatalf("execute discovery sweep: %v", err)
	}
	detail, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := h.client.ReportJobResult(t.Context(), h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(detail), "sha256:discovery-test"))
	if err != nil || !accepted.Accepted {
		t.Fatalf("report discovery result: accepted=%v err=%v", accepted, err)
	}
	return report
}

// TestServedNetworkDiscoveryUsesTheBoundRelayAUD28 is the missing production
// journey behind C2. Queueing resolves the source into the exact command a relay
// can execute, the control-plane worker leaves that command alone, and the
// signed result is what advances the run and creates metadata-only findings.
func TestServedNetworkDiscoveryUsesTheBoundRelayAUD28(t *testing.T) {
	var controlPlaneDials atomic.Int64
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	tlsSrv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			controlPlaneDials.Add(1)
		}
	}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindDiscoveryRun)
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "aud28-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	segment, err := h.store.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{
		Name: "isolated-core", Ranges: []string{"127.0.0.1"}, StalenessHours: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	statusCode, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "relay-only-tls",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
			"segment":        segment.Name,
			"relay_agent_id": relayID,
		},
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("create relay source: %d %s", statusCode, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}

	statusCode, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("queue relay run: %d %s", statusCode, body)
	}
	var queued struct {
		ID                string `json:"id"`
		Status            string `json:"status"`
		Execution         string `json:"execution"`
		Segment           string `json:"segment"`
		RequiredAgentRole string `json:"required_agent_role"`
		RequiredAgentID   string `json:"required_agent_id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatal(err)
	}
	if queued.ID == "" || queued.Status != "queued" || queued.Execution != "relay" ||
		queued.Segment != segment.Name || queued.RequiredAgentRole != mtls.AgentRoleNetwork || queued.RequiredAgentID != relayID {
		t.Fatalf("queued run lost relay binding: %+v", queued)
	}

	// The assembled control-plane dispatcher sees the row, but must not dial the
	// target. DeferDelivery leaves it pending and refunds the attempt.
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain relay-owned row: %v", err)
	}
	if got := controlPlaneDials.Load(); got != 0 {
		t.Fatalf("control plane executed relay-owned scan: %d target connections", got)
	}
	wrongAgentJobs, err := h.store.ClaimAgentJobs(t.Context(), h.tenant, uuid.NewString(),
		[]string{relay.KindDiscoveryRun}, []string{mtls.AgentRoleNetwork}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(wrongAgentJobs) != 0 {
		t.Fatalf("wrong relay selector claimed bound scan: jobs=%d err=%v", len(wrongAgentJobs), err)
	}
	wrongRoleJobs, err := h.store.ClaimAgentJobs(t.Context(), h.tenant, relayID,
		[]string{relay.KindDiscoveryRun}, []string{mtls.AgentRoleHost}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(wrongRoleJobs) != 0 {
		t.Fatalf("host role claimed network scan: jobs=%d err=%v", len(wrongRoleJobs), err)
	}

	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{
		Kinds: []string{relay.KindDiscoveryRun}, Limit: 1,
	})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("network relay claim: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	var intent relay.DiscoveryScanIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.ID != queued.ID || intent.SourceID != source.ID || intent.Mode != relay.DiscoveryModeTLS ||
		intent.Segment != segment.Name || intent.RequiredAgentRole != mtls.AgentRoleNetwork ||
		intent.RequiredAgentID != relayID || len(intent.Targets) != 1 || intent.Targets[0] != u.Host {
		t.Fatalf("claimed command is not the resolved scan intent: %+v", intent)
	}

	report, err := relay.Sweep(t.Context(), intent)
	if err != nil {
		t.Fatalf("relay sweep: %v", err)
	}
	if got := controlPlaneDials.Load(); got != 1 {
		t.Fatalf("target was not reached exactly once by relay execution: %d", got)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	wrongMode := report
	wrongMode.Mode = relay.DiscoveryModeSSH
	wrongModeJSON, err := json.Marshal(wrongMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ReportJobResult(t.Context(), h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(wrongModeJSON), "sha256:wrong-mode")); err == nil {
		t.Fatal("signed but command-mismatched relay report was accepted")
	}
	stillQueued, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, queued.ID)
	if err != nil || stillQueued.Status != "queued" {
		t.Fatalf("rejected report changed run: status=%q err=%v", stillQueued.Status, err)
	}
	beforeEvents := discoveryRelayEventCounts(t, h)
	reports := []*transport.ReportJobResultRequest{
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), "sha256:relay-discovery-transcript"),
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), "sha256:relay-discovery-transcript"),
	}
	type reportResult struct {
		accepted bool
		err      error
	}
	results := make(chan reportResult, len(reports))
	for _, request := range reports {
		go func() {
			response, reportErr := h.client.ReportJobResult(t.Context(), request)
			results <- reportResult{accepted: response != nil && response.Accepted, err: reportErr}
		}()
	}
	acceptedCount := 0
	for range reports {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent signed relay report: %v", result.err)
		}
		if result.accepted {
			acceptedCount++
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("concurrent signed relay reports accepted=%d, want exactly one", acceptedCount)
	}
	afterEvents := discoveryRelayEventCounts(t, h)
	for _, eventType := range []string{
		projections.EventDiscoveryRunStarted,
		projections.EventCertificateRecorded,
		projections.EventDiscoveryFindingRecorded,
		projections.EventDiscoveryRunCompleted,
	} {
		if delta := afterEvents[eventType] - beforeEvents[eventType]; delta != 1 {
			t.Fatalf("concurrent receipt appended %d %s events, want one", delta, eventType)
		}
	}

	run, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "succeeded" || run.Targets != 1 || run.Discovered != 1 || run.ExecutedByAgentID != relayID || run.Segment != segment.Name {
		t.Fatalf("relay result did not project terminal provenance: %+v", run)
	}
	swept, err := h.store.GetDiscoverySegmentByName(t.Context(), h.tenant, segment.Name)
	if err != nil || swept.LastSweptAt == nil || swept.LastSweptBy != relayID || swept.LastFoundCount != 1 {
		t.Fatalf("relay result did not project segment freshness: segment=%+v err=%v", swept, err)
	}
	findings, err := h.store.ListDiscoveryFindingsPage(t.Context(), h.tenant, queued.ID, store.ZeroUUID, 10)
	if err != nil || len(findings) != 1 {
		t.Fatalf("relay findings: count=%d err=%v", len(findings), err)
	}
	if findings[0].Ref != u.Host || findings[0].Fingerprint == "" || findings[0].Kind != "x509_certificate" {
		t.Fatalf("bad relay finding: %+v", findings[0])
	}

	replayed, err := h.client.ReportJobResult(t.Context(), h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(reportJSON), "sha256:relay-discovery-transcript"))
	if err != nil || replayed.Accepted {
		t.Fatalf("same-key relay replay: accepted=%v err=%v", replayed, err)
	}
	findings, err = h.store.ListDiscoveryFindingsPage(t.Context(), h.tenant, queued.ID, store.ZeroUUID, 10)
	if err != nil || len(findings) != 1 {
		t.Fatalf("replay duplicated relay findings: count=%d err=%v", len(findings), err)
	}

	// A second tenant cannot read or claim the bound command even if it knows
	// every identifier. This exercises the real RLS role, not an application-only
	// ownership check.
	otherTenant := uuid.NewString()
	if _, err := h.store.GetDiscoveryRun(t.Context(), otherTenant, queued.ID); err == nil {
		t.Fatal("cross-tenant discovery run read bypassed RLS")
	}
	crossTenantJobs, err := h.store.ClaimAgentJobs(t.Context(), otherTenant, relayID,
		[]string{relay.KindDiscoveryRun}, []string{mtls.AgentRoleNetwork}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(crossTenantJobs) != 0 {
		t.Fatalf("cross-tenant relay claim: jobs=%d err=%v", len(crossTenantJobs), err)
	}

	// A restart/full replay must reproduce command binding, actual executor,
	// terminal counts, findings, and the segment observation from immutable
	// events. The independently declared segment survives read-model rebuilds.
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild relay discovery read model: %v", err)
	}
	rebuilt, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Execution != run.Execution || rebuilt.Segment != run.Segment ||
		rebuilt.RequiredAgentRole != run.RequiredAgentRole || rebuilt.RequiredAgentID != run.RequiredAgentID ||
		rebuilt.ExecutedByAgentID != run.ExecutedByAgentID || rebuilt.Status != run.Status ||
		rebuilt.Targets != run.Targets || rebuilt.Discovered != run.Discovered || rebuilt.Failed != run.Failed ||
		rebuilt.Rejected != run.Rejected || rebuilt.Blocked != run.Blocked {
		t.Fatalf("rebuild changed relay run authority:\n warm=%+v\nrebuilt=%+v", run, rebuilt)
	}
	rebuiltFindings, err := h.store.ListDiscoveryFindingsPage(t.Context(), h.tenant, queued.ID, store.ZeroUUID, 10)
	if err != nil || len(rebuiltFindings) != 1 || rebuiltFindings[0].Ref != findings[0].Ref ||
		rebuiltFindings[0].Fingerprint != findings[0].Fingerprint || rebuiltFindings[0].Provenance != findings[0].Provenance {
		t.Fatalf("rebuild changed relay findings: findings=%+v err=%v", rebuiltFindings, err)
	}
	rebuiltSegment, err := h.store.GetDiscoverySegmentByName(t.Context(), h.tenant, segment.Name)
	if err != nil || rebuiltSegment.LastSweptAt == nil || rebuiltSegment.LastSweptBy != swept.LastSweptBy ||
		rebuiltSegment.LastFoundCount != swept.LastFoundCount || !rebuiltSegment.LastSweptAt.Equal(*swept.LastSweptAt) {
		t.Fatalf("rebuild changed segment observation: segment=%+v err=%v", rebuiltSegment, err)
	}
}

func discoveryRelayEventCounts(t *testing.T, h *roleHarness) map[string]int {
	t.Helper()
	counts := map[string]int{}
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		counts[event.Type]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return counts
}

func TestServedNetworkDiscoveryRequiresDeclaredSegmentAUD28(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	statusCode, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name":   "unbound-network",
		"kind":   "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}},
	})
	if statusCode != http.StatusBadRequest || !json.Valid(body) {
		t.Fatalf("unbound network source = %d %s, want structured 400", statusCode, body)
	}

	segmentKey := "aud28-declare-segment"
	statusCode, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/segments", tok, segmentKey, map[string]any{
		"name": "served-dmz", "ranges": []string{"192.0.2.0/24"}, "staleness_hours": 12,
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("declare served segment: %d %s", statusCode, body)
	}
	firstBody := append([]byte(nil), body...)
	statusCode, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/segments", tok, segmentKey, map[string]any{
		"name": "served-dmz", "ranges": []string{"192.0.2.0/24"}, "staleness_hours": 12,
	})
	if statusCode != http.StatusCreated || string(body) != string(firstBody) {
		t.Fatalf("segment declaration replay = %d %s, want exact cached 201", statusCode, body)
	}
	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/plans/preview", tok, map[string]any{
		"name": "bounded-preview", "kind": "network",
		"config": map[string]any{
			"cidrs": []string{"192.0.2.0/30"}, "ports": []int{443},
			"exclude_cidrs": []string{"192.0.2.1/32"}, "segment": "served-dmz",
		},
	})
	if statusCode != http.StatusOK {
		t.Fatalf("preview served segment: %d %s", statusCode, body)
	}
	var preview struct {
		NormalizedTargetCount int      `json:"normalized_target_count"`
		ExcludedTargetCount   int      `json:"excluded_target_count"`
		NormalizedTargets     []string `json:"normalized_targets"`
		SideEffects           bool     `json:"side_effects"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.NormalizedTargetCount != 3 || preview.ExcludedTargetCount != 1 || len(preview.NormalizedTargets) != 3 || preview.SideEffects {
		t.Fatalf("server-calculated plan = %+v", preview)
	}
	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/plans/preview", tok, map[string]any{
		"name": "outside-preview", "kind": "network",
		"config": map[string]any{"targets": []string{"198.51.100.10:443"}, "segment": "served-dmz"},
	})
	if statusCode != http.StatusBadRequest || !strings.Contains(string(body), "outside declared segment") {
		t.Fatalf("out-of-scope preview = %d %s, want structured 400", statusCode, body)
	}
	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "bound-network", "kind": "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}, "segment": "served-dmz"},
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("create source against served segment declaration: %d %s", statusCode, body)
	}
	if _, err := h.store.GetDiscoverySegmentByName(t.Context(), h.tenant, "served-dmz"); err != nil {
		t.Fatalf("served declaration did not project: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`DELETE FROM discovery_segments WHERE tenant_id = $1 AND name = $2`, h.tenant, "served-dmz"); err != nil {
		t.Fatalf("remove segment projection before cold replay: %v", err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild served segment declaration: %v", err)
	}
	if _, err := h.store.GetDiscoverySegmentByName(t.Context(), h.tenant, "served-dmz"); err != nil {
		t.Fatalf("served segment declaration did not survive replay: %v", err)
	}
}
