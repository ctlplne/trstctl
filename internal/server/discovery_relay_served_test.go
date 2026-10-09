// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func newDiscoveryRelayHarness(t *testing.T, segmentName string) *roleHarness {
	return newDiscoveryRelayHarnessWithDeps(t, segmentName)
}

func newDiscoveryRelayHarnessWithDeps(t *testing.T, segmentName string, options ...func(*Deps)) *roleHarness {
	t.Helper()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindDiscoveryRun}, options...)
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "discovery-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	if _, err := h.srv.orch.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{
		Name: segmentName, Ranges: []string{"10.42.0.0/16", "127.0.0.1"}, StalenessHours: 24,
	}); err != nil {
		t.Fatalf("declare discovery segment: %v", err)
	}
	return h
}

func TestServedDiscoveryPreflightRejectsStaleRelayAndRecoversAfterHeartbeat(t *testing.T) {
	h := newDiscoveryRelayHarness(t, "stale-relay-segment")
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token,
		"stale-relay-source", map[string]any{
			"name": "stale-relay-source", "kind": "network",
			"config": map[string]any{"targets": []string{"10.42.0.10:443"}, "segment": "stale-relay-segment", "allow_rfc1918": true},
		})
	if statusCode != http.StatusCreated {
		t.Fatalf("create source: %d %s", statusCode, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE agents SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`,
		h.tenant, agentRowID(h.tenant, h.agent), time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("age task relay heartbeat: %v", err)
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/discovery/sources/"+source.ID+"/preflight", token, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), `"ready":false`) ||
		!strings.Contains(string(body), "heartbeat") {
		t.Fatalf("stale relay preflight = %d %s, want actionable block", statusCode, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token,
		"stale-relay-run", map[string]any{"source_id": source.ID})
	if statusCode != http.StatusConflict || !strings.Contains(string(body), "heartbeat") {
		t.Fatalf("stale relay run = %d %s, want no queued job", statusCode, body)
	}
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "discovery-test", Status: "active",
	}); err != nil {
		t.Fatalf("restore task relay heartbeat: %v", err)
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/discovery/sources/"+source.ID+"/preflight", token, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), `"ready":true`) {
		t.Fatalf("recovered relay preflight = %d %s, want ready", statusCode, body)
	}
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
	segment, err := h.srv.orch.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{
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

// A legacy agent may have durably sealed a malformed terminal observation
// before a race fix. It must be closed as an audited failed run, without
// importing partial findings, so the original report is acknowledged and the
// agent can claim a clean retry after restart.
func TestServedDiscoveryCountMismatchFailsClosedAndUnblocksRelay(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	target := strings.TrimPrefix(tlsServer.URL, "https://")
	h := newDiscoveryRelayHarness(t, "report-recovery-loopback")
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	statusCode, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", operator, map[string]any{
		"name": "report-recovery-tls", "kind": "network",
		"config": map[string]any{
			"targets": []string{target}, "segment": "report-recovery-loopback",
			"allow_loopback": true, "relay_agent_id": agentRowID(h.tenant, h.agent),
		},
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("create discovery source: %d %s", statusCode, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	queue := func() string {
		t.Helper()
		code, queuedBody := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", operator,
			map[string]any{"source_id": source.ID})
		if code != http.StatusCreated {
			t.Fatalf("queue discovery: %d %s", code, queuedBody)
		}
		var run struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(queuedBody, &run); err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	claim := func() transport.ClaimedJob {
		t.Helper()
		claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{
			Kinds: []string{relay.KindDiscoveryRun}, Limit: 1,
		})
		if err != nil || len(claimed.Jobs) != 1 {
			t.Fatalf("claim discovery: jobs=%d err=%v", len(claimed.Jobs), err)
		}
		return claimed.Jobs[0]
	}
	failedRunID := queue()
	job := claim()
	invalid := segmentscan.Report{
		Mode: segmentscan.ModeTLS, Targets: 1, Discovered: 1,
		TargetResults: []segmentscan.TargetResult{{Target: target, Status: segmentscan.TargetSucceeded}},
	}
	encoded, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.client.ReportJobResult(t.Context(), h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), "sha256:sealed-count-mismatch"))
	if err != nil || response == nil || !response.Accepted {
		t.Fatalf("invalid sealed report was not closed as a failed run: response=%+v err=%v", response, err)
	}
	failed, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, failedRunID)
	if err != nil || failed.Status != "failed" || failed.Discovered != 0 || !strings.Contains(failed.Error, "findings count") {
		t.Fatalf("invalid report was not visible as a failed run: %+v err=%v", failed, err)
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/discovery/runs/"+failedRunID, operator, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), "findings count mismatch") {
		t.Fatalf("operator API hid the failed run: %d %s", statusCode, body)
	}
	if events := discoveryRelayEventCounts(t, h); events["agent.job.failed"] != 1 {
		t.Fatalf("signed inconsistent result produced %d agent failure audit events, want 1", events["agent.job.failed"])
	}
	var jobStatus, jobReason string
	var retainedReceipts int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(),
			`SELECT status, coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 AND id = $2`,
			h.tenant, job.JobID).Scan(&jobStatus, &jobReason); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(),
			`SELECT count(*) FROM agent_job_receipts WHERE tenant_id = $1 AND job_id = $2
			  AND attempt = $3 AND state = 'verified' AND signature <> ''`,
			h.tenant, job.JobID, job.Attempt).Scan(&retainedReceipts)
	}); err != nil || jobStatus != "failed" || jobReason != "discovery_findings_count_mismatch" || retainedReceipts != 1 {
		t.Fatalf("job/receipt recovery status=%q reason=%q signed_receipts=%d err=%v",
			jobStatus, jobReason, retainedReceipts, err)
	}
	findings, err := h.store.ListDiscoveryFindingsPage(t.Context(), h.tenant, failedRunID, store.ZeroUUID, 10)
	if err != nil || len(findings) != 0 {
		t.Fatalf("invalid report imported %d findings: %v", len(findings), err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("replay failed run: %v", err)
	}
	rebuilt, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, failedRunID)
	if err != nil || rebuilt.Status != "failed" || rebuilt.Discovered != 0 {
		t.Fatalf("replayed failed run: %+v err=%v", rebuilt, err)
	}

	retryRunID := queue()
	retryJob := claim()
	var intent relay.DiscoveryScanIntent
	if err := json.Unmarshal(retryJob.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	valid, err := relay.Sweep(t.Context(), intent)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	response, err = h.client.ReportJobResult(t.Context(), h.report(t, retryJob.JobID, retryJob.Attempt,
		transport.JobOutcomeExecuted, string(encoded), "sha256:clean-retry"))
	if err != nil || response == nil || !response.Accepted {
		t.Fatalf("clean retry: response=%+v err=%v", response, err)
	}
	retry, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, retryRunID)
	if err != nil || retry.Status != "succeeded" || retry.Discovered != 1 {
		t.Fatalf("relay did not recover on a new run: %+v err=%v", retry, err)
	}
}

func TestServedNetworkDiscoveryRequiresDeclaredSegmentAUD28(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
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

func TestServedNetworkDiscoveryPreflightBlocksGhostQueueWithoutRelay(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	statusCode, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/segments", tok,
		"relay-readiness-segment", map[string]any{
			"name": "relay-readiness-dmz", "ranges": []string{"192.0.2.0/24"}, "staleness_hours": 12,
		})
	if statusCode != http.StatusCreated {
		t.Fatalf("declare relay-readiness segment: %d %s", statusCode, body)
	}

	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/plans/preview", tok, map[string]any{
		"name": "relay-readiness-preview", "kind": "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}, "segment": "relay-readiness-dmz"},
	})
	if statusCode != http.StatusOK {
		t.Fatalf("preview without relay: %d %s", statusCode, body)
	}
	var preview struct {
		Ready            bool     `json:"ready"`
		ConnectionOrigin string   `json:"connection_origin"`
		BlockedReasons   []string `json:"blocked_reasons"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Ready || !strings.Contains(preview.ConnectionOrigin, "No network relay") ||
		len(preview.BlockedReasons) != 1 || !strings.Contains(preview.BlockedReasons[0], "Enroll") {
		t.Fatalf("preview readiness = %+v, want one exact no-relay blocker", preview)
	}

	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "relay-readiness-source", "kind": "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}, "segment": "relay-readiness-dmz"},
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("save source without relay: %d %s", statusCode, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}

	statusCode, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/discovery/sources/"+source.ID+"/preflight", tok, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("saved-source preflight without relay: %d %s", statusCode, body)
	}
	preview = struct {
		Ready            bool     `json:"ready"`
		ConnectionOrigin string   `json:"connection_origin"`
		BlockedReasons   []string `json:"blocked_reasons"`
	}{}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Ready || len(preview.BlockedReasons) != 1 {
		t.Fatalf("saved-source preflight = %+v, want blocked", preview)
	}
	statusCode, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/monitoring", tok, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), `"execution_ready":false`) ||
		!strings.Contains(string(body), "restore its authenticated heartbeat") {
		t.Fatalf("monitoring hid source execution blocker: %d %s", statusCode, body)
	}

	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok, map[string]any{
		"source_id": source.ID, "name": "blocked-hourly", "interval_seconds": 3600, "enabled": true,
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("save schedule for blocked source: %d %s", statusCode, body)
	}
	queued, scheduleErr := h.srv.RunDiscoverySchedulerOnce(t.Context())
	if queued != 0 || !errors.Is(scheduleErr, orchestrator.ErrDiscoveryRelayUnavailable) {
		t.Fatalf("scheduled run without relay = queued %d err %v, want no run and typed relay blocker", queued, scheduleErr)
	}

	statusCode, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID, "dry_run": true,
	})
	if statusCode != http.StatusConflict || !strings.Contains(string(body), "Enroll") {
		t.Fatalf("run without relay = %d %s, want structured 409 with remedy", statusCode, body)
	}
	statusCode, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs?limit=10", tok, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), `"items":[]`) {
		t.Fatalf("blocked run created durable ghost state: %d %s", statusCode, body)
	}
}

func TestServedNetworkDiscoveryBlocksWhenDispatchAllowlistIsEmpty(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "allowlist-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/segments", tok,
		"allowlist-readiness-segment", map[string]any{
			"name": "allowlist-readiness-dmz", "ranges": []string{"192.0.2.0/24"}, "staleness_hours": 12,
		})
	if statusCode != http.StatusCreated {
		t.Fatalf("declare allowlist-readiness segment: %d %s", statusCode, body)
	}

	plan := map[string]any{
		"name": "allowlist-readiness-preview", "kind": "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}, "segment": "allowlist-readiness-dmz"},
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/plans/preview", tok, plan)
	if statusCode != http.StatusOK {
		t.Fatalf("preview with empty dispatch allowlist: %d %s", statusCode, body)
	}
	var preview struct {
		Ready            bool     `json:"ready"`
		ConnectionOrigin string   `json:"connection_origin"`
		BlockedReasons   []string `json:"blocked_reasons"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	const guidance = "Enable discovery.run in agent_channel.claimable_job_kinds before starting this source."
	if preview.Ready || preview.ConnectionOrigin != "Agent dispatch is not enabled for discovery.run" ||
		len(preview.BlockedReasons) != 1 || preview.BlockedReasons[0] != guidance {
		t.Fatalf("preview readiness = %+v, want exact dispatch-allowlist blocker", preview)
	}

	statusCode, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "allowlist-readiness-source", "kind": "network",
		"config": map[string]any{"targets": []string{"192.0.2.10:443"}, "segment": "allowlist-readiness-dmz"},
	})
	if statusCode != http.StatusCreated {
		t.Fatalf("save source while dispatch is disabled: %d %s", statusCode, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
		t.Fatalf("decode source: id=%q err=%v", source.ID, err)
	}

	statusCode, body = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/discovery/sources/"+source.ID+"/preflight", tok, nil)
	if statusCode != http.StatusOK || !strings.Contains(string(body), guidance) || !strings.Contains(string(body), `"ready":false`) {
		t.Fatalf("saved-source preflight hid dispatch blocker: %d %s", statusCode, body)
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	if statusCode != http.StatusConflict || !strings.Contains(string(body), guidance) {
		t.Fatalf("run admission with empty dispatch allowlist = %d %s, want structured 409", statusCode, body)
	}
	runs, err := h.store.ListDiscoveryRunsPage(t.Context(), h.tenant, store.ZeroUUID, 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("blocked run still created durable work: runs=%d err=%v", len(runs), err)
	}
}
