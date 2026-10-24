// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

type exposureReachabilityRow struct {
	InventoryID  string   `json:"inventory_id"`
	EvidenceRefs []string `json:"evidence_refs"`
	Reachability *struct {
		Status    string `json:"status"`
		Endpoints []struct {
			Address             string `json:"address"`
			Outcome             string `json:"outcome"`
			Reachable           bool   `json:"reachable"`
			ObservedFingerprint string `json:"observed_fingerprint"`
			Agent               string `json:"agent"`
		} `json:"endpoints"`
	} `json:"reachability"`
}

// A102: an operator probes the exposed NHIs' public endpoints from a network
// relay. The probe is one discovery run under the product's exposure-probe
// source and one public-only relay sweep with no expectation; the relay's
// signed report becomes one finding per endpoint, and the exposure posture
// then shows, per record, what answered from the relay. A retried request
// converges on the same run and sweep.
func TestServedNHIExposureProbeRecordsRelayReachability(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	const answered, dark = "22222222-2222-2222-2222-22222222e003", "22222222-2222-2222-2222-22222222e013"
	now := time.Now().UTC()
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-22222222e001", "22222222-2222-2222-2222-22222222e002", answered, now,
		map[string]any{"public_endpoint": "https://api.partner.example.com/v1/hook", "callback_url": "http://hooks.partner.example.com/cb"})
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-22222222e011", "22222222-2222-2222-2222-22222222e012", dark, now,
		map[string]any{"public_endpoints": []string{"https://dark.partner.example.net"}})
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	const path = "/api/v1/nhi/posture/exposure/probe"

	// Reading the posture does not let anyone make a relay connect anywhere,
	// and only records in the exposure posture are probed.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, reader, "probe-reader", map[string]any{}); status != http.StatusForbidden {
		t.Fatalf("probe with nhi:read = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, writer, "probe-unknown", map[string]any{"inventory_ids": []string{"finding/22222222-2222-2222-2222-22222222ffff"}}); status != http.StatusUnprocessableEntity {
		t.Fatalf("probe of a record outside the posture = %d %s", status, body)
	}

	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, writer, "probe-1", map[string]any{"inventory_ids": []string{}})
	var queued struct {
		RunID     string `json:"run_id"`
		Vantage   string `json:"vantage"`
		Omitted   int    `json:"omitted"`
		Endpoints []struct {
			InventoryID string `json:"inventory_id"`
			Address     string `json:"address"`
			ServerName  string `json:"server_name"`
		} `json:"endpoints"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" || queued.Vantage != "relay" || queued.Omitted != 0 || len(queued.Endpoints) != 3 {
		t.Fatalf("probe = %d %s", status, body)
	}
	if status, replay := secretsReqKey(t, h.servedHarness, http.MethodPost, path, writer, "probe-1", map[string]any{"inventory_ids": []string{}}); status != http.StatusAccepted || !bytes.Equal(replay, body) {
		t.Fatalf("replay = %d %s", status, replay)
	}
	addresses := map[string]string{}
	for _, e := range queued.Endpoints {
		addresses[e.Address] = e.InventoryID + "|" + e.ServerName
	}
	if addresses["api.partner.example.com:443"] != "finding/"+answered+"|api.partner.example.com" ||
		addresses["hooks.partner.example.com:80"] != "finding/"+answered+"|hooks.partner.example.com" ||
		addresses["dark.partner.example.net:443"] != "finding/"+dark+"|dark.partner.example.net" {
		t.Fatalf("probe endpoints = %+v", queued.Endpoints)
	}

	// One public-only sweep, no expectation, bound to the run.
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("relay claim = %+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Exposure == nil || intent.Exposure.RunID != queued.RunID || len(intent.Endpoints) != 3 {
		t.Fatalf("claimed sweep = %s err=%v", job.Payload, err)
	}
	report := relay.EndpointVerifyReport{}
	var canonical []byte
	observedAt := time.Now().UTC().Unix()
	servedFP := strings.Repeat("c", 64)
	for _, want := range intent.Endpoints {
		if want.Fingerprint != "" || len(want.DNSNames) != 0 {
			t.Fatalf("exposure endpoint carries an expectation: %+v", want)
		}
		tr := transport.ProbeTranscript{Address: want.Address, ServerName: want.ServerName, Vantage: transport.VantageRelay, ObservedAtUnix: observedAt}
		switch want.Address {
		case "api.partner.example.com:443":
			tr.Reached, tr.ObservedFingerprint, tr.Mismatch = true, servedFP, certinfo.MismatchFingerprint
			tr.ObservedSANDigest = transport.SANSetDigest([]string{"api.partner.example.com"})
			tr.ObservedChainDigest = transport.ChainDigest(nil)
			tr.ChainBytes, tr.HandshakeMillis = 812, 4
			tr.NotBeforeUnix, tr.NotAfterUnix = observedAt-3600, observedAt+86400
		case "hooks.partner.example.com:80":
			tr.Error = "tlsprobe: handshake hooks.partner.example.com:80: tls: first record does not look like a TLS handshake"
		default:
			tr.Error = "tlsprobe: dial dark.partner.example.net:443: dial tcp: lookup dark.partner.example.net: no such host"
		}
		report.Results = append(report.Results, relay.EndpointVerifyResult{EndpointID: want.EndpointID, Transcript: tr})
		canonical = append(canonical, tr.Canonical()...)
		canonical = append(canonical, '\n')
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), transport.SweepDigest(canonical)))
	if err != nil || !res.Accepted {
		t.Fatalf("signed exposure sweep: %+v err=%v", res, err)
	}
	if again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 5, LeaseSeconds: 60}); err != nil || len(again.Jobs) != 0 {
		t.Fatalf("a retried probe queued a second sweep: %+v err=%v", again, err)
	}

	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.Targets != 3 || run.Discovered != 2 {
		t.Fatalf("probe run = %+v err=%v", run, err)
	}
	var findings int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM discovery_findings WHERE tenant_id=$1 AND run_id=$2 AND kind=$3`,
		h.tenant, queued.RunID, orchestrator.ExposureProbeFindingKind).Scan(&findings); err != nil || findings != 3 {
		t.Fatalf("probe findings = %d err=%v", findings, err)
	}

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
	var posture struct {
		Coverage []string `json:"coverage"`
		Summary  struct {
			Probed        int `json:"probed"`
			LiveReachable int `json:"live_reachable"`
		} `json:"summary"`
		Findings []exposureReachabilityRow `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil || posture.Summary.Probed != 2 || posture.Summary.LiveReachable != 1 ||
		!containsString(posture.Coverage, "relay_reachability_probes") {
		t.Fatalf("exposure posture = %d %s", status, body)
	}
	rows := map[string]exposureReachabilityRow{}
	for _, f := range posture.Findings {
		rows[f.InventoryID] = f
	}
	up, down := rows["finding/"+answered], rows["finding/"+dark]
	if up.Reachability == nil || up.Reachability.Status != "reachable" || len(up.Reachability.Endpoints) != 2 ||
		up.Reachability.Endpoints[0].Address != "api.partner.example.com:443" || up.Reachability.Endpoints[0].Outcome != orchestrator.ExposureProbeTLSCertificate ||
		up.Reachability.Endpoints[0].ObservedFingerprint != servedFP || up.Reachability.Endpoints[0].Agent == "" ||
		up.Reachability.Endpoints[1].Outcome != orchestrator.ExposureProbeListenerWithoutTLS || !up.Reachability.Endpoints[1].Reachable {
		t.Fatalf("answered row reachability = %+v", up.Reachability)
	}
	if down.Reachability == nil || down.Reachability.Status != "unreachable" || len(down.Reachability.Endpoints) != 1 ||
		down.Reachability.Endpoints[0].Outcome != orchestrator.ExposureProbeUnreachable || down.Reachability.Endpoints[0].Reachable {
		t.Fatalf("dark row reachability = %+v", down.Reachability)
	}
	probeEvidence := 0
	for _, ref := range up.EvidenceRefs {
		if strings.HasPrefix(ref, "exposure_probe:") {
			probeEvidence++
		}
	}
	if probeEvidence != 2 {
		t.Fatalf("answered row evidence = %v; want its two probe findings", up.EvidenceRefs)
	}
}
