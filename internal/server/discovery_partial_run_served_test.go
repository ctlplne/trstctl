// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A partial network run must say which target failed and why, in the run's
// error text and as one outcome per assigned target.
func TestServedPartialNetworkDiscoveryNamesTheFailedTarget(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	good, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	// A reachable listener that never speaks TLS: every accepted connection is
	// closed at once, so the probe fails at the handshake stage.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			conn, err := plain.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	bad := plain.Addr().String()

	h := newDiscoveryRelayHarness(t, "loopback-partial")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-partial",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{good.Host, bad},
			"allow_loopback": true,
			"segment":        "loopback-partial",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}

	executeNextDiscoveryRelayJob(t, h)

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get discovery run: status %d body %s", status, body)
	}
	var run struct {
		Status        string `json:"status"`
		Targets       int    `json:"targets"`
		Discovered    int    `json:"discovered"`
		Failed        int    `json:"failed"`
		Error         string `json:"error"`
		TargetResults []struct {
			Kind   string `json:"kind"`
			Target string `json:"target"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"target_results"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode run: %v (%s)", err, body)
	}
	if run.Status != "partial" || run.Targets != 2 || run.Discovered != 1 || run.Failed != 1 {
		t.Fatalf("run = %+v, want a partial run with one success and one failure", run)
	}
	if !strings.Contains(run.Error, bad+" failed") || !strings.Contains(run.Error, "handshake") {
		t.Fatalf("run error %q does not name the failed target and its handshake failure", run.Error)
	}
	if strings.Contains(run.Error, good.Host) {
		t.Fatalf("run error %q names the target that succeeded", run.Error)
	}
	if len(run.TargetResults) != 2 {
		t.Fatalf("target results = %+v, want one per assigned target", run.TargetResults)
	}
	outcomes := map[string]string{}
	for _, result := range run.TargetResults {
		if result.Kind != "network" {
			t.Fatalf("target result kind = %q, want network", result.Kind)
		}
		outcomes[result.Target] = result.Status
		if result.Target == bad && (result.Status != "failed" || !strings.Contains(result.Error, "handshake")) {
			t.Fatalf("failed target result = %+v, want failed with the handshake reason", result)
		}
	}
	if outcomes[good.Host] != "succeeded" || outcomes[bad] != "failed" {
		t.Fatalf("outcomes = %v, want %s succeeded and %s failed", outcomes, good.Host, bad)
	}

	// The list endpoint carries the same per-target outcomes for the console table.
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery runs: status %d body %s", status, body)
	}
	if !strings.Contains(string(body), `"target_results":[{`) {
		t.Fatalf("run list does not carry target results: %s", body)
	}
}
