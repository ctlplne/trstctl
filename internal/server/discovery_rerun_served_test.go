// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Running the same network source twice must not open a second finding per
// listener: the console shows the estate once, with first/last seen and a count.
func TestServedNetworkDiscoveryRerunRefreshesFindingsInsteadOfDuplicating(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newDiscoveryRelayHarness(t, "loopback-rerun")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-rerun",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
			"segment":        "loopback-rerun",
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

	runIDs := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
			"source_id": source.ID,
		})
		if status != http.StatusCreated {
			t.Fatalf("start discovery run %d: status %d body %s", i+1, status, body)
		}
		var queued struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &queued); err != nil {
			t.Fatalf("decode queued run: %v (%s)", err, body)
		}
		runIDs = append(runIDs, queued.ID)
		executeNextDiscoveryRelayJob(t, h)

		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("get discovery run %d: status %d body %s", i+1, status, body)
		}
		var completed struct {
			Status     string `json:"status"`
			Discovered int    `json:"discovered"`
		}
		if err := json.Unmarshal(body, &completed); err != nil {
			t.Fatalf("decode completed run: %v (%s)", err, body)
		}
		if completed.Status != "succeeded" || completed.Discovered != 1 {
			t.Fatalf("run %d = %+v, want one successful discovery", i+1, completed)
		}
	}

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Ref         string    `json:"ref"`
			RunID       string    `json:"run_id"`
			SeenCount   int       `json:"seen_count"`
			FirstSeenAt time.Time `json:"first_seen_at"`
			LastSeenAt  time.Time `json:"last_seen_at"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("findings after two runs = %d (%s), want the one listener once", len(findings.Items), body)
	}
	f := findings.Items[0]
	if f.Ref != u.Host || f.SeenCount != 2 || f.RunID != runIDs[1] {
		t.Fatalf("finding = %+v, want ref %s seen twice on the latest run %s", f, u.Host, runIDs[1])
	}
	if f.FirstSeenAt.IsZero() || f.LastSeenAt.Before(f.FirstSeenAt) {
		t.Fatalf("first/last seen = %s/%s, want last seen at or after first seen", f.FirstSeenAt, f.LastSeenAt)
	}

	// The first run's page still resolves to the same row through its latest run.
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?run_id="+runIDs[1], tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list findings by run: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &findings); err != nil || len(findings.Items) != 1 {
		t.Fatalf("findings for the latest run = %d (%v)", len(findings.Items), err)
	}

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 {
		t.Fatalf("inventory after two runs = %d certificates, want the one listener once", len(certs.Items))
	}
}
