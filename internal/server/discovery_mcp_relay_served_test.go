// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestServedNetworkDiscoveryFindsMCPServersAndARescanWritesNothingNewP7 (A20, A21,
// A22): a network discovery source with the MCP probe on, run by the bound relay,
// finds an MCP server on its declared range and records it as an MCP server finding
// with the authorization it requires; the probe sends no credential and the finding
// holds none. A rescan that observes the server unchanged records nothing (the
// finding is not seen again and no event is written); a changed server is recorded.
func TestServedNetworkDiscoveryFindsMCPServersAndARescanWritesNothingNewP7(t *testing.T) {
	var version atomic.Value
	version.Store("1.0.0")
	var credentials, requests atomic.Int64
	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			credentials.Add(1)
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"issues","version":%q}}}`,
			version.Load())
	}))
	defer mcpSrv.Close()
	target := strings.TrimPrefix(mcpSrv.URL, "http://")

	h := newDiscoveryRelayHarness(t, "mcp-lab")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "mcp-lab", "kind": "network",
		"config": map[string]any{"targets": []string{target}, "allow_loopback": true, "segment": "mcp-lab",
			"mcp": true, "mcp_schemes": []string{"http"}},
	})
	if status != http.StatusCreated {
		t.Fatalf("create source: %d %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	sweep := func() {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		if status != http.StatusCreated {
			t.Fatalf("start run: %d %s", status, body)
		}
		executeNextDiscoveryRelayJob(t, h)
	}
	type finding struct {
		Kind        string          `json:"kind"`
		Ref         string          `json:"ref"`
		Fingerprint string          `json:"fingerprint"`
		RiskScore   int             `json:"risk_score"`
		SeenCount   int             `json:"seen_count"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	mcpFindings := func() []finding {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?kind=mcp_server&source_kind=network", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("list findings: %d %s", status, body)
		}
		var page struct {
			Items []finding `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode findings: %v (%s)", err, body)
		}
		return page.Items
	}

	sweep()
	got := mcpFindings()
	if len(got) != 1 || got[0].Ref != mcpSrv.URL+"/mcp" || got[0].RiskScore != 80 || got[0].SeenCount != 1 {
		t.Fatalf("findings after the first sweep = %+v", got)
	}
	var meta map[string]any
	if err := json.Unmarshal(got[0].Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["auth"] != "none" || meta["server_name"] != "issues" || meta["server_version"] != "1.0.0" ||
		meta["transport"] != "streamable-http" || meta["credential_values"] != "not_collected" || meta["segment"] != "mcp-lab" {
		t.Fatalf("finding metadata = %v", meta)
	}

	sweep()
	if again := mcpFindings(); len(again) != 1 || again[0].SeenCount != 1 || again[0].Fingerprint != got[0].Fingerprint {
		t.Fatalf("an unchanged rescan recorded the endpoint again: %+v", again)
	}

	version.Store("1.1.0")
	sweep()
	changed := mcpFindings()
	if len(changed) != 2 {
		t.Fatalf("a changed server was not recorded: %+v", changed)
	}
	if credentials.Load() != 0 {
		t.Fatalf("the probe sent %d credentials", credentials.Load())
	}
	if requests.Load() == 0 {
		t.Fatal("the server was never probed")
	}
}
