// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

// A manual import is useful evidence, but cannot speak as an authenticated
// host agent to create an executable trust edge or dependency relationship.
func TestServedManualDiscoveryCannotForgeAgentGraphAuthority(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "graph:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", token,
		"manual-agent-spoof-source", map[string]any{
			"name": "manual-agent-spoof", "kind": "manual",
			"config": map[string]any{"findings": []any{map[string]any{
				"kind": "trust-store", "ref": "qa-manual-anchor", "fingerprint": "sha256:manual-anchor",
				"provenance": "trust-store:frontdoors", "metadata": map[string]any{
					"host": "frontdoors", "agent_id": "11111111-1111-4111-8111-111111111111", "trust_store_kind": "os",
				},
			}}},
		})
	if status != http.StatusCreated {
		t.Fatalf("create manual source: %d %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", token,
		"manual-agent-spoof-run", map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("queue manual run: %d %s", status, body)
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordDiscoveryFinding(t.Context(), h.tenant, store.DiscoveryFinding{
		RunID: run.ID, SourceID: source.ID, Kind: "trust-store", Ref: "qa-manual-anchor",
		Provenance: "trust-store:frontdoors", Fingerprint: "sha256:manual-anchor",
		Metadata: json.RawMessage(`{"host":"frontdoors","agent_id":"11111111-1111-4111-8111-111111111111","trust_store_kind":"os"}`),
	}); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
	if status != http.StatusOK {
		t.Fatalf("graph: %d %s", status, body)
	}
	var got struct {
		Nodes []graph.Node `json:"nodes"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, node := range got.Nodes {
		if node.Kind == graph.KindTrustStore {
			t.Fatalf("manual finding gained executable trust-store node: %+v", node)
		}
	}
	if _, err := h.srv.orch.RecordDiscoveryFinding(t.Context(), h.tenant, store.DiscoveryFinding{
		RunID: run.ID, SourceID: source.ID, Kind: "service_dependency", Ref: "qa-manual-dependency",
		Provenance: "manual:frontdoors", Fingerprint: "sha256:manual-dependency",
		Metadata: json.RawMessage(`{"workload":"unmapped-forgery","target":"edge","agent_id":"11111111-1111-4111-8111-111111111111"}`),
	}); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
	if status != http.StatusOK {
		t.Fatalf("manual dependency caused graph denial of service: %d %s", status, body)
	}
}
