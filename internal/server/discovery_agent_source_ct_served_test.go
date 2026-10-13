// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestServedCTMonitoringCannotClaimAgentInventorySource(t *testing.T) {
	put := func(t *testing.T, h *servedHarness, token, name, key string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPut,
			"/api/v1/discovery/ct-monitoring", token, key, map[string]any{
				"name": name, "logs": []string{"https://ct.example.com/log"},
				"watched_domains": []string{"example.com"}, "run_now": false,
			})
		if status != http.StatusBadRequest {
			t.Fatalf("CT monitoring claimed agent source %q: %d %s", name, status, body)
		}
	}
	t.Run("before agent reports", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{})
		token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
		put(t, h, token, "agent:future-host:trust-store", "ct-preclaim-agent-source")
	})
	t.Run("after authenticated report", func(t *testing.T) {
		h := newRoleHarness(t, []string{mtls.AgentRoleHost})
		if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{Version: "ct-source-guard", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.client.ReportInventory(t.Context(), &transport.InventoryRequest{
			SourceKind: "trust-store", Findings: []transport.InventoryFinding{{
				Kind: "trust-store", Ref: "qa:local-root", Fingerprint: "sha256:qa-root",
				Metadata: map[string]string{"trust_store_kind": "os"},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		name := "agent:" + h.agent + ":trust-store"
		before, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, name)
		if err != nil {
			t.Fatal(err)
		}
		token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
		put(t, h.servedHarness, token, name, "ct-overwrite-agent-source")
		after, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, name)
		if err != nil {
			t.Fatal(err)
		}
		if after.ID != before.ID || after.Kind != "agent" || !bytes.Equal(after.Config, before.Config) {
			t.Fatalf("CT update changed authenticated source: before=%+v after=%+v", before, after)
		}
	})
}
