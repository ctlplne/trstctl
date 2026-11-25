// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR024ServedMCPEvidenceWithholdsResultWhenAuditAppendFails(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withAIEnabled())
	token := seedScopedToken(t, h.store, h.tenant, "risk:read", "graph:read", "audit:read")
	const route = "/api/v1/mcp/tools/crypto_inventory"
	status, body := aiReq(t, h, http.MethodPost, route, token, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("control MCP evidence call: HTTP %d %s", status, body)
	}
	if err := h.log.Close(); err != nil {
		t.Fatal(err)
	}
	status, body = aiReq(t, h, http.MethodPost, route, token, map[string]any{})
	if status != http.StatusServiceUnavailable || bytes.Contains(body, []byte(`"tool":"crypto_inventory"`)) {
		t.Fatalf("MCP evidence escaped failed audit append: HTTP %d %s", status, body)
	}
}

func TestCR024ServedMCPEvidenceRateRefusalExposesAuditOutage(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withAIEnabled(), func(d *Deps) { d.AIRateMax = 1 })
	token := seedScopedToken(t, h.store, h.tenant, "risk:read", "graph:read", "audit:read")
	const route = "/api/v1/mcp/tools/crypto_inventory"
	status, body := aiReq(t, h, http.MethodPost, route, token, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("control MCP evidence call: HTTP %d %s", status, body)
	}
	if err := h.log.Close(); err != nil {
		t.Fatal(err)
	}
	status, body = aiReq(t, h, http.MethodPost, route, token, map[string]any{})
	if status != http.StatusServiceUnavailable || bytes.Contains(body, []byte(`"tool":"crypto_inventory"`)) {
		t.Fatalf("MCP rate refusal hid failed audit append: HTTP %d %s", status, body)
	}
}
