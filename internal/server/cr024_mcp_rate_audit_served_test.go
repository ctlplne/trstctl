// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR024ServedMCPRESTAndWriteRateRefusalsExposeAuditOutage(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withMCPWriteToolsEnabled(), func(d *Deps) { d.AIRateMax = 1 })
	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue", "identities:write", "graph:read")
	const restRoute = "/api/v1/mcp/tools/rest_list_certificates"
	const writeRoute = "/api/v1/mcp/tools/issue_certificate"
	restStatus, restBody := aiReq(t, h, http.MethodPost, restRoute, token, map[string]any{})
	if restStatus != http.StatusOK {
		t.Fatalf("control REST tool call: HTTP %d %s", restStatus, restBody)
	}
	writeStatus, writeBody := aiReq(t, h, http.MethodPost, writeRoute, token, map[string]any{})
	if writeStatus != http.StatusBadRequest {
		t.Fatalf("control write tool validation: HTTP %d %s", writeStatus, writeBody)
	}
	if err := h.log.Close(); err != nil {
		t.Fatal(err)
	}
	restStatus, restBody = aiReq(t, h, http.MethodPost, restRoute, token, map[string]any{})
	writeStatus, writeBody = aiReq(t, h, http.MethodPost, writeRoute, token, map[string]any{})
	if restStatus != http.StatusServiceUnavailable || writeStatus != http.StatusServiceUnavailable {
		t.Fatalf("MCP rate refusals hid audit outage: REST HTTP %d %s; write HTTP %d %s", restStatus, restBody, writeStatus, writeBody)
	}
}
