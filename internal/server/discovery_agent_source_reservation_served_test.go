// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedGenericDiscoveryCannotReserveAgentInventorySource(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	for _, test := range []struct {
		name, kind string
		config     map[string]any
	}{
		{"reserved agent name", "manual", map[string]any{"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}}}},
		{"agent kind", "agent", map[string]any{"agent_id": "11111111-1111-4111-8111-111111111111"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := "generic-fake-agent"
			if test.kind == "manual" {
				name = "agent:frontdoors:trust-store"
			}
			plan := map[string]any{"name": name, "kind": test.kind, "config": test.config}
			previewStatus, previewBody := secretsReq(t, h, http.MethodPost,
				"/api/v1/discovery/plans/preview", token, plan)
			var preview struct {
				Ready          bool     `json:"ready"`
				BlockedReasons []string `json:"blocked_reasons"`
			}
			if err := json.Unmarshal(previewBody, &preview); err != nil {
				t.Fatal(err)
			}
			if previewStatus != http.StatusOK || preview.Ready || !strings.Contains(strings.Join(preview.BlockedReasons, " "), "agent") {
				t.Fatalf("reserved source preview = %d %s, want actionable not-ready", previewStatus, previewBody)
			}
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", token,
				"agent-source-reservation-"+test.kind, plan)
			if status != http.StatusBadRequest {
				t.Fatalf("generic source reserved agent authority: status %d body %s", status, body)
			}
		})
	}
}
