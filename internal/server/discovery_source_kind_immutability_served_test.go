// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedGenericDiscoveryCannotRetypeExistingCTSource(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	const name = "qa-ct-source-owned"
	status, body := secretsReqKey(t, h, http.MethodPut,
		"/api/v1/discovery/ct-monitoring", token, "ct-before-generic-retype", map[string]any{
			"name": name, "logs": []string{"https://ct.example.com/log"},
			"watched_domains": []string{"example.com"}, "run_now": false,
		})
	if status != http.StatusOK {
		t.Fatalf("create CT source: %d %s", status, body)
	}
	before, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"name": name, "kind": "manual", "config": map[string]any{
		"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}},
	}}
	t.Run("preview", func(t *testing.T) {
		status, body := secretsReq(t, h, http.MethodPost,
			"/api/v1/discovery/plans/preview", token, plan)
		var preview struct {
			Ready          bool     `json:"ready"`
			BlockedReasons []string `json:"blocked_reasons"`
		}
		if err := json.Unmarshal(body, &preview); err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK || preview.Ready || !strings.Contains(strings.Join(preview.BlockedReasons, " "), "kind") {
			t.Fatalf("cross-kind preview = %d %s, want actionable not-ready", status, body)
		}
	})
	t.Run("mutation", func(t *testing.T) {
		status, body := secretsReqKey(t, h, http.MethodPost,
			"/api/v1/discovery/sources", token, "generic-cannot-retype-ct", plan)
		if status != http.StatusConflict {
			t.Fatalf("generic source retyped CT source: %d %s", status, body)
		}
		assertDiscoverySourcePreserved(t, h, before)
	})
}
