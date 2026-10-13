// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedGenericDiscoveryCannotPreclaimProductSourceNames(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	for _, prefix := range []string{"secretscan:", "secret-repo:", "secret-third-party:"} {
		t.Run(strings.TrimSuffix(prefix, ":"), func(t *testing.T) {
			name := prefix + "qa-owned-source"
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
				if status != http.StatusOK || preview.Ready || !strings.Contains(strings.Join(preview.BlockedReasons, " "), "reserved") {
					t.Fatalf("product source preview = %d %s, want reserved not-ready", status, body)
				}
			})
			t.Run("generic mutation", func(t *testing.T) {
				status, body := secretsReqKey(t, h, http.MethodPost,
					"/api/v1/discovery/sources", token, "generic-preclaim-"+strings.TrimSuffix(prefix, ":"), plan)
				if status != http.StatusBadRequest {
					t.Fatalf("generic source preclaimed %q: %d %s", name, status, body)
				}
			})
			t.Run("CT mutation", func(t *testing.T) {
				ctName := prefix + "qa-owned-source-ct"
				status, body := secretsReqKey(t, h, http.MethodPut,
					"/api/v1/discovery/ct-monitoring", token,
					"ct-preclaim-"+strings.TrimSuffix(prefix, ":"), map[string]any{
						"name": ctName, "logs": []string{"https://ct.example.com/log"},
						"watched_domains": []string{"example.com"}, "run_now": false,
					})
				if status != http.StatusBadRequest {
					t.Fatalf("CT source preclaimed %q: %d %s", ctName, status, body)
				}
			})
		})
	}
}
