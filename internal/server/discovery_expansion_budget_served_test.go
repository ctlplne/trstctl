// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedDiscoveryRejectsCIDRPortProductBeforePreviewOrCreate(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	ports := make([]int, 1_000)
	for i := range ports {
		ports[i] = i + 1
	}
	config := map[string]any{"segment": "edge", "cidr": "10.0.0.0/16", "ports": ports}
	request := map[string]any{"name": "oversized-scan", "kind": "network", "config": config}
	for path, key := range map[string]string{
		"/api/v1/discovery/plans/preview": "n0005-preview",
		"/api/v1/discovery/sources":       "n0005-create",
	} {
		status, body := secretsReqKey(t, h, http.MethodPost, path, token, key, request)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "maximum") {
			t.Fatalf("%s: status %d body %s, want bounded target budget rejection", path, status, body)
		}
	}
}
