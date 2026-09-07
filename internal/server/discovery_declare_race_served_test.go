// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// A tight declare-then-create must never surface the transient inline/tail apply
// race as an internal error: the durable declaration event is applied by the
// projection tail regardless, and the orchestrator retries the inline apply, so
// the customer sees a created source, not a 500.
func TestServedTightSegmentThenSourceNeverInternalErrors(t *testing.T) {
	h := newDiscoveryRelayHarness(t, "loopback-race-seed")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	for i := 0; i < 40; i++ {
		seg := fmt.Sprintf("race-%d", i)
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/segments", tok, "seg-"+seg, map[string]any{
			"name": seg, "segment": seg, "targets": []string{"127.0.0.1:10443"},
			"cidrs": []string{"127.0.0.1/32"}, "ranges": []string{"127.0.0.1/32"}, "ports": []int{10443}, "allow_loopback": true,
		})
		if status != http.StatusCreated {
			t.Fatalf("declare segment %d = %d body %s", i, status, body)
		}
		status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, "src-"+seg, map[string]any{
			"kind": "network", "name": seg + "-src",
			"config": map[string]any{"targets": []string{"127.0.0.1:10443"}, "ports": []int{10443}, "allow_loopback": true, "segment": seg},
		})
		if status == http.StatusInternalServerError {
			t.Fatalf("create source %d immediately after its segment surfaced a 500: %s", i, body)
		}
		if status != http.StatusCreated {
			t.Fatalf("create source %d = %d body %s, want 201", i, status, body)
		}
		var src struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &src); err != nil || src.ID == "" {
			t.Fatalf("source %d has no id: %v (%s)", i, err, body)
		}
	}
}
