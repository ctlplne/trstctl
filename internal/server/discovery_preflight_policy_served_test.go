// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestServedDiscoveryPreflightReportsLiteralAddressPolicy(t *testing.T) {
	h := newDiscoveryRelayHarness(t, "private-preflight")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	for _, allowPrivate := range []bool{false, true} {
		name := "private-without-permission"
		if allowPrivate {
			name = "private-with-permission"
		}
		t.Run(name, func(t *testing.T) {
			plan := map[string]any{
				"name": name, "kind": "network",
				"config": map[string]any{
					"segment": "private-preflight", "targets": []string{"10.42.0.8:443"},
					"allow_rfc1918": allowPrivate,
				},
			}
			status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", tok, plan)
			if status != http.StatusCreated {
				t.Fatalf("save source: %d %s", status, body)
			}
			var source struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
				t.Fatalf("source response: %s, err %v", body, err)
			}
			before := discoveryRelayEventCounts(t, h)
			for _, request := range []struct {
				method, path string
				body         any
			}{
				{http.MethodPost, "/api/v1/discovery/plans/preview", plan},
				{http.MethodGet, "/api/v1/discovery/sources/" + source.ID + "/preflight", nil},
			} {
				status, body = secretsReq(t, h.servedHarness, request.method, request.path, tok, request.body)
				if status != http.StatusOK {
					t.Fatalf("%s: %d %s", request.path, status, body)
				}
				var preview struct {
					Ready             bool     `json:"ready"`
					SideEffects       bool     `json:"side_effects"`
					BlockedReasons    []string `json:"blocked_reasons"`
					NormalizedTargets []string `json:"normalized_targets"`
				}
				if err := json.Unmarshal(body, &preview); err != nil {
					t.Fatal(err)
				}
				if preview.Ready != allowPrivate || preview.SideEffects || !reflect.DeepEqual(preview.NormalizedTargets, []string{"10.42.0.8:443"}) {
					t.Fatalf("%s hid address policy: %s", request.path, body)
				}
				if allowPrivate {
					if len(preview.BlockedReasons) != 0 {
						t.Fatalf("authorized target blocked: %s", body)
					}
				} else if reasons := strings.Join(preview.BlockedReasons, " "); !strings.Contains(reasons, "10.42.0.8") || !strings.Contains(reasons, "allow_rfc1918") {
					t.Fatalf("missing exact private-target remedy: %s", body)
				}
			}
			if after := discoveryRelayEventCounts(t, h); !reflect.DeepEqual(before, after) {
				t.Fatalf("preview changed the event log: before=%v after=%v", before, after)
			}
		})
	}
}
