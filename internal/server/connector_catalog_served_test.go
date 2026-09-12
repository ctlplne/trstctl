// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// The API is assembled before issuance surfaces. Its catalog must still expose
// the operator's actual native registry, including receiver replay safety.
func TestServedConnectorCatalogReflectsConfiguredNativeRegistry(t *testing.T) {
	registry, err := connectorRegistryFromConfig(config.Connectors{Enabled: []string{"postfix", "envoy"}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
	token := seedScopedToken(t, h.store, h.tenant, "connectors:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/catalog", token, nil)
	if status != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", status, body)
	}
	var catalog struct {
		Items []struct {
			Name          string `json:"name"`
			Native        bool   `json:"native"`
			ReplaySafety  string `json:"replay_safety"`
			TargetVantage string `json:"target_vantage"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range catalog.Items {
		seen[item.Name] = true
		switch item.Name {
		case "postfix", "envoy":
			if !item.Native || item.ReplaySafety != "reconciled" || item.TargetVantage != "host_agent" {
				t.Errorf("enabled connector lost its runtime contract: %+v", item)
			}
		case "nginx":
			if item.Native {
				t.Error("disabled nginx was advertised as a native connector")
			}
		}
	}
	for _, name := range []string{"postfix", "envoy", "nginx"} {
		if !seen[name] {
			t.Errorf("catalog omitted %s", name)
		}
	}
}
