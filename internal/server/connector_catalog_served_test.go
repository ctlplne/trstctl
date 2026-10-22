// SPDX-License-Identifier: BUSL-1.1

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
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
	token := seedScopedToken(t, h.store, h.tenant, "connectors:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/catalog", token, nil)
	if status != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", status, body)
	}
	var catalog struct {
		Items []struct {
			Name          string   `json:"name"`
			Native        bool     `json:"native"`
			ReplaySafety  string   `json:"replay_safety"`
			TargetVantage string   `json:"target_vantage"`
			Capabilities  []string `json:"capabilities"`
			GrantSource   string   `json:"grant_source"`
			Executor      string   `json:"executor"`
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
			// A75: a factory registration declares its grant; the registry
			// reports it without constructing a connector.
			if item.GrantSource != "registry" || len(item.Capabilities) == 0 || item.Executor != "host_agent" {
				t.Errorf("enabled factory connector reports no declared grant: %+v", item)
			}
		case "nginx":
			if item.Native {
				t.Error("disabled nginx was advertised as a native connector")
			}
			// A74: the host agent still executes nginx with the shipped
			// connector, so its grant and executor are named.
			if item.Executor != "host_agent" || item.GrantSource != "shipped" || len(item.Capabilities) == 0 {
				t.Errorf("nginx the control plane never enabled reads as unexecuted: %+v", item)
			}
		case "aws-acm":
			// A59: a cloud store runs on an enrolled relay; the census names
			// its grant although this process never enabled it.
			if item.Executor != "network_relay" || item.GrantSource != "shipped" || len(item.Capabilities) == 0 {
				t.Errorf("aws-acm nothing enabled = %+v, want the relay as executor with its shipped grant", item)
			}
		}
	}
	for _, name := range []string{"postfix", "envoy", "nginx"} {
		if !seen[name] {
			t.Errorf("catalog omitted %s", name)
		}
	}
}
