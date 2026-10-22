// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// A61: only an envoy target may declare the relay as its executor, and only
// with the value "network". Everything else is refused rather than ignored,
// so a typo cannot silently keep a remote Envoy on a host agent that would
// refuse it, and an appliance cannot be talked onto the control plane.
func TestOnlyAnEnvoyTargetMayDeclareTheRelayAsItsExecutor(t *testing.T) {
	t.Parallel()
	override, ok, err := connector.TargetVantageOverride("envoy", json.RawMessage(`{"endpoint":"https://sds.remote:9901","vantage":"network"}`))
	if err != nil || !ok || override != connector.VantageNetworkRelay {
		t.Fatalf("envoy vantage network = %q %v %v", override, ok, err)
	}
	if override, ok, err := connector.TargetVantageOverride("envoy", json.RawMessage(`{"vantage":" Network "}`)); err != nil || !ok || override != connector.VantageNetworkRelay {
		t.Fatalf("case and space are not meaning: %q %v %v", override, ok, err)
	}
	for name, cfg := range map[string]string{
		"absent":                `{"endpoint":"http://127.0.0.1:9901"}`,
		"empty":                 `{"vantage":""}`,
		"null":                  `{"vantage":null}`,
		"no config":             ``,
		"unparseable":           `not json`,
		"envoy without vantage": `{"secret_name":"server_cert"}`,
	} {
		if _, ok, err := connector.TargetVantageOverride("envoy", json.RawMessage(cfg)); ok || err != nil {
			t.Errorf("%s: override=%v err=%v, want neither", name, ok, err)
		}
	}
	for name, tc := range map[string]struct{ family, cfg string }{
		"envoy host":         {"envoy", `{"vantage":"host"}`},
		"envoy control":      {"envoy", `{"vantage":"control_plane"}`},
		"envoy not string":   {"envoy", `{"vantage":true}`},
		"nginx network":      {"nginx", `{"vantage":"network"}`},
		"f5 control plane":   {"f5", `{"vantage":"control_plane"}`},
		"aws-acm host":       {"aws-acm", `{"vantage":"host"}`},
		"postgresql network": {"postgresql", `{"vantage":"network"}`},
	} {
		if _, ok, err := connector.TargetVantageOverride(tc.family, json.RawMessage(tc.cfg)); err == nil || ok {
			t.Errorf("%s: override=%v err=%v, want a refusal", name, ok, err)
		}
	}
	if v, known := connector.EffectiveTargetVantage("envoy", json.RawMessage(`{"vantage":"network"}`)); !known || v != connector.VantageNetworkRelay {
		t.Fatalf("effective vantage with a declaration = %q %v", v, known)
	}
	if v, known := connector.EffectiveTargetVantage("envoy", nil); !known || v != connector.VantageHostAgent {
		t.Fatalf("effective vantage without a declaration = %q %v, want the family's host vantage", v, known)
	}
	if v, known := connector.EffectiveTargetVantage("nginx", json.RawMessage(`{"vantage":"network"}`)); !known || v != connector.VantageHostAgent {
		t.Fatalf("an impermissible declaration must not move nginx: %q %v", v, known)
	}
}
