// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateConnectorsAcceptsTenantBoundRightSizeEndpoint(t *testing.T) {
	cfg := Connectors{HTTPTimeout: "10s", RightSize: []ConnectorRightSizeBinding{{
		TenantID: "d0d00000-0000-4000-8000-000000000301", Connector: "least-privilege",
		Endpoint: "https://entitlements.example.test", TokenRef: "secret://right-size/token?version=2",
	}}}
	if err := errors.Join(validateConnectors(cfg)...); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConnectorsRejectsAmbiguousRightSizeBindings(t *testing.T) {
	binding := ConnectorRightSizeBinding{
		TenantID: "not-a-uuid", Connector: "Least Privilege", Endpoint: "http://127.0.0.1:8080?token=bad", TokenRef: "plaintext-token",
	}
	cfg := Connectors{HTTPTimeout: "10s", RightSize: []ConnectorRightSizeBinding{binding, binding}}
	message := errors.Join(validateConnectors(cfg)...).Error()
	for _, want := range []string{"tenant_id must be a UUID", "lowercase connector key", "absolute HTTPS URL", "token_ref must use secret://name", "duplicates tenant/connector"} {
		if !strings.Contains(message, want) {
			t.Errorf("validation errors %q do not contain %q", message, want)
		}
	}
}

func TestValidateConnectorsRestrictsInsecureRightSizeEndpointToLoopback(t *testing.T) {
	binding := ConnectorRightSizeBinding{
		TenantID: "d0d00000-0000-4000-8000-000000000301", Connector: "least-privilege",
		Endpoint: "http://10.0.0.8:8080", TokenRef: "secret://right-size/token",
	}
	if err := errors.Join(validateConnectors(Connectors{AllowInsecureHTTP: true, RightSize: []ConnectorRightSizeBinding{binding}})...); err == nil || !strings.Contains(err.Error(), "loopback-only") {
		t.Fatalf("non-loopback insecure endpoint error = %v", err)
	}
	binding.Endpoint = "http://127.0.0.1:8080"
	if err := errors.Join(validateConnectors(Connectors{AllowInsecureHTTP: true, RightSize: []ConnectorRightSizeBinding{binding}})...); err != nil {
		t.Fatalf("loopback emulator endpoint: %v", err)
	}
}
