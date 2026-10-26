// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/nginx"
)

// A153: the relay builds the shipped families through the control plane's
// constructor census and runs them in the WASM connector sandbox unless the
// agent opted out; the opt-out yields the same family, built in process.
func TestRelayRunsShippedConnectorsInTheSandboxByDefault(t *testing.T) {
	material := Material{"secret://f5": []byte("pw")}
	pair := TargetConfig{Endpoint: "https://f5-a.example.test", PeerEndpoint: "https://f5-b.example.test",
		Username: "admin", PasswordRef: "secret://f5", ClientSSLProfile: "clientssl"}
	host := HostTargetConfig{CertPath: "/etc/nginx/tls.crt", KeyPath: "/etc/nginx/tls.key"}

	if ConnectorIsolation() != connector.IsolationWASMSandbox {
		t.Fatalf("default isolation = %s", ConnectorIsolation())
	}
	relayBuilt, err := buildRelayConnector("f5", pair, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, inProcess := relayBuilt.(*f5.HAPair); inProcess {
		t.Fatal("the relay built an in-process F5 pair while connectors are sandboxed")
	}
	if _, ok := relayBuilt.(connector.Rollbacker); !ok {
		t.Fatal("the sandboxed F5 pair lost its rollback operation")
	}
	hostBuilt, err := buildHostConnector("nginx", host, Material{})
	if err != nil {
		t.Fatal(err)
	}
	if _, inProcess := hostBuilt.(*nginx.Connector); inProcess {
		t.Fatal("the host agent built an in-process nginx connector while connectors are sandboxed")
	}

	SetConnectorsInProcess(true)
	t.Cleanup(func() { SetConnectorsInProcess(false) })
	relayBuilt, err = buildRelayConnector("f5", pair, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, inProcess := relayBuilt.(*f5.HAPair); !inProcess {
		t.Fatalf("in-process isolation built %T, want the F5 HA pair", relayBuilt)
	}
	if _, err := buildRelayConnector("f5", TargetConfig{Endpoint: "https://f5.example.test", Username: "admin", PasswordRef: "secret://missing", ClientSSLProfile: "clientssl"}, material); err == nil {
		t.Fatal("a credential that was not redeemed built a connector")
	}
}
