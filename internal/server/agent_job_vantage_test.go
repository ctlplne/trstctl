// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
)

// TestVantageCensusCoversEveryShippedConnector: a connector that can be enabled
// in production must have a hand-written vantage answer. The census switch has a
// fail-closed default, so this test exists to make "we forgot to classify it"
// a build-time conversation instead of a silently control-plane-bound connector.
func TestVantageCensusCoversEveryShippedConnector(t *testing.T) {
	// The full production set, from nativeConnectorFactory's two arms.
	shipped := []string{
		"nginx", "apache", "caddy", "iis", "haproxy", "postfix", "traefik",
		"java-keystore", "postgresql", "mysql", "rabbitmq", "elasticsearch", "tomcat",
		"envoy", "f5", "netscaler", "a10", "kemp", "cisco", "fortigate",
		"paloalto", "aws-acm", "azure-keyvault", "gcp-certificate-manager",
	}
	explicit := map[string]connector.TargetVantage{
		// Host services: the connector mutates the machine's files and reloads
		// its services; the executor belongs on the machine.
		"nginx": connector.VantageHostAgent, "apache": connector.VantageHostAgent,
		"caddy": connector.VantageHostAgent, "iis": connector.VantageHostAgent,
		"haproxy": connector.VantageHostAgent, "postfix": connector.VantageHostAgent,
		"traefik": connector.VantageHostAgent, "java-keystore": connector.VantageHostAgent,
		"postgresql": connector.VantageHostAgent, "mysql": connector.VantageHostAgent,
		"rabbitmq": connector.VantageHostAgent, "elasticsearch": connector.VantageHostAgent,
		"tomcat": connector.VantageHostAgent,
		// envoy is HTTP-driven but its admin/SDS surface binds loopback in the
		// deployments we ship for — transport does not decide vantage.
		"envoy": connector.VantageHostAgent,
		// Appliances that cannot host an agent: relay work.
		"f5": connector.VantageNetworkRelay, "netscaler": connector.VantageNetworkRelay,
		"a10": connector.VantageNetworkRelay, "kemp": connector.VantageNetworkRelay,
		"cisco": connector.VantageNetworkRelay, "fortigate": connector.VantageNetworkRelay,
		"paloalto": connector.VantageNetworkRelay,
		// Cloud certificate stores: no host, no segment — permanently the
		// control plane's egress-guarded client.
		"aws-acm": connector.VantageControlPlane, "azure-keyvault": connector.VantageControlPlane,
		"gcp-certificate-manager": connector.VantageControlPlane,
	}
	for _, name := range shipped {
		want, declared := explicit[name]
		if !declared {
			t.Errorf("shipped connector %q has no expected vantage in this test — classify it deliberately", name)
			continue
		}
		if got := nativeConnectorVantage(name); got != want {
			t.Errorf("nativeConnectorVantage(%q) = %q, want %q", name, got, want)
		}
	}
	if got := nativeConnectorVantage("some-future-connector"); got != connector.VantageControlPlane {
		t.Errorf("unlisted connector classifies as %q, want the fail-closed control_plane", got)
	}

	// A host stamp is now an unconditional control-plane refusal. Therefore the
	// production census and the agent binary's constructors must be the SAME
	// set; an extra name on either side strands work or permits a split-brain
	// executor. Derive both sides so a new family fails this guard automatically.
	var classifiedHost []string
	for _, name := range shipped {
		if nativeConnectorVantage(name) == connector.VantageHostAgent {
			classifiedHost = append(classifiedHost, name)
		}
	}
	slices.Sort(classifiedHost)
	hostExecutable := agentrelay.HostConnectorKinds()
	slices.Sort(hostExecutable)
	if !slices.Equal(classifiedHost, hostExecutable) {
		t.Fatalf("host-vantage census = %v, agent constructors = %v; every refused family needs a shipped executor", classifiedHost, hostExecutable)
	}
}

// TestSideEffectRoleClassifier drives the classifier the enqueue paths share:
// the connector name in the raw payload decides the row's claim demand, and
// anything unreadable fails closed to never-claimable.
func TestSideEffectRoleClassifier(t *testing.T) {
	registry := connector.NewRegistry()
	for name, vantage := range map[string]connector.TargetVantage{
		"nginx": connector.VantageHostAgent,
		"f5":    connector.VantageNetworkRelay,
		"acm":   connector.VantageControlPlane,
	} {
		if err := registry.RegisterFactory(name, func(_ context.Context, _ connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
			return nil, nil, func() {}, nil
		}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		if err := registry.DeclareTargetVantage(name, vantage); err != nil {
			t.Fatalf("declare %s: %v", name, err)
		}
	}
	classify := connectorSideEffectRoleClassifier(registry)

	payload := func(name string) []byte {
		b, err := json.Marshal(connector.DeployPayload{Connector: name, Target: "t"})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		destination string
		payload     []byte
		want        string
	}{
		{"connector.deploy", payload("nginx"), "host"},
		{"connector.deploy", payload("f5"), "network"},
		{"connector.deploy", payload("acm"), "control_plane"},
		// Undeclared connector: fail closed, stays with the control plane.
		{"connector.deploy", payload("mystery"), "control_plane"},
		// Unreadable payload: if the control plane cannot tell what a deploy is,
		// it must not hand it to an agent.
		{"connector.deploy", []byte("not json"), "control_plane"},
		{"connector.rollback", payload("f5"), "network"},
		// Non-connector destinations carry no per-row demand.
		{"ca.issue", payload("nginx"), ""},
		{"endpoint.verify", []byte(`{}`), ""},
	}
	for _, tc := range cases {
		if got := classify(tc.destination, tc.payload); got != tc.want {
			t.Errorf("classify(%s, %.20q) = %q, want %q", tc.destination, tc.payload, got, tc.want)
		}
	}
}
