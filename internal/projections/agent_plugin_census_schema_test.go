// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/plugincensus"
)

func TestAgentHeartbeatPluginCensusSchemaFailsClosed(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	plugins := []plugincensus.Entry{{
		Name: "partner-f5", Digest: digest, Publisher: digest,
		ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM,
		Grants:           []plugincensus.Grant{},
	}}
	statement := plugincensus.Statement{
		TenantID: "tenant-a", AgentCommonName: "relay-a", Plugins: plugins, IssuedAtUnix: 42,
	}
	canonical, err := statement.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	valid := AgentHeartbeat{
		Agent: "relay-a",
		RelayPlugins: &AgentRelayPluginCensus{
			Plugins: plugins, IssuedAtUnix: 42, Signature: []byte("signature"),
			Statement: string(canonical), SignerFingerprint: strings.Repeat("b", 64),
		},
	}

	if err := validateAgentHeartbeatPluginCensus(1, "tenant-a", valid); err == nil {
		t.Fatal("v1 heartbeat accepted v2 signed census fields")
	}
	if err := validateAgentHeartbeatPluginCensus(AgentHeartbeatPluginCensusSchemaVersion, "tenant-a", AgentHeartbeat{Agent: "relay-a"}); err == nil {
		t.Fatal("v2 heartbeat accepted a missing census")
	}
	mutated := valid
	copyReport := *valid.RelayPlugins
	copyReport.Statement += "tampered"
	mutated.RelayPlugins = &copyReport
	if err := validateAgentHeartbeatPluginCensus(AgentHeartbeatPluginCensusSchemaVersion, "tenant-a", mutated); err == nil {
		t.Fatal("v2 heartbeat accepted statement bytes that do not match its metadata")
	}
	if err := validateAgentHeartbeatPluginCensus(AgentHeartbeatPluginCensusSchemaVersion, "tenant-a", valid); err != nil {
		t.Fatalf("valid v2 heartbeat census rejected: %v", err)
	}
}
