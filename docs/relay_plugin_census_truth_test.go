// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// TestRelayPluginCensusClaimsStayCurrent prevents E4's old blind-spot wording
// from surviving after the signed per-relay census shipped. ELI5: the relay is
// the only process that knows what it loaded, so it signs the small label from
// each loaded module; the control plane verifies and displays those labels.
func TestRelayPluginCensusClaimsStayCurrent(t *testing.T) {
	t.Parallel()

	limitations := strings.Join(strings.Fields(read(t, "limitations.md")), " ")
	feature := strings.Join(strings.Fields(read(t, "features/deployment-connectors.md")), " ")

	if strings.Contains(strings.ToLower(limitations), "the control plane cannot enumerate which modules a given relay carries") {
		t.Error("limitations.md retains the obsolete pre-AUD-34 relay census claim")
	}
	for _, marker := range []string{
		"signed, metadata-only census",
		"network_relay_wasm",
		"signed empty census",
		"tampered, stale, or cross-tenant",
		"immutable event stream",
		"no module bytes, publisher keys, credentials, or secrets",
	} {
		if !strings.Contains(strings.ToLower(limitations), strings.ToLower(marker)) {
			t.Errorf("limitations.md omits the relay census boundary %q", marker)
		}
	}
	for _, marker := range []string{
		"Verified relay plugins",
		"GET /api/v1/connectors/catalog",
		"publisher fingerprint",
		"effective grants and normalized constraints",
		"signed empty census",
	} {
		if !strings.Contains(feature, marker) {
			t.Errorf("deployment-connectors.md omits the operator-facing census contract %q", marker)
		}
	}
}

// TestRelayPluginCensusClaimsRemainLoadBearing couples the prose to every
// security boundary it describes. Renaming a page cannot make an unsigned or
// tenant-confused heartbeat true.
func TestRelayPluginCensusClaimsRemainLoadBearing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file   string
		tokens []string
	}{
		{"../internal/agent/relay/plugins.go", []string{"LoadVerifiedWithProvenance", "func (r *PluginRuntime) Census()"}},
		{"../internal/plugincensus/census.go", []string{"ExecutionContextNetworkRelayWASM", "func Normalize", "func (s Statement) Canonical"}},
		{"../internal/agent/transport/plugin_census.go", []string{"func SignedPluginCensus", "id.SignStatement"}},
		{"../internal/server/agentchannel.go", []string{"validatedRelayPluginCensus", "VerifyStatement", "AgentHeartbeatPluginCensusSchemaVersion"}},
		{"../internal/projections/projections.go", []string{"RelayPlugins *AgentRelayPluginCensus", "AgentHeartbeatPluginCensusSchemaVersion = 2"}},
		{"../internal/store/migrations/0173_agent_relay_plugin_census.sql", []string{"relay_plugins jsonb", "relay_plugins_signature", "relay_plugins_signer_fingerprint"}},
		{"../internal/api/connectors_lifecycle.go", []string{"RelayPlugins", "SignatureVerified", "MetadataOnly"}},
		{"../web/src/pages/Connectors.tsx", []string{"connectors.relayPlugins.title", "relayPlugins.flatMap", "loadMoreRelayPlugins"}},
	} {
		body := read(t, tc.file)
		for _, token := range tc.tokens {
			if !strings.Contains(body, token) {
				t.Errorf("%s no longer contains %q; relay census prose would lose production proof", tc.file, token)
			}
		}
	}
}
