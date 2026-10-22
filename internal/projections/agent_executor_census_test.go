// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// A62: the executor census is bound to the heartbeat version that introduced
// it, and bounded, so an agent cannot use a heartbeat as a bulk channel.
func TestAgentHeartbeatExecutorCensusIsVersionBoundAndBounded(t *testing.T) {
	t.Parallel()
	census := &AgentExecutorCensus{Version: "1.0", Kinds: []AgentExecutorKind{{Kind: "connector.deploy", Connectors: []string{"f5"}}}}
	for _, version := range []int{events.DefaultSchemaVersion, AgentHeartbeatPluginCensusSchemaVersion, AgentHeartbeatRevocationCacheSchemaVersion} {
		if err := validateAgentHeartbeatExecutors(version, AgentHeartbeat{Executors: census}); err == nil {
			t.Errorf("v%d accepted an executor census", version)
		}
		if err := validateAgentHeartbeatExecutors(version, AgentHeartbeat{}); err != nil {
			t.Errorf("v%d without a census = %v", version, err)
		}
	}
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatExecutorCensusSchemaVersion, AgentHeartbeat{}); err == nil {
		t.Error("v4 without a census was accepted")
	}
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatExecutorCensusSchemaVersion, AgentHeartbeat{Executors: census}); err != nil {
		t.Errorf("v4 with a census = %v", err)
	}
	tooMany := &AgentExecutorCensus{}
	for i := 0; i <= maxAgentExecutorKinds; i++ {
		tooMany.Kinds = append(tooMany.Kinds, AgentExecutorKind{Kind: "k" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)})
	}
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatExecutorCensusSchemaVersion, AgentHeartbeat{Executors: tooMany}); err == nil {
		t.Error("an oversized census was accepted")
	}
	repeated := &AgentExecutorCensus{Kinds: []AgentExecutorKind{{Kind: "a"}, {Kind: "a"}}}
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatExecutorCensusSchemaVersion, AgentHeartbeat{Executors: repeated}); err == nil {
		t.Error("a repeated kind was accepted")
	}
	oversized := &AgentExecutorCensus{Kinds: []AgentExecutorKind{{Kind: "a", Connectors: []string{strings.Repeat("c", maxAgentExecutorName+1)}}}}
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatExecutorCensusSchemaVersion, AgentHeartbeat{Executors: oversized}); err == nil {
		t.Error("an oversized connector name was accepted")
	}
}
