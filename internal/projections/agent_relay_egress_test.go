// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// A190-L1: a relay's egress policy rides the executor census on agent.heartbeat
// v8 only. The earlier shapes stay closed, so the field cannot be appended
// under an earlier version, and today's v7 census still fits v7.
func TestAgentHeartbeatV8AloneCarriesTheRelayEgressPolicy(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenant = "11111111-1111-4111-8111-111111111111"
	beat := AgentHeartbeat{ID: "a1900000-0000-4000-8000-000000000001", Agent: "relay-1", Version: "1.0.0", Status: "active",
		Executors: &AgentExecutorCensus{Version: "1.0.0", Kinds: []AgentExecutorKind{{Kind: "connector.deploy"}},
			RelayEgress: &AgentRelayEgress{Restricted: true, Allow: []string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443"}}}}
	wire, err := json.Marshal(beat)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= AgentHeartbeatRelayEgressSchemaVersion; version++ {
		_, err := log.Append(t.Context(), events.Event{Type: EventAgentHeartbeat, TenantID: tenant, SchemaVersion: version, Data: wire})
		if (err == nil) != (version == AgentHeartbeatRelayEgressSchemaVersion) {
			t.Fatalf("a heartbeat carrying the relay egress policy at v%d accepted=%t: %v", version, err == nil, err)
		}
	}
	census := *beat.Executors
	census.RelayEgress = nil
	before := beat
	before.Executors = &census
	wire, err = json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: EventAgentHeartbeat, TenantID: tenant, SchemaVersion: AgentHeartbeatSSHTrustSchemaVersion, Data: wire}); err != nil {
		t.Fatalf("the closed v7 shape refused a census without the relay egress policy: %v", err)
	}
}

// The projector holds the policy to its version and bounds, and v8 keeps
// every earlier report independently optional.
func TestAgentHeartbeatRelayEgressValidation(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	census := func(egress *AgentRelayEgress) AgentHeartbeat {
		return AgentHeartbeat{Agent: "relay-1", Executors: &AgentExecutorCensus{Version: "1.0.0", Kinds: []AgentExecutorKind{}, RelayEgress: egress}}
	}
	listed := census(&AgentRelayEgress{Restricted: true, Allow: []string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443", "[fd00::5]:443"}})
	open := census(&AgentRelayEgress{Allow: []string{}})
	truncated := census(&AgentRelayEgress{Restricted: true, Allow: []string{"10.20.0.0/16"}, Truncated: true})
	for name, beat := range map[string]AgentHeartbeat{"listed": listed, "open": open, "truncated": truncated} {
		if err := validateAgentHeartbeatRelayEgress(AgentHeartbeatRelayEgressSchemaVersion, beat); err != nil {
			t.Errorf("v8 refused the %s policy: %v", name, err)
		}
	}
	for version := 1; version < AgentHeartbeatRelayEgressSchemaVersion; version++ {
		if err := validateAgentHeartbeatRelayEgress(version, listed); err == nil {
			t.Errorf("agent.heartbeat v%d carried a relay egress policy", version)
		}
		if err := validateAgentHeartbeatRelayEgress(version, census(nil)); err != nil {
			t.Errorf("agent.heartbeat v%d without a policy: %v", version, err)
		}
	}
	if err := validateAgentHeartbeatRelayEgress(AgentHeartbeatRelayEgressSchemaVersion, census(nil)); err == nil {
		t.Error("v8 accepted a census without the relay egress policy")
	}
	if err := validateAgentHeartbeatRelayEgress(AgentHeartbeatRelayEgressSchemaVersion, AgentHeartbeat{}); err == nil {
		t.Error("v8 accepted a heartbeat without a census")
	}
	tooMany := make([]string, AgentRelayEgressMaxEntries+1)
	for i := range tooMany {
		tooMany[i] = "10.0.0.1"
	}
	for name, bad := range map[string]*AgentRelayEgress{
		"over the entry bound":     {Restricted: true, Allow: tooMany},
		"a host name":              {Restricted: true, Allow: []string{"appliance.example.com"}},
		"over the length bound":    {Restricted: true, Allow: []string{strings.Repeat("1", AgentRelayEgressMaxEntryBytes+1)}},
		"a padded entry":           {Restricted: true, Allow: []string{" 10.0.0.1"}},
		"no allowlist but entries": {Allow: []string{"10.0.0.1"}},
		"no allowlist but cut":     {Allow: []string{}, Truncated: true},
	} {
		if err := validateAgentHeartbeatRelayEgress(AgentHeartbeatRelayEgressSchemaVersion, census(bad)); err == nil {
			t.Errorf("v8 accepted %s", name)
		}
	}
	for name, err := range map[string]error{
		"ssh trust":         validateAgentHeartbeatSSHTrust(AgentHeartbeatRelayEgressSchemaVersion, listed),
		"executor census":   validateAgentHeartbeatExecutors(AgentHeartbeatRelayEgressSchemaVersion, listed),
		"clock":             validateAgentHeartbeatClock(AgentHeartbeatRelayEgressSchemaVersion, listed),
		"ssh krl":           validateAgentHeartbeatSSHKRL(AgentHeartbeatRelayEgressSchemaVersion, tenant, listed),
		"plugin census":     validateAgentHeartbeatPluginCensus(AgentHeartbeatRelayEgressSchemaVersion, tenant, listed),
		"revocation caches": validateAgentHeartbeatRevocationCaches(AgentHeartbeatRelayEgressSchemaVersion, tenant, listed),
	} {
		if err != nil {
			t.Errorf("v8 required the %s report: %v", name, err)
		}
	}
}
