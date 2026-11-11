// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"slices"
	"testing"
)

// A190-L1: a relay that claims jobs reports the egress allowlist its job
// connections follow, in canonical form, so the Agents page can say what the
// relay may reach; one without an allowlist reports an empty list; an agent
// that claims no relay jobs reports none.
func TestExecutorCensusReportsTheRelayEgressPolicy(t *testing.T) {
	report := executorCensus(agentOptions{relayClaim: true, relayEgressAllow: "198.51.100.9:8443, 10.20.0.0/16,::ffff:192.0.2.7"}, nil)
	if report.RelayEgress == nil || !slices.Equal(report.RelayEgress.Allow, []string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443"}) {
		t.Fatalf("census relay egress = %+v, want the canonical allowlist", report.RelayEgress)
	}
	open := executorCensus(agentOptions{relayClaim: true}, nil)
	if open.RelayEgress == nil {
		t.Fatal("a relay without an allowlist reported no egress policy")
	}
	if raw, _ := json.Marshal(open.RelayEgress); string(raw) != `{"allow":[]}` {
		t.Fatalf("a relay without an allowlist reported %s, want an empty allowlist", raw)
	}
	if plain := executorCensus(agentOptions{relayEgressAllow: "10.0.0.0/8"}, nil); plain.RelayEgress != nil {
		t.Fatalf("an agent that claims no relay jobs reported %+v", plain.RelayEgress)
	}
}
