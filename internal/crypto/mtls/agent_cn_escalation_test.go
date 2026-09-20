// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"testing"
)

// TestAgentCommonNameCannotForgeRoleSegments is the regression guard for the
// agent role-escalation defect. The CSR's common name is interpolated into the
// agent's SPIFFE ID as a PATH SEGMENT, and capability roles are encoded as
// further segments of that same path. A CN of "agent1/role/network" therefore
// produced spiffe://…/agent/agent1/role/network, which AgentRolesFromClientCert
// reads back as a `network` grant — so an agent issued a host-only bootstrap
// token could self-grant relay capability just by choosing its own CSR subject.
func TestAgentCommonNameCannotForgeRoleSegments(t *testing.T) {
	for _, cn := range []string{
		"agent1/role/network",
		"agent1/role/" + AgentRoleNetwork,
		"a/b",
		"agent1%2Frole%2Fnetwork",
		"agent1\\role\\network",
		"agent1?x=1",
		"agent1#frag",
	} {
		if err := validateAgentCommonName(cn); err == nil {
			t.Errorf("common name %q was accepted; it can forge SPIFFE path segments", cn)
		}
	}

	// Empty, padded and control-character subjects are refused too.
	for _, cn := range []string{"", "   ", " agent1", "agent1 ", "agent\x001"} {
		if err := validateAgentCommonName(cn); err == nil {
			t.Errorf("common name %q was accepted", cn)
		}
	}
}

// TestAgentCommonNameAcceptsOrdinarySubjects keeps the guard honest: real agent
// names must still enrol, so the check cannot be a blanket refusal.
func TestAgentCommonNameAcceptsOrdinarySubjects(t *testing.T) {
	for _, cn := range []string{
		"agent1",
		"web-01.corp.example",
		"agent_1",
		"agent.eu-west-1.prod",
		"AGENT-42",
	} {
		if err := validateAgentCommonName(cn); err != nil {
			t.Errorf("ordinary agent name %q was refused: %v", cn, err)
		}
	}
}
