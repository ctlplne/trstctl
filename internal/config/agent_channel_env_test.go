// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// Every AgentChannel field an operator needs must be settable by environment.
//
// ClaimableJobKinds was the one that was not, and it is the field that decides
// whether an enrolled agent can do anything at all: an empty allowlist serves
// the job ledger and hands nothing out, so a container deployment could enable
// the channel, watch an agent enrol, and never learn why no work ran. A compose
// file setting a variable nothing reads is the same defect one layer out.
func TestTheClaimableJobAllowlistIsSettableByEnvironment(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"TRSTCTL_AGENT_CHANNEL_ENABLED":             "true",
		"TRSTCTL_AGENT_CHANNEL_CLAIMABLE_JOB_KINDS": "discovery.run,endpoint.verify,connector.test",
	}
	var c Config
	c.applyEnv(func(k string) string { return env[k] })

	if !c.AgentChannel.Enabled {
		t.Fatal("TRSTCTL_AGENT_CHANNEL_ENABLED was not applied")
	}
	got := c.AgentChannel.ClaimableJobKinds
	if len(got) != 3 {
		t.Fatalf("claimable job kinds = %v, want three entries. Without this key a container "+
			"deployment can enable the agent channel and has no way to let an agent claim "+
			"anything: the ledger is served, hands nothing out, and the agent idles while every "+
			"surface looks healthy", got)
	}
	for i, want := range []string{"discovery.run", "endpoint.verify", "connector.test"} {
		if got[i] != want {
			t.Errorf("kind[%d] = %q, want %q", i, got[i], want)
		}
	}
}
