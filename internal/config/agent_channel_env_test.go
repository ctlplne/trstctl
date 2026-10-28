// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// Every AgentChannel field an operator needs must be settable by environment.
//
// ClaimableJobKinds was the one that was not, and it is the field that decides
// whether an enrolled agent can do anything at all: an empty allowlist serves
// the job ledger and hands nothing out, so a container deployment could enable
// the channel, watch an agent enroll, and never learn why no work ran. A compose
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

// A66: the per-agent lease quota is settable by environment like every sibling,
// and a negative value is refused at startup rather than read as "no quota".
func TestThePerAgentClaimQuotaIsSettableByEnvironmentAndRefusesNegatives(t *testing.T) {
	t.Parallel()
	env := map[string]string{"TRSTCTL_AGENT_CHANNEL_MAX_LIVE_CLAIMS_PER_AGENT": "3"}
	var c Config
	c.applyEnv(func(k string) string { return env[k] })
	if c.AgentChannel.MaxLiveClaimsPerAgent != 3 {
		t.Fatalf("max_live_claims_per_agent = %d, want 3 from the environment", c.AgentChannel.MaxLiveClaimsPerAgent)
	}

	cfg := Default()
	cfg.AgentChannel.Enabled = true
	cfg.AgentChannel.MaxLiveClaimsPerAgent = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent_channel.max_live_claims_per_agent") {
		t.Fatalf("a negative quota must fail validation naming the key; got %v", err)
	}
	cfg.AgentChannel.MaxLiveClaimsPerAgent = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("zero (no quota) must pass; got %v", err)
	}
}

// A68: the upgrade publisher key file is settable by environment like every
// sibling, so a container deployment can pin the publisher without a config file.
func TestTheUpgradePublisherKeyFileIsSettableByEnvironment(t *testing.T) {
	t.Parallel()
	env := map[string]string{"TRSTCTL_AGENT_CHANNEL_UPGRADE_PUBLISHER_KEY_FILE": "/run/secrets/upgrade-publisher.pub"}
	var c Config
	c.applyEnv(func(k string) string { return env[k] })
	if c.AgentChannel.UpgradePublisherKeyFile != "/run/secrets/upgrade-publisher.pub" {
		t.Fatalf("upgrade_publisher_key_file = %q, want the environment value", c.AgentChannel.UpgradePublisherKeyFile)
	}
}

// A211: probing certificates known only from scans is off by default and
// settable by environment like every sibling.
func TestProbingScannedCertificatesIsOffByDefaultAndSettableByEnvironment(t *testing.T) {
	t.Parallel()
	if Default().AgentChannel.ProbeScannedCertificates {
		t.Fatal("probe_scanned_certificates must default to off")
	}
	env := map[string]string{"TRSTCTL_AGENT_CHANNEL_PROBE_SCANNED_CERTIFICATES": "true"}
	var c Config
	c.applyEnv(func(k string) string { return env[k] })
	if !c.AgentChannel.ProbeScannedCertificates {
		t.Fatal("probe_scanned_certificates was not set from the environment")
	}
}
