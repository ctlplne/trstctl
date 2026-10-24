// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
)

// A109: a host's KRL receipt is bound to the heartbeat version that introduced
// it, and replays only with the signed statement that matches its metadata.
func TestAgentHeartbeatSSHKRLReceiptIsVersionBoundAndEvidenced(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	receipt := sshkrlreceipt.Receipt{KRLTenantID: "tenant-1", InstalledVersion: 3, InstalledSHA256: digest,
		Outcome: sshkrlreceipt.OutcomeCurrent, FetchedVersion: 3, FetchedSHA256: digest, CheckedAtUnix: 1_800_000_000, PollEverySeconds: 30}
	canonical, err := (sshkrlreceipt.Statement{TenantID: "tenant-1", AgentCommonName: "edge-1", Receipt: receipt, IssuedAtUnix: 1_800_000_001}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	evidence := &AgentSSHKRLReceipt{Receipt: receipt, IssuedAtUnix: 1_800_000_001, Signature: []byte{1},
		Statement: string(canonical), SignerFingerprint: strings.Repeat("b", 64)}
	beat := AgentHeartbeat{Agent: "edge-1", SSHKRL: evidence}
	for _, version := range []int{events.DefaultSchemaVersion, AgentHeartbeatPluginCensusSchemaVersion, AgentHeartbeatRevocationCacheSchemaVersion, AgentHeartbeatExecutorCensusSchemaVersion} {
		if err := validateAgentHeartbeatSSHKRL(version, "tenant-1", beat); err == nil {
			t.Errorf("v%d accepted an SSH KRL receipt", version)
		}
		if err := validateAgentHeartbeatSSHKRL(version, "tenant-1", AgentHeartbeat{Agent: "edge-1"}); err != nil {
			t.Errorf("v%d without a receipt = %v", version, err)
		}
	}
	if err := validateAgentHeartbeatSSHKRL(AgentHeartbeatSSHKRLSchemaVersion, "tenant-1", AgentHeartbeat{Agent: "edge-1"}); err == nil {
		t.Error("v5 without a receipt was accepted")
	}
	if err := validateAgentHeartbeatSSHKRL(AgentHeartbeatSSHKRLSchemaVersion, "tenant-1", beat); err != nil {
		t.Errorf("v5 with a receipt = %v", err)
	}
	for name, mutate := range map[string]func(*AgentHeartbeat){
		"another agent's statement": func(b *AgentHeartbeat) { b.Agent = "edge-2" },
		"edited receipt": func(b *AgentHeartbeat) {
			r := *b.SSHKRL
			r.Receipt.InstalledVersion = 4
			r.Receipt.FetchedVersion = 4
			b.SSHKRL = &r
		},
		"no signature":           func(b *AgentHeartbeat) { r := *b.SSHKRL; r.Signature = nil; b.SSHKRL = &r },
		"bad signer fingerprint": func(b *AgentHeartbeat) { r := *b.SSHKRL; r.SignerFingerprint = "ABC"; b.SSHKRL = &r },
	} {
		changed := beat
		mutate(&changed)
		if err := validateAgentHeartbeatSSHKRL(AgentHeartbeatSSHKRLSchemaVersion, "tenant-1", changed); err == nil {
			t.Errorf("%s: replay accepted the receipt", name)
		}
	}
	// The other v5 reports stay optional.
	if err := validateAgentHeartbeatExecutors(AgentHeartbeatSSHKRLSchemaVersion, beat); err != nil {
		t.Errorf("v5 without an executor census = %v", err)
	}
	if err := validateAgentHeartbeatRevocationCaches(AgentHeartbeatSSHKRLSchemaVersion, "tenant-1", beat); err != nil {
		t.Errorf("v5 without cache posture = %v", err)
	}
	if err := validateAgentHeartbeatPluginCensus(AgentHeartbeatSSHKRLSchemaVersion, "tenant-1", beat); err != nil {
		t.Errorf("v5 without a plugin census = %v", err)
	}
}
