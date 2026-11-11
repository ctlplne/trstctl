// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// AgentHeartbeatRelayEgressSchemaVersion adds a relay's self-reported egress
// policy to the executor census (A190-L1). It is introduced by that policy;
// every earlier report stays independently optional.
const AgentHeartbeatRelayEgressSchemaVersion = 8

// AgentRelayEgressMaxEntries and AgentRelayEgressMaxEntryBytes bound a
// relay's self-reported egress allowlist.
const (
	AgentRelayEgressMaxEntries    = 64
	AgentRelayEgressMaxEntryBytes = 64
)

// AgentRelayEgress is the egress policy a relay's job connections follow, as
// the relay reports it: Restricted when --relay-egress-allow lists
// destinations, and the listed CIDRs, addresses and address:port pairs.
// Link-local, cloud metadata, unspecified and multicast addresses are refused
// either way. Truncated says the recorded list is shorter than the relay's:
// it listed more than AgentRelayEgressMaxEntries entries, or an entry that is
// not an address, prefix or address:port.
type AgentRelayEgress struct {
	Restricted bool     `json:"restricted"`
	Allow      []string `json:"allow"`
	Truncated  bool     `json:"truncated,omitempty"`
}

// ValidRelayEgressEntry reports whether entry is one relay egress allowlist
// entry as a relay reports it: a CIDR prefix, an address or an address:port,
// at most AgentRelayEgressMaxEntryBytes long.
func ValidRelayEgressEntry(entry string) bool {
	if entry == "" || len(entry) > AgentRelayEgressMaxEntryBytes || strings.TrimSpace(entry) != entry {
		return false
	}
	if _, err := netip.ParsePrefix(entry); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(entry); err == nil {
		return true
	}
	_, err := netip.ParseAddrPort(entry)
	return err == nil
}

// validateAgentHeartbeatRelayEgress binds the relay egress policy to the
// schema version that introduced it and holds it to its bounds.
func validateAgentHeartbeatRelayEgress(schemaVersion int, heartbeat AgentHeartbeat) error {
	var report *AgentRelayEgress
	if heartbeat.Executors != nil {
		report = heartbeat.Executors.RelayEgress
	}
	if schemaVersion != AgentHeartbeatRelayEgressSchemaVersion {
		if report != nil {
			return fmt.Errorf("projections: agent.heartbeat v%d cannot carry a relay egress policy", schemaVersion)
		}
		return nil
	}
	if report == nil {
		return errors.New("projections: agent.heartbeat v8 requires the relay's egress policy")
	}
	if len(report.Allow) > AgentRelayEgressMaxEntries {
		return errors.New("projections: relay egress allowlist exceeds its bounds")
	}
	if !report.Restricted && (len(report.Allow) > 0 || report.Truncated) {
		return errors.New("projections: a relay egress policy without an allowlist cannot list destinations")
	}
	for _, entry := range report.Allow {
		if !ValidRelayEgressEntry(entry) {
			return errors.New("projections: relay egress entry is not an address, prefix or address:port")
		}
	}
	return nil
}
