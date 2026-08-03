// SPDX-License-Identifier: MPL-2.0

package relay

// What this build can actually execute (epic A3, the C1a discipline).
//
// C1a's rule: a capability the product advertises must be one the shipped
// binary performs. It applies with more force here than to discovery, because
// an advertised-but-absent relay capability does not merely fail to collect
// something — it takes a claim, burns the attempt's one credential redemption,
// and hands the work back having moved a credential outside the seal for
// nothing.
//
// So the census below is the single source of truth for what a relay tells the
// control plane it can do, and docs/agent_advertised_capability_test.go fails
// the build if a declared kind has no constructor this binary calls.

// ShippedJobKind is one job kind this agent build can execute end to end.
type ShippedJobKind struct {
	// Kind is the outbox destination the agent claims.
	Kind string
	// Connectors are the connector implementations this build carries for that
	// kind. A connector.* kind with none is not shipped, whatever it claims.
	// Kinds that are not connector work legitimately have none — a revocation
	// probe reads public distribution points and drives no connector at all —
	// so the guard checks this only for the kinds it applies to.
	Connectors []string
	// Flags are the agent flags that switch this kind on. A kind with flags
	// executes nothing until an operator sets them, so advertising it without
	// naming them would read as coverage that is not running.
	Flags []string
}

// ShippedJobKinds is what this build performs. connector.deploy is the only
// one: a relay drives appliances, and everything else in the job allowlist is
// either host-local work (discovery.run, trust.distribute), observation the
// verification epics own (endpoint.verify, revocation.probe), or rollback,
// which needs a retained predecessor credential that nothing yet keeps.
func ShippedJobKinds() []ShippedJobKind {
	return []ShippedJobKind{
		{
			Kind: "connector.deploy",
			// Both vantages, because one binary serves both roles: the appliance
			// connectors a relay drives over an API, and the file/exec
			// connectors a host agent runs on its own machine (epic D1). Which
			// one a given job needs is decided by the connector, and the control
			// plane's per-row role demand decides which agent may claim it.
			Connectors: append(append([]string(nil), RelayConnectorKinds()...), HostConnectorKinds()...),
			Flags:      []string{"--relay-claim", "--host-exec-profile"},
		},
		{
			// D5: the dry-run. Same connectors, same credential redemption, and
			// deliberately never connector.Run — zero writes is structural here,
			// not a promise, because the mutating path is not on it.
			Kind:       KindConnectorTest,
			Connectors: RelayConnectorKinds(),
			Flags:      []string{"--relay-claim"},
		},
		{
			// R1: revocation distribution-point health. It carries no credential
			// — CRLs are public — so it is the one shipped kind that redeems
			// nothing, and the loop routes it before the redemption step for
			// exactly that reason.
			Kind:  KindRevocationProbe,
			Flags: []string{"--relay-claim"},
		},
		{
			// C2: segment sweeps. Like the revocation probe this reads publicly
			// served material and redeems nothing — and like it, the value is
			// entirely in the vantage: a scan that can only see what the control
			// plane routes to inventories the least interesting surface an
			// estate has.
			Kind:  KindDiscoveryRun,
			Flags: []string{"--relay-claim"},
		},
		{
			// F1: AD CS template posture. It must run in-domain — a domain
			// controller's LDAP is not reachable from a hosted control plane and
			// should not be — so an in-domain relay is the only vantage from
			// which this inventory exists at all. It redeems a bind credential,
			// unlike the other read-only kinds.
			Kind:  KindADCSInventory,
			Flags: []string{"--relay-claim"},
		},
	}
}

// UnshippedJobKinds are kinds the control plane's allowlist recognises that this
// relay build cannot execute, with the reason. Naming them is the point: an
// operator enabling one of these on the control plane should be able to find out
// here why nothing happens, rather than watching a queue not drain.
func UnshippedJobKinds() map[string]string {
	return map[string]string{
		"connector.rollback": "needs a retained predecessor credential; nothing keeps one yet",
		"trust.distribute":   "host-local work: installs roots in a host's own trust store",
		"endpoint.verify":    "owned by the verification epics; no relay-side prober ships yet",
	}
}
