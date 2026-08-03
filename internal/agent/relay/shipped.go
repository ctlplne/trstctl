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
	// kind. A kind with no connectors is not shipped, whatever it claims.
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
			Kind:       "connector.deploy",
			Connectors: RelayConnectorKinds(),
			Flags:      []string{"--relay-claim"},
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
		"discovery.run":      "host-local work: a relay has no filesystem of the appliance's to enumerate",
		"trust.distribute":   "host-local work: installs roots in a host's own trust store",
		"endpoint.verify":    "owned by the verification epics; no relay-side prober ships yet",
		"revocation.probe":   "owned by the verification epics; no relay-side prober ships yet",
	}
}
