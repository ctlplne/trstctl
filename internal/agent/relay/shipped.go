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

// ShippedJobKinds is what this build performs.
func ShippedJobKinds() []ShippedJobKind {
	return []ShippedJobKind{
		{
			// H2: host-local CA-anchor install/remove plus exact readback. Public
			// anchor bytes travel in the job; no credential is redeemed.
			Kind:  KindTrustDistribute,
			Flags: []string{"--relay-claim", "--host-exec-profile"},
		},
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
			// B2: host-generated renewal. HOST connectors only, and that is the
			// whole point of it being a distinct kind rather than a flag on
			// connector.deploy: the key is generated on the machine that will
			// serve it, so a vantage that merely reaches the target cannot
			// perform this work at all.
			//
			// It redeems no credential, because the credential does not exist
			// until this agent makes it. That is the one kind in this census
			// whose material flows UP.
			Kind:       KindEndpointRenew,
			Connectors: HostConnectorKinds(),
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
			// D4/G1: appliances re-bind an installed object; host agents restore
			// their one encrypted predecessor bundle, reload, and reverify.
			// Every other family is refused at the API rather than advertised.
			Kind:       KindConnectorRollback,
			Connectors: RollbackExecutableKinds(),
			Flags:      []string{"--relay-claim", "--host-exec-profile", "--host-rollback-dir"},
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
			// D2: the network vantage. It carries no credential — a listener's
			// served certificate is public — so like the revocation probe it
			// redeems nothing, and it declares no connectors because it is a
			// probe rather than connector work.
			//
			// The HOST half of verification is deliberately absent from this
			// census: the agent's post-deploy self-check is not a claimed job,
			// it runs inside connector.deploy where the deployed material is
			// still live. Listing it here would advertise a claimable capability
			// that no claim protocol serves.
			Kind:  KindEndpointVerify,
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
		{
			// I2: the CMDB read from inside the segment. Redeems the ServiceNow
			// token per attempt; reports parsed records, never the raw response.
			// The reconcile stays in the control plane.
			Kind:  KindCMDBSync,
			Flags: []string{"--relay-claim"},
		},
		{
			// I5: the MDM read from inside the segment, for the on-prem Jamf
			// the control plane cannot reach. Redeems the MDM token per
			// attempt; reports parsed devices, never the raw response. The
			// correlation stays in the control plane.
			Kind:  KindMDMSync,
			Flags: []string{"--relay-claim"},
		},
		{
			// I3: ServiceNow ticket intake. Only mapped request fields return;
			// the bearer token is redeemed for this one attempt.
			Kind:  KindTicketSync,
			Flags: []string{"--relay-claim"},
		},
		{
			// A5: this agent's own staged upgrade. It redeems nothing — the
			// artifact URL travels in the payload and the pinned sha256 is the
			// trust anchor — and it declares no connectors because the thing it
			// deploys is this binary itself. Its own flag rather than
			// --relay-claim, because replacing the executable is a consent the
			// machine's operator gives separately from executing connector work.
			Kind:  KindAgentUpgrade,
			Flags: []string{"--self-upgrade"},
		},
	}
}

// UnshippedJobKinds are kinds the control plane's allowlist recognises that this
// relay build cannot execute, with the reason. Naming them is the point: an
// operator enabling one of these on the control plane should be able to find out
// here why nothing happens, rather than watching a queue not drain.
func UnshippedJobKinds() map[string]string {
	return map[string]string{}
}
