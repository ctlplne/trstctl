// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

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
	// Roles are the certificate-bound agent roles the server permits to claim
	// this kind. The API filters the advertised census using the same values.
	Roles []string
	// Unconditional marks a kind every polling agent claims whatever its
	// flags (A71's self-check): there is no flag to name because nothing
	// switches it off, and the census guard accepts that in place of one.
	Unconditional bool
}

// ShippedJobKinds is what this build performs.
func ShippedJobKinds() []ShippedJobKind {
	return []ShippedJobKind{
		{Kind: sshtrustrollout.Destination, Flags: []string{"--ssh-trust-fleet", "--ssh-trust-confirm", "--ssh-trust-ca-key", "--ssh-trust-reload-cmd", "--ssh-trust-health-cmd"}, Roles: []string{mtls.AgentRoleHost}},
		{
			// H2: host-local CA-anchor install/remove plus exact readback. Public
			// anchor bytes travel in the job; no credential is redeemed.
			Kind:  KindTrustDistribute,
			Flags: []string{"--relay-claim", "--host-exec-profile"},
			Roles: []string{mtls.AgentRoleHost},
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
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			// B2: renewal with the key generated where it will be used, never
			// in the control plane: on the host that serves it (host
			// connectors, host role), or, for an appliance target that
			// declared key_generation=appliance, by the appliance itself at a
			// network relay's request (A122). The per-row role demand keeps
			// host work on hosts and appliance work on the pinned relay.
			//
			// A host renewal redeems no key: the key does not exist until this
			// agent makes it, which makes this the one kind in the census whose
			// material flows UP. Management credentials (a keystore password,
			// an appliance login) are redeemed per attempt as for any job.
			// --host-exec-profile applies to host agents only, as for
			// connector.deploy.
			Kind:       KindEndpointRenew,
			Connectors: append(append([]string(nil), HostConnectorKinds()...), connector.ApplianceKeyFamilies()...),
			Flags:      []string{"--relay-claim", "--host-exec-profile"},
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			// D5: the dry-run. Appliance relays resolve their management credential
			// and make one read-only request. Host agents validate their operator
			// profile and handshake the listener without receiving certificate/key
			// material or invoking connector.Run. A blocked plan is terminal, so a
			// deterministic refusal cannot become an unbounded retry storm.
			Kind:       KindConnectorTest,
			Connectors: append(append([]string(nil), RelayConnectorKinds()...), HostConnectorKinds()...),
			Flags:      []string{"--relay-claim", "--host-exec-profile"},
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			// An exact compromised leaf is stopped only by its enrolled host
			// agent under an operator-pinned local action. This is not connector
			// work: the host profile supplies the one listener and executable.
			Kind:  KindEndpointContain,
			Flags: []string{"--relay-claim", "--host-exec-profile"},
			Roles: []string{mtls.AgentRoleHost},
		},
		{
			// A210: after containment, the same enrolled host reports whether
			// its profile pins an action that restores the listener (digests
			// only) and what the listener serves now. Read-only.
			Kind:  KindEndpointRecoveryCheck,
			Flags: []string{"--relay-claim", "--host-exec-profile"},
			Roles: []string{mtls.AgentRoleHost},
		},
		{
			// A49: after containment, the same enrolled host removes the
			// compromised certificate and key files its target names, wipes
			// every ledger snapshot with that fingerprint, and runs the pinned
			// stop action when one is bound. Reference-only like containment.
			Kind:  KindEndpointPurge,
			Flags: []string{"--relay-claim", "--host-exec-profile", "--host-rollback-dir"},
			Roles: []string{mtls.AgentRoleHost},
		},
		{
			// D4/G1: appliances re-bind an installed object; host agents restore
			// their one encrypted predecessor bundle, reload, and reverify.
			// Every other family is refused at the API rather than advertised.
			Kind:       KindConnectorRollback,
			Connectors: RollbackExecutableKinds(),
			Flags:      []string{"--relay-claim", "--host-exec-profile", "--host-rollback-dir"},
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			// A43: a network relay removes the fingerprint-named object a deploy
			// installed on an appliance; a bound object is refused, never
			// unbound. Same credential redemption and grant as a deploy.
			Kind:       KindConnectorTakedown,
			Connectors: TakedownCapableKinds(),
			Flags:      []string{"--relay-claim"},
			Roles:      []string{mtls.AgentRoleNetwork},
		},
		{
			// A64: the entitlement right-size for bindings that name a relay.
			// Not connector work despite its name: the executor is the shared
			// entitlement-API conversation bound by connectors.right_size, so
			// like a revocation probe it names no connector family.
			Kind:  KindConnectorRightSize,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// A104: a co-resident Envoy's posture runs on its host; a remote
			// Envoy that declares vantage network runs on the relay the
			// target names. Each row is pinned to that one agent.
			Kind:       KindPQCPosture,
			Connectors: []string{"envoy"},
			Flags:      []string{"--relay-claim"},
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			Kind:       KindPQCPostureRollback,
			Connectors: []string{"envoy"},
			Flags:      []string{"--relay-claim"},
			Roles:      []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
		{
			// A71: the post-upgrade functional check. Every agent answers it,
			// whichever role it holds; it redeems nothing and names no
			// connector, and the campaign pins each one to the agent it asks.
			Kind:          KindAgentSelfCheck,
			Roles:         []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
			Unconditional: true,
		},
		{
			// R1: revocation distribution-point health. It carries no credential
			// — CRLs are public — so it is the one shipped kind that redeems
			// nothing, and the loop routes it before the redemption step for
			// exactly that reason.
			Kind:  KindRevocationProbe,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// C2: segment sweeps. Like the revocation probe this reads publicly
			// served material and redeems nothing — and like it, the value is
			// entirely in the vantage: a scan that can only see what the control
			// plane routes to inventories the least interesting surface an
			// estate has.
			Kind:  KindDiscoveryRun,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
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
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// F1: AD CS template posture. It must run in-domain — a domain
			// controller's LDAP is not reachable from a hosted control plane and
			// should not be — so an in-domain relay is the only vantage from
			// which this inventory exists at all. It redeems a bind credential,
			// unlike the other read-only kinds.
			Kind:  KindSSHTrustCollect,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			Kind:  KindADCSNestedGroups,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			Kind:  KindADCSInventory,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// I2: the CMDB read from inside the segment. Redeems the ServiceNow
			// token per attempt; reports parsed records, never the raw response.
			// The reconcile stays in the control plane.
			Kind:  KindCMDBSync,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// I5: the MDM read from inside the segment, for the on-prem Jamf
			// the control plane cannot reach. Redeems the MDM token per
			// attempt; reports parsed devices, never the raw response. The
			// correlation stays in the control plane.
			Kind:  KindMDMSync,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
		},
		{
			// I3: ServiceNow ticket intake. Only mapped request fields return;
			// the bearer token is redeemed for this one attempt.
			Kind:  KindTicketSync,
			Flags: []string{"--relay-claim"},
			Roles: []string{mtls.AgentRoleNetwork},
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
			Roles: []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		},
	}
}

// ShippedJobVantages is the server's fail-closed role gate for claimed work.
// Building it from the advertised census keeps the console and claim path in
// agreement when a new executable kind is added.
func ShippedJobVantages() map[string][]string {
	out := make(map[string][]string)
	for _, shipped := range ShippedJobKinds() {
		out[shipped.Kind] = append([]string(nil), shipped.Roles...)
	}
	return out
}

// UnshippedJobKinds are kinds the control plane's allowlist recognizes that this
// relay build cannot execute, with the reason. Naming them is the point: an
// operator enabling one of these on the control plane should be able to find out
// here why nothing happens, rather than watching a queue not drain.
func UnshippedJobKinds() map[string]string {
	return map[string]string{}
}
