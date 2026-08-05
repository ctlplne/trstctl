// SPDX-License-Identifier: MPL-2.0

package connector

import "sort"

// Per-family parity gates for the relay migration (epic E1).
//
// E1 is a MIGRATION, not a feature: each appliance family moves its execution
// from the control plane to the relay runtime, and the control-plane path is
// refused once that family is through its gate. A migration needs a state per
// family, and the reason this file exists is that the state was previously
// implicit — the tree had a device-proof census, a rollback census, a readback
// census and a support matrix, four independent lists that between them decide
// whether a family is ready, and nothing that read them together or told an
// operator the answer.
//
// The gates are DERIVED from those censuses rather than restated here. A second
// hand-maintained list would be a second thing to forget: a family added to
// rollbackCapableFamilies and not to a parity list would read as un-migrated
// forever, and — worse in the other direction — a family removed from a census
// would keep whatever parity status somebody last typed. Deriving means the
// answer cannot disagree with the evidence it is drawn from.

// relayVantageFamilies are the appliance families whose deploy work executes on
// a network relay rather than in the control plane.
//
// This list is the ONE owner of that fact. The composition root's vantage census
// consults it instead of repeating it, because the tree has already been bitten
// by a duplicated census: B2 shipped an executor marker defined twice, in
// internal/server and internal/api, with a comment claiming a guard test aligned
// them and no such test existing. A guard test would make drift detectable; one
// list makes it impossible, which is the better of the two.
//
// Membership is a statement about where the DEVICE lives — inside a segment a
// relay sits in — not about whether this repository is finished migrating the
// family. That is what ParityStatusFor answers, and the two are deliberately
// separate: a family is relay-vantage from the moment it is an appliance, and
// relay-MIGRATED only once its gates are green.
var relayVantageFamilies = []string{
	"a10",
	"cisco",
	"f5",
	"fortigate",
	"kemp",
	"netscaler",
	"paloalto",
}

// IsRelayVantageFamily reports whether a family's deploys execute on a relay.
func IsRelayVantageFamily(name string) bool {
	for _, n := range relayVantageFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// RelayVantageFamilies reports the relay-executed appliance families, sorted.
func RelayVantageFamilies() []string {
	out := append([]string(nil), relayVantageFamilies...)
	sort.Strings(out)
	return out
}

// ParityGate names one of the per-family gates E1 requires.
type ParityGate string

const (
	// ParityGateDeviceProof — the family's deploy runs against a faithful
	// in-process double of its management API, not just against MemoryOps.
	ParityGateDeviceProof ParityGate = "device_proof"
	// ParityGateRollback — the family can re-bind a predecessor object, so a
	// bad deploy is recoverable from the relay rather than by hand.
	ParityGateRollback ParityGate = "rollback"
	// ParityGateReadback — the family's API can be asked what it actually has
	// installed, which is what makes the relay a witness (E2) rather than a
	// reporter of its own intent.
	ParityGateReadback ParityGate = "readback"
	// ParityGateSupportMatrix — the family publishes an E3 row saying what was
	// exercised and what was not, in the same change that migrates it.
	ParityGateSupportMatrix ParityGate = "support_matrix"
	// ParityGateRelayExecutionProof — a deploy driven through relay.Execute
	// reaches the family's device double and the certificate is read back out
	// of it. Distinct from device_proof, which drives the CONNECTOR: the relay
	// adds target-config decoding, credential-reference resolution and
	// connector construction, none of which the device proof runs.
	ParityGateRelayExecutionProof ParityGate = "relay_execution_proof"
	// ParityGateCPPathRefusal — the control plane refuses this family's deploys,
	// so the relay is the only executor rather than merely a possible one.
	ParityGateCPPathRefusal ParityGate = "cp_path_refusal"
	// ParityGateHAPeerSync — the family's devices are deployed as an HA pair
	// with independent configuration stores, and a deploy must reach both.
	ParityGateHAPeerSync ParityGate = "ha_peer_sync"
	// ParityGateDeviceCSR — the appliance generates its own key and emits a
	// CSR, so the key never leaves the device.
	ParityGateDeviceCSR ParityGate = "device_generated_csr"
)

// haPairedFamilies are families whose HA deployment gives each peer its own
// configuration store, so a deploy that reaches one peer leaves the other
// serving the old certificate until failover — at which point it serves an
// expired one.
//
// Named for F5 by E1 specifically. NetScaler and A10 also run HA, but their
// pairs propagate configuration between peers, so a single push converges; F5's
// does not for certificate objects. Listing them here anyway would block their
// migration on work that has nothing to do for them.
var haPairedFamilies = []string{
	"f5",
}

// deviceCSRCapableFamilies are appliances whose management API can generate a
// key on the device and return a CSR.
//
// This is a capability of the DEVICE, not of this repository: every family here
// supports it and none of them is wired for it yet. The list exists so the
// parity surface can say "supported by the appliance, not implemented here"
// rather than staying silent, which would read as "not applicable".
var deviceCSRCapableFamilies = []string{
	"f5",
	"netscaler",
	"a10",
	"cisco",
	"paloalto",
}

// requiredParityGates are the gates that decide migration.
//
// They are exactly E1's acceptance line — deploy, verify, rollback, published
// support row — plus HA-peer sync for the families that need it, and the HA
// inclusion is a judgement worth stating. HA-peer sync is not on the acceptance
// line. It is included because migrating without it would make the migrated
// path WRONG rather than merely incomplete: a relay deploy to an F5 pair would
// report success having updated one peer, and the failure surfaces at failover,
// months later, as an expired certificate on a device nobody touched.
//
// ParityGateRelayExecutionProof and ParityGateCPPathRefusal are both required
// because between them they are the migration: one says the relay can do the
// work, the other says it is the thing that does it. A family with the first
// and not the second is a family the relay COULD serve while the control plane
// still does, which is where every one of them stands today.
//
// ParityGateDeviceCSR is deliberately NOT required. It is an alternative
// custody mode, and the existing mode — relay generates, relay installs — is
// correct as it stands, just less good. Blocking migration on it would hold
// four families in the control plane to avoid an improvement, and E1 stays
// in_progress until it is built either way.
func requiredParityGates(family string) []ParityGate {
	gates := []ParityGate{
		ParityGateDeviceProof,
		ParityGateRollback,
		ParityGateReadback,
		ParityGateSupportMatrix,
		ParityGateRelayExecutionProof,
		ParityGateCPPathRefusal,
	}
	if isHAPaired(family) {
		gates = append(gates, ParityGateHAPeerSync)
	}
	return gates
}

func isHAPaired(family string) bool {
	for _, n := range haPairedFamilies {
		if n == family {
			return true
		}
	}
	return false
}

func deviceCSRCapable(family string) bool {
	for _, n := range deviceCSRCapableFamilies {
		if n == family {
			return true
		}
	}
	return false
}

// gateMet answers one gate from the census that owns it.
//
// ParityGateHAPeerSync and ParityGateDeviceCSR have no census because nothing
// implements them; they answer false, and the day one is built this switch is
// where the census it grows gets consulted.
func gateMet(family string, gate ParityGate) bool {
	switch gate {
	case ParityGateDeviceProof:
		return DeviceProven(family)
	case ParityGateRollback:
		return CanRollback(family)
	case ParityGateReadback:
		return CanReadback(family)
	case ParityGateSupportMatrix:
		_, ok := SupportRowFor(family)
		return ok
	case ParityGateRelayExecutionProof:
		// Every relay family is covered, and the enforcement is the test
		// itself: TestARelayDeployReachesEveryApplianceItAdvertises iterates
		// RelayConnectorKinds and fails on any family it has no case for. So
		// this cannot drift into a claim — adding a family without a proof
		// breaks the build rather than quietly reading as proven here.
		return IsRelayVantageFamily(family)
	case ParityGateCPPathRefusal:
		// Not met for any family, and this is the honest blocker on the whole
		// migration rather than an oversight.
		//
		// The control-plane dispatcher sweeps every connector.* row on a
		// one-second ticker and the outbox claim query carries no
		// required_agent_role predicate, so the control plane wins the race for
		// a deploy the A3 stamp reserved for a relay. Refusing there is a
		// three-line change and is deliberately NOT made yet: the end-to-end
		// evidence that an appliance deploy works through the served API is the
		// DoD connector suite, which drives a10, cisco, kemp and netscaler
		// through the CONTROL PLANE to their device doubles. Flipping the
		// refusal without re-homing that suite onto a relay would retire a
		// proven path in favour of one whose only proof is a unit test — the
		// opposite of what this gate is for.
		return false
	case ParityGateHAPeerSync, ParityGateDeviceCSR:
		return false
	default:
		// An unknown gate is not met. Failing closed here means adding a gate
		// constant without teaching this function about it blocks migration
		// rather than silently passing it.
		return false
	}
}

// ParityStatus is one family's position in the E1 migration.
type ParityStatus struct {
	Family string `json:"family"`
	// Met are the required gates this family has passed.
	Met []ParityGate `json:"met"`
	// Missing are the required gates it has not, and they are the reason
	// RelayMigrated is false. Named individually because "not migrated" without
	// a reason is the kind of status that gets read as "coming soon".
	Missing []ParityGate `json:"missing"`
	// Outstanding are gates that are NOT required for migration but are part of
	// E1 and are not built. Reported so a migrated family cannot read as
	// finished while a named deliverable is still missing.
	Outstanding []ParityGate `json:"outstanding"`
	// RelayMigrated is true when every required gate is met. It is what decides
	// whether the control plane refuses this family's deploys.
	RelayMigrated bool `json:"relay_migrated"`
}

// ParityStatusFor reports a family's migration position.
//
// A host or cloud family has no device proof, so it reports un-migrated with
// device_proof missing. That is accurate rather than meaningful — the gate does
// not apply to a connector that writes a file — and it is why callers ask about
// relay-vantage families rather than iterating everything.
func ParityStatusFor(family string) ParityStatus {
	status := ParityStatus{Family: family, RelayMigrated: true}
	for _, gate := range requiredParityGates(family) {
		if gateMet(family, gate) {
			status.Met = append(status.Met, gate)
			continue
		}
		status.Missing = append(status.Missing, gate)
		status.RelayMigrated = false
	}
	if deviceCSRCapable(family) && !gateMet(family, ParityGateDeviceCSR) {
		status.Outstanding = append(status.Outstanding, ParityGateDeviceCSR)
	}
	return status
}

// RelayMigrated reports whether a family has passed every required E1 gate and
// therefore executes only on a relay.
//
// This is the predicate the control-plane dispatcher consults to refuse a
// deploy. It answers false for every host and cloud connector, so wiring it
// changes nothing for them.
func RelayMigrated(family string) bool {
	return ParityStatusFor(family).RelayMigrated
}

// RelayMigratedConnectors reports the migrated families, sorted.
func RelayMigratedConnectors() []string {
	out := make([]string, 0, len(relayVantageFamilies))
	for _, family := range RelayVantageFamilies() {
		if RelayMigrated(family) {
			out = append(out, family)
		}
	}
	return out
}

// ParityProgram reports every relay-vantage family's status, sorted by family.
//
// Scoped to the relay-vantage families rather than the whole registry because
// E1 is about appliances: a family with no device API has no relay migration to
// be partway through, and listing nginx here with four missing gates would be
// noise that makes the real gaps harder to see.
func ParityProgram() []ParityStatus {
	out := make([]ParityStatus, 0, len(relayVantageFamilies))
	for _, family := range RelayVantageFamilies() {
		out = append(out, ParityStatusFor(family))
	}
	return out
}
