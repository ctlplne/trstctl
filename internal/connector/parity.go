// SPDX-License-Identifier: BUSL-1.1

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

// e1SourcePlanFamilies is the accepted denominator from WS-E/E1 in
// trstctl-clm-remediation-plan-2026-08-02.html, not a list inferred from what the
// current relay happens to implement.
//
// The plan spells out eleven names and then says "+ DB/API variants" while the
// same sentence and epic title fix the total at thirteen. PostgreSQL and MySQL
// are the two shipped database connector families that resolve that shorthand.
// Naming them here removes the ambiguity from every executable surface. If the
// product plan changes, this one list changes first; ParityProgram, the catalog,
// support matrix guards, console, and docs all consume it.
//
// Membership does NOT route work. It only says "E1 promised to assess this
// family." relayVantageFamilies below remains the runtime routing census, so an
// omitted implementation shows as unimplemented instead of accidentally
// sending cloud or host work to an agent that has no constructor for it.
var e1SourcePlanFamilies = []string{
	"a10",
	"aws-acm",
	"azure-keyvault",
	"cisco",
	"envoy",
	"f5",
	"fortigate",
	"gcp-certificate-manager",
	"kemp",
	"mysql",
	"netscaler",
	"paloalto",
	"postgresql",
}

// IsE1Family reports whether the accepted E1 source plan names a family.
func IsE1Family(name string) bool {
	for _, family := range e1SourcePlanFamilies {
		if family == name {
			return true
		}
	}
	return false
}

// E1Families returns the accepted E1 denominator, sorted.
func E1Families() []string {
	out := append([]string(nil), e1SourcePlanFamilies...)
	sort.Strings(out)
	return out
}

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

// cpRetainedFamilies are relay-vantage families whose control-plane execution
// remains an OPEN architecture exception.
//
// A 2026-08-08 owner decision retained these paths. AUD-33 corrects the status:
// retention explains why a migration is unsafe; it does not erase the family
// from the accepted denominator or make E1 complete. These three cannot pass
// the rollback/readback gates because of a property of
// the DEVICE APIs, not of this repository: each imports a certificate by name
// with no separately addressable installed object, so a re-bind (rollback) and
// an installed-state query (readback) are not expressible. Migrating them
// anyway would remove the control plane's proven fallback without the recovery
// path that justifies removing it, which D5 forbids. Their support-matrix rows
// (KnownLimits) state the same constraint per family; this census is what lets
// the parity surface say "open architecture exception" instead of silently
// presenting the control-plane path as completed migration.
//
// A family leaves this list only if its vendor API grows an addressable
// installed object (re-check on new PAN-OS / FortiOS / IOS-XE majors) — at
// which point it must pass the same gates as everyone else, not skip them.
var cpRetainedFamilies = []string{
	"cisco",
	"fortigate",
	"paloalto",
}

// CPRetained reports whether a family's control-plane execution remains as an
// explicit E1 architecture exception. The wire field is kept for compatible
// clients; ParityStatus.Disposition is the authoritative classification.
func CPRetained(family string) bool {
	for _, n := range cpRetainedFamilies {
		if n == family {
			return true
		}
	}
	return false
}

// retainedScopeNote is the operator-facing sentence for a retained family.
const retainedScopeNote = "open architecture exception: control-plane execution remains because this " +
	"device's management API imports a certificate by name with no separately addressable " +
	"installed object, so relay rollback and readback are not expressible; this family keeps E1 " +
	"open and its support-matrix row records the limitation"

// unimplementedScopeNotes state where each omitted family executes today and
// which E1 proof is absent. They are deliberately per family: one generic
// "pending" label would hide that cloud stores still run in the control plane
// while Envoy and the database connectors already run on host agents.
var unimplementedScopeNotes = map[string]string{
	"envoy": "E1 network-relay migration is unimplemented: Envoy SDS currently executes on the " +
		"co-resident host agent and has no network-relay constructor, relay proof, or E1 refusal",
	"aws-acm": "E1 network-relay migration is unimplemented: AWS ACM currently executes in the " +
		"control plane and has no relay constructor, relay proof, or control-plane refusal",
	"azure-keyvault": "E1 network-relay migration is unimplemented: Azure Key Vault currently executes " +
		"in the control plane and has no relay constructor, relay proof, or control-plane refusal",
	"gcp-certificate-manager": "E1 network-relay migration is unimplemented: GCP Certificate Manager " +
		"currently executes in the control plane and has no relay constructor, relay proof, or " +
		"control-plane refusal",
	"postgresql": "E1 network-relay migration is unimplemented: PostgreSQL currently executes on the " +
		"host agent and has no network-relay constructor, relay proof, or E1 refusal",
	"mysql": "E1 network-relay migration is unimplemented: MySQL currently executes on the host agent " +
		"and has no network-relay constructor, relay proof, or E1 refusal",
}

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

// haPeerSyncFamilies are the HA-paired families whose connector deploys to,
// rolls back, and reads back BOTH peers — closing the split-config-store gap
// that would otherwise make their migrated path wrong. It is the census that
// OWNS the "HA-peer sync is built for this family" fact; requiredParityGates
// adds the gate for haPairedFamilies and this list answers it.
//
// f5's HAPair (internal/connector/f5/hapair.go) is a Connector over both peers,
// exercised end to end in the relay HA proof test. NetScaler and A10 are HA
// too but their pairs replicate certificate objects, so they are not in
// haPairedFamilies and need nothing here.
var haPeerSyncFamilies = []string{
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
// four families in the control plane to avoid an improvement. It is reported
// as Outstanding on the parity surface: a post-E1 enhancement (E1 itself
// closed 2026-08-08 at the gate-capable families), not a silent omission.
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

// haPeerSyncBuilt reports whether a family's connector deploys to both HA peers.
func haPeerSyncBuilt(family string) bool {
	for _, n := range haPeerSyncFamilies {
		if n == family {
			return true
		}
	}
	return false
}

// gateMet answers one gate from the census that owns it.
//
// ParityGateDeviceCSR has no census because nothing implements it; it answers
// false, and the day it is built this switch is where the census it grows gets
// consulted. ParityGateHAPeerSync gained exactly such a census (haPeerSyncFamilies)
// when F5's HAPair was built.
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
		// Met for every relay family: internal/server's handleDeploy refuses a
		// migrated family's deploy when the tenant has a network relay
		// enrolled, so the control plane no longer races the relay for work the
		// A3 stamp reserved for it.
		//
		// The refusal is CONDITIONAL on a relay existing, and this census says
		// "met" for that rather than inventing a fourth state. An estate with no
		// relay still deploys from the control plane, which is the behaviour
		// that predates E1 and is not a defect — E1's claim is that a relay,
		// where you run one, is the executor and not merely a candidate.
		return IsRelayVantageFamily(family)
	case ParityGateHAPeerSync:
		// Met for families whose connector reaches BOTH HA peers, enforced by
		// the relay HA proof test: it drives a deploy to two device doubles and
		// fails if either is left behind, so this cannot drift into a claim.
		return haPeerSyncBuilt(family)
	case ParityGateDeviceCSR:
		return false
	default:
		// An unknown gate is not met. Failing closed here means adding a gate
		// constant without teaching this function about it blocks migration
		// rather than silently passing it.
		return false
	}
}

// ParityDisposition is the closed, operator-visible classification of an E1
// family. A family cannot disappear into a narrower denominator: it is either
// migrated, an explicit architecture exception, or not implemented.
type ParityDisposition string

const (
	ParityDispositionMigrated              ParityDisposition = "migrated"
	ParityDispositionArchitectureException ParityDisposition = "architecture_exception"
	ParityDispositionUnimplemented         ParityDisposition = "unimplemented"
)

// ParityStatus is one family's position in the E1 migration.
type ParityStatus struct {
	Family string `json:"family"`
	// Disposition is the authoritative, closed classification for this family.
	Disposition ParityDisposition `json:"disposition"`
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
	// CPRetained is true for families whose control-plane path remains an open
	// architecture exception: their device APIs cannot express the
	// rollback/readback gates. ScopeNote carries the operator-facing reason.
	CPRetained bool   `json:"cp_retained"`
	ScopeNote  string `json:"scope_note,omitempty"`
}

// ParityStatusFor reports a family's migration position.
//
// Families outside E1 fail closed with no disposition and cannot become
// relay-migrated by accidentally satisfying a subset of unrelated censuses.
func ParityStatusFor(family string) ParityStatus {
	status := ParityStatus{Family: family, RelayMigrated: IsE1Family(family)}
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
	if CPRetained(family) {
		status.CPRetained = true
		status.ScopeNote = retainedScopeNote
	}
	if !IsE1Family(family) {
		return status
	}
	switch {
	case status.RelayMigrated:
		status.Disposition = ParityDispositionMigrated
	case status.CPRetained:
		status.Disposition = ParityDispositionArchitectureException
	default:
		status.Disposition = ParityDispositionUnimplemented
		status.ScopeNote = unimplementedScopeNotes[family]
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
	out := make([]string, 0, len(e1SourcePlanFamilies))
	for _, family := range E1Families() {
		if RelayMigrated(family) {
			out = append(out, family)
		}
	}
	return out
}

// ParityProgram reports every family in the accepted source-plan denominator.
// It must not iterate relayVantageFamilies: doing so would let implementation
// scope rewrite product acceptance and is the exact AUD-33 regression.
func ParityProgram() []ParityStatus {
	out := make([]ParityStatus, 0, len(e1SourcePlanFamilies))
	for _, family := range E1Families() {
		out = append(out, ParityStatusFor(family))
	}
	return out
}
