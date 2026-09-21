// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"reflect"
	"sort"
	"testing"
)

// The E1 migration census, asserted against what this repository actually has.
//
// This is a change-detector on purpose — the C1a discipline. The status is
// published to operators and is the predicate the control-plane refusal will be
// wired to, so a change to any census it derives from moves a claim on the
// console and, once the refusal lands, production routing with it. Failing here
// forces whoever made that change to look at this table and agree with it.
//
// Which is the point, because the previous version of E1 shipped "7 appliance
// families proven" as its headline while three of the seven had no rollback and
// no readback, and nothing anywhere said so.

func TestTheParityProgramReportsExactlyWhatIsBuilt(t *testing.T) {
	t.Parallel()
	missingRelayImplementation := []ParityGate{
		ParityGateDeviceProof,
		ParityGateRollback,
		ParityGateReadback,
		ParityGateRelayExecutionProof,
		ParityGateCPPathRefusal,
	}
	want := map[string]struct {
		migrated    bool
		retained    bool
		disposition ParityDisposition
		missing     []ParityGate
		outstanding []ParityGate
	}{
		// MIGRATED. Device proof, rollback, readback, a published support row,
		// a relay deploy proven against the device double, and a control plane
		// that refuses their deploys when a relay is enrolled. For these three,
		// E1's sentence is now true: where you run a relay, the relay is the
		// executor rather than one of two candidates racing.
		"a10":       {migrated: true, disposition: ParityDispositionMigrated, outstanding: []ParityGate{ParityGateDeviceCSR}},
		"kemp":      {migrated: true, disposition: ParityDispositionMigrated},
		"netscaler": {migrated: true, disposition: ParityDispositionMigrated, outstanding: []ParityGate{ParityGateDeviceCSR}},
		// F5 now closes the last gate: HAPair deploys, rolls back, and reads
		// back BOTH peers, so the migrated path is no longer wrong on an HA
		// pair. A deploy that reaches only the active node fails rather than
		// reporting success, and a readback reports the pair serving only when
		// both peers are bound to the deployed certificate.
		"f5": {migrated: true, disposition: ParityDispositionMigrated, outstanding: []ParityGate{ParityGateDeviceCSR}},
		// Device-proven and relay-proven, but they cannot be asked what they
		// hold or told to put back what they held. Migrating them would remove
		// the control plane's fallback without providing the recovery path that
		// justifies removing it.
		"cisco": {migrated: false, retained: true, disposition: ParityDispositionArchitectureException,
			missing:     []ParityGate{ParityGateRollback, ParityGateReadback},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		"fortigate": {migrated: false, retained: true, disposition: ParityDispositionArchitectureException,
			missing: []ParityGate{ParityGateRollback, ParityGateReadback}},
		"paloalto": {migrated: false, retained: true, disposition: ParityDispositionArchitectureException,
			missing:     []ParityGate{ParityGateRollback, ParityGateReadback},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		// The source plan's six omitted families. None has a network-relay
		// constructor, relay execution proof, or control-plane refusal. Envoy,
		// PostgreSQL, and MySQL currently execute on host agents; the cloud
		// stores execute in the control plane. Those are honest runtime facts,
		// not permission to remove them from E1's accepted denominator.
		"envoy":                   {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
		"aws-acm":                 {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
		"azure-keyvault":          {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
		"gcp-certificate-manager": {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
		"postgresql":              {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
		"mysql":                   {migrated: false, disposition: ParityDispositionUnimplemented, missing: missingRelayImplementation},
	}

	program := ParityProgram()
	if len(program) != len(want) {
		t.Fatalf("the parity program covers %d families, the table expects %d — a relay family "+
			"was added or removed without updating this census", len(program), len(want))
	}
	for _, got := range program {
		expect, ok := want[got.Family]
		if !ok {
			t.Errorf("family %q is relay-vantage but absent from this census; decide its gates "+
				"deliberately rather than letting it inherit a default", got.Family)
			continue
		}
		if got.RelayMigrated != expect.migrated {
			t.Errorf("%s: relay_migrated=%v, expected %v. This flips whether the control plane "+
				"refuses the family's deploys, so confirm the change is intended before "+
				"updating this table (missing gates: %v)", got.Family, got.RelayMigrated,
				expect.migrated, got.Missing)
		}
		if got.CPRetained != expect.retained {
			t.Errorf("%s: cp_retained=%v, expected %v", got.Family, got.CPRetained, expect.retained)
		}
		if got.Disposition != expect.disposition {
			t.Errorf("%s: disposition=%q, expected %q", got.Family, got.Disposition, expect.disposition)
		}
		if !sameGates(got.Missing, expect.missing) {
			t.Errorf("%s: missing gates %v, expected %v", got.Family, got.Missing, expect.missing)
		}
		if !sameGates(got.Outstanding, expect.outstanding) {
			t.Errorf("%s: outstanding gates %v, expected %v", got.Family, got.Outstanding, expect.outstanding)
		}
	}
}

// A migrated family must have nothing missing, and an un-migrated one must say
// what is missing. "Not migrated" with an empty reason is a status an operator
// reads as "coming soon" and nobody ever revisits.
func TestNoFamilyIsUnmigratedWithoutSayingWhy(t *testing.T) {
	t.Parallel()
	for _, status := range ParityProgram() {
		if status.RelayMigrated && len(status.Missing) > 0 {
			t.Errorf("%s reports migrated while still missing %v", status.Family, status.Missing)
		}
		if !status.RelayMigrated && len(status.Missing) == 0 {
			t.Errorf("%s reports un-migrated and names no missing gate", status.Family)
		}
	}
}

// RelayMigrated must answer false for everything that is not an appliance, so
// wiring the control-plane refusal to it cannot change host or cloud routing.
func TestOnlyApplianceFamiliesCanBeRelayMigrated(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"nginx", "apache", "iis", "tomcat", "aws-acm",
		"azure-keyvault", "gcp-certificate-manager", "", "does-not-exist"} {
		if RelayMigrated(family) {
			t.Errorf("%q reports relay-migrated; the control plane would refuse to deploy it "+
				"and no relay would ever claim it", family)
		}
	}
}

// A family may read as migrated only if the control plane really refuses it.
//
// This started life asserting that NOTHING was migrated, which was true while
// cp_path_refusal was unimplemented. The assertion that mattered was never the
// zero — it was that the console cannot claim a migration the running binary
// does not honor. That is what is asserted now, so the test survived the
// change it was written to catch instead of being deleted by it.
func TestNothingReadsAsMigratedWhileTheControlPlaneStillExecutesIt(t *testing.T) {
	t.Parallel()
	for _, family := range RelayMigratedConnectors() {
		if !IsRelayVantageFamily(family) {
			t.Errorf("%s is relay-migrated but not relay-vantage", family)
		}
	}
	for _, status := range ParityProgram() {
		if status.RelayMigrated && !gateMet(status.Family, ParityGateCPPathRefusal) {
			t.Errorf("%s reads as migrated while the control plane still executes its deploys",
				status.Family)
		}
	}
	if len(RelayMigratedConnectors()) == 0 {
		t.Error("no family is relay-migrated, so the control-plane refusal is wired to a " +
			"predicate that is always false and E1 serves nothing")
	}
}

// The relay execution proof must cover every family the relay advertises.
//
// Asserted here as well as in the relay's own test because this census reports
// it as a gate: if the two ever disagree, the console publishes a proof that
// does not exist.
func TestEveryRelayFamilyReportsItsExecutionProof(t *testing.T) {
	t.Parallel()
	for _, family := range RelayVantageFamilies() {
		if !gateMet(family, ParityGateRelayExecutionProof) {
			t.Errorf("%s is relay-vantage and reports no relay execution proof", family)
		}
	}
	for _, family := range []string{"nginx", "aws-acm", ""} {
		if gateMet(family, ParityGateRelayExecutionProof) {
			t.Errorf("%q is not relay work and must not report a relay execution proof", family)
		}
	}
}

func sameGates(got, want []ParityGate) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	g := append([]ParityGate(nil), got...)
	w := append([]ParityGate(nil), want...)
	sort.Slice(g, func(i, j int) bool { return g[i] < g[j] })
	sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
	return reflect.DeepEqual(g, w)
}
