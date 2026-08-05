// SPDX-License-Identifier: MPL-2.0

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
	want := map[string]struct {
		migrated    bool
		missing     []ParityGate
		outstanding []ParityGate
	}{
		// Nothing is migrated, and cp_path_refusal is why. Every family below
		// carries it, because the control plane still executes all seven: the
		// dispatcher sweeps connector.* on a one-second ticker and the outbox
		// claim query has no required_agent_role predicate, so the A3 role stamp
		// reserves the row for a relay that never gets to it. This census is the
		// first place that fact is written down where a reader can see it.
		//
		// These three are otherwise through: device proof, rollback, readback,
		// a published support row, and a relay deploy proven against the device
		// double. They are the families the refusal would flip first.
		"a10": {missing: []ParityGate{ParityGateCPPathRefusal},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		"kemp": {missing: []ParityGate{ParityGateCPPathRefusal}},
		"netscaler": {missing: []ParityGate{ParityGateCPPathRefusal},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		// F5 has everything those three have and one more gate to clear. A
		// migrated F5 without HA-peer sync would be WRONG rather than
		// incomplete: the deploy updates one peer, reports success, and the
		// other keeps serving the old certificate until a failover months later
		// surfaces it as expired.
		"f5": {missing: []ParityGate{ParityGateCPPathRefusal, ParityGateHAPeerSync},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		// Device-proven and relay-proven, but they cannot be asked what they
		// hold or told to put back what they held. Migrating them would remove
		// the control plane's fallback without providing the recovery path that
		// justifies removing it.
		"cisco": {missing: []ParityGate{ParityGateCPPathRefusal, ParityGateRollback, ParityGateReadback},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
		"fortigate": {missing: []ParityGate{ParityGateCPPathRefusal, ParityGateRollback, ParityGateReadback}},
		"paloalto": {missing: []ParityGate{ParityGateCPPathRefusal, ParityGateRollback, ParityGateReadback},
			outstanding: []ParityGate{ParityGateDeviceCSR}},
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

// Every migrated family must be relay-vantage, and today none is.
//
// The zero is asserted rather than tolerated. A green "0 of 7 migrated" is the
// true state and it is the whole reason this census was written; the failure
// mode it guards against is somebody making a family read as migrated without
// the control-plane refusal actually landing, which would put a claim on the
// console that the running binary does not honour.
func TestNothingReadsAsMigratedWhileTheControlPlaneStillExecutesIt(t *testing.T) {
	t.Parallel()
	for _, family := range RelayMigratedConnectors() {
		if !IsRelayVantageFamily(family) {
			t.Errorf("%s is relay-migrated but not relay-vantage", family)
		}
	}
	for _, status := range ParityProgram() {
		refused := gateMet(status.Family, ParityGateCPPathRefusal)
		if status.RelayMigrated && !refused {
			t.Errorf("%s reads as migrated while the control plane still executes its deploys",
				status.Family)
		}
		if refused != status.RelayMigrated && refused {
			t.Errorf("%s: the control plane refuses it but it does not read as migrated; the "+
				"refusal and the census have come apart", status.Family)
		}
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
