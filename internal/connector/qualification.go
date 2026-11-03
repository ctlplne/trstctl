// SPDX-License-Identifier: BUSL-1.1

package connector

// Qualification is how far a connector or integration is proven, on one
// ladder (A242). Each rung implies the ones below it.
type Qualification string

const (
	// QualificationDiscovered: known (listed in the integration catalog or
	// seen in an estate), with no implementation in this build.
	QualificationDiscovered Qualification = "discovered"
	// QualificationImplemented: the code ships, but nothing in this estate
	// executes it.
	QualificationImplemented Qualification = "implemented"
	// QualificationServed: the running product executes it, proven through
	// its served path against a stand-in of the vendor's API or service.
	QualificationServed Qualification = "served"
	// QualificationLocallyProven: also proven against the vendor's own
	// software, run locally or on a CI runner.
	QualificationLocallyProven Qualification = "locally-proven"
	// QualificationVendorQualified: also proven against the vendor's live
	// service or hardware.
	QualificationVendorQualified Qualification = "vendor-qualified"
)

// locallyProvenFamilies are the deployment connector families with a
// repository proof against the vendor's real software, each with the test
// that proves it. None today: the census runs every family against an
// emulator of its API or service and the device proofs against faithful
// doubles, which is what "served" means. A family enters this map only with
// a lab test that runs the real software.
var locallyProvenFamilies = map[string]string{}

// QualificationFor places a deployment connector family on the ladder:
// implemented says the build carries its code, executes that something in
// this estate performs its deploys.
func QualificationFor(family string, implemented, executes bool) Qualification {
	switch {
	case !implemented:
		return QualificationDiscovered
	case supportHardwareTested(family):
		return QualificationVendorQualified
	case locallyProvenFamilies[family] != "":
		return QualificationLocallyProven
	case executes:
		return QualificationServed
	default:
		return QualificationImplemented
	}
}

func supportHardwareTested(family string) bool {
	row, ok := SupportRowFor(family)
	return ok && row.HardwareTested
}
