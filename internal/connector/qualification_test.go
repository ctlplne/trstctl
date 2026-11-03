// SPDX-License-Identifier: BUSL-1.1

package connector

import "testing"

// The ladder never claims more than the build knows: no family is locally
// proven or vendor-qualified without its proof, an executed family is served,
// one nothing executes is implemented, and one without code is discovered.
func TestQualificationLadderA242(t *testing.T) {
	if QualificationFor("nginx", false, false) != QualificationDiscovered {
		t.Fatal("a family without code is not discovered")
	}
	if QualificationFor("nginx", true, false) != QualificationImplemented {
		t.Fatal("a shipped family nothing executes is not implemented")
	}
	if QualificationFor("nginx", true, true) != QualificationServed {
		t.Fatal("an executed family is not served")
	}
	for family, proof := range locallyProvenFamilies {
		if proof == "" {
			t.Fatalf("%s is listed locally proven without the test that proves it", family)
		}
	}
	for _, row := range supportMatrix {
		if row.HardwareTested && QualificationFor(row.Family, true, true) != QualificationVendorQualified {
			t.Fatalf("%s ran on hardware but is not vendor-qualified", row.Family)
		}
		if !row.HardwareTested && QualificationFor(row.Family, true, true) == QualificationVendorQualified {
			t.Fatalf("%s is vendor-qualified without a hardware run", row.Family)
		}
	}
}
