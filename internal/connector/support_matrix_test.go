// SPDX-License-Identifier: MPL-2.0

package connector_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// The support matrix is served to operators, so it is a claim (epic E3).
//
// A published compatibility surface is the single most tempting place in a
// product to write something aspirational, because nobody reads it during
// development and everybody reads it during procurement. These tests exist to
// make the optimistic direction the one that fails.

func TestEveryDeviceProvenFamilyHasASupportRow(t *testing.T) {
	t.Parallel()
	for _, family := range connector.DeviceProvenConnectors() {
		if _, ok := connector.SupportRowFor(family); !ok {
			t.Errorf("%s is device-proven but has no support row; the catalog would report a "+
				"family as verified with nothing said about what that verification covers", family)
		}
	}
}

func TestEverySupportRowNamesAFamilyThatExists(t *testing.T) {
	t.Parallel()
	for _, row := range connector.SupportMatrix() {
		if !connector.DeviceProven(row.Family) {
			t.Errorf("the support matrix describes %q as exercised, but that family has no device "+
				"proof; the row would be describing tests that do not run", row.Family)
		}
	}
}

// Every row must say what it proves and what it does not.
//
// A row with no proven operations is a family we have said nothing useful about.
// A row with no known limits is almost always a row nobody finished — every one
// of these APIs has something it cannot do, and an empty list reads as "no
// limitations", which is the strongest claim on the page and the least likely to
// be true.
func TestEverySupportRowStatesBothWhatItProvesAndWhatItCannot(t *testing.T) {
	t.Parallel()
	for _, row := range connector.SupportMatrix() {
		row := row
		t.Run(row.Family, func(t *testing.T) {
			t.Parallel()
			if strings.TrimSpace(row.APIContract) == "" {
				t.Error("no API contract named, so an operator cannot match this against their " +
					"device's documentation")
			}
			if len(row.ProvenOperations) == 0 {
				t.Error("no proven operations listed; the row claims support without saying of what")
			}
			if len(row.KnownLimits) == 0 {
				t.Error("no known limits listed, which reads as 'none' — the strongest claim on " +
					"the page. Every one of these APIs has something it cannot do; if this family " +
					"genuinely has none worth stating, that itself needs saying explicitly")
			}
		})
	}
}

// A family the rollback census refuses must say so in its limits.
//
// The two surfaces are read by different people at different times — the census
// by the code during an incident, the matrix by a human during planning — and an
// operator who plans around a rollback the product will refuse has been misled
// by the surface that was supposed to prevent exactly that.
func TestAFamilyWithoutRollbackSaysSoInItsLimits(t *testing.T) {
	t.Parallel()
	for _, row := range connector.SupportMatrix() {
		if connector.CanRollback(row.Family) {
			continue
		}
		said := false
		for _, limit := range row.KnownLimits {
			if strings.Contains(strings.ToLower(limit), "no rollback") {
				said = true
			}
		}
		if !said {
			t.Errorf("%s cannot roll back and its support row does not say so; an operator "+
				"planning a rotation would discover it from a refusal instead of from the "+
				"published matrix", row.Family)
		}
	}
}

// No family may claim hardware testing this repository does not do.
//
// The field exists so the absence is stated rather than inferred. If it ever
// flips to true, this test is where somebody has to justify it — and the
// justification is a CI job against a real device, not a conversation.
func TestNoFamilyClaimsHardwareTestingWithoutIt(t *testing.T) {
	t.Parallel()
	for _, row := range connector.SupportMatrix() {
		if row.HardwareTested {
			t.Errorf("%s claims hardware testing. Nothing in this repository runs against a "+
				"physical or vendor-hosted device; if that has changed, the CI job proving it "+
				"must land in the same change that flips this field", row.Family)
		}
	}
}
