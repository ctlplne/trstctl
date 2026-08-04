// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// The published page must equal what the census says (epic E3).
//
// A Makefile target alone would not be enough. The failure this guards against
// is a capability being removed while its published row survives — and the
// person removing it runs the test suite, not necessarily the docs target. This
// puts the check where the change happens.

func TestThePublishedMatrixMatchesTheCensus(t *testing.T) {
	t.Parallel()
	committed, err := os.ReadFile(filepath.Join("..", "..", outputPath))
	if err != nil {
		t.Fatalf("read the committed support matrix: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(committed), bytes.TrimSpace(render())) {
		t.Fatal("docs/features/connector-support-matrix.md no longer matches the connector " +
			"census. Run `go run ./tools/connectorsupportdoc` and commit the result. If the page " +
			"changed because a capability was removed, that is the point: the published matrix " +
			"must lose the row at the same moment the code loses the capability")
	}
}

// The generated page must not acquire a firmware version range.
//
// This is the specific thing the surface exists to avoid, and it is the thing
// somebody will eventually add in good faith because a customer asked. A version
// range is a claim about hardware nothing here runs; the moment one appears, the
// page stops being evidence and becomes a promise.
func TestTheGeneratedPageMakesNoFirmwareClaim(t *testing.T) {
	t.Parallel()
	page := strings.ToLower(string(render()))
	for _, phrase := range []string{
		"firmware version", "supported versions", "compatible with version",
		"tested against version", "certified for",
	} {
		if strings.Contains(page, phrase) {
			t.Errorf("the generated page contains %q. Nothing in this repository runs against a "+
				"physical or vendor-hosted device, so a version claim would be unbacked — and it "+
				"is exactly the claim an operator would plan a migration around", phrase)
		}
	}
}

// Every family in the census reaches the page.
//
// A row that exists in code and not in the published page is a capability an
// operator cannot discover, which is a milder failure than the reverse but still
// makes the page an unreliable place to look.
func TestEveryCensusFamilyAppearsOnThePage(t *testing.T) {
	t.Parallel()
	page := string(render())
	for _, row := range connector.SupportMatrix() {
		if !strings.Contains(page, "## "+row.Family) {
			t.Errorf("family %q is in the census but has no section on the published page", row.Family)
		}
		for _, limit := range row.KnownLimits {
			if !strings.Contains(page, limit) {
				t.Errorf("%s's limit %q is recorded in the census but not published; the limits "+
					"are the half of this surface an operator most needs", row.Family, limit)
			}
		}
	}
}
