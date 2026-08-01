// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The doctor runbook is the operator-facing statement of what each probe does
// and does not prove. A probe added to the command without a line on that page
// is an undocumented assertion in a receipt a customer's auditor keeps, so
// these guards fail the build instead of letting the page drift — the same
// discipline the architecture invariants get.

var (
	probeIDRe = regexp.MustCompile(`ID: *"([A-Z]+-[A-Z0-9]+)"`)
	flagRe    = regexp.MustCompile(`fs\.(?:Bool|String)Var\(&opts\.\w+, "([a-z-]+)"`)
)

func doctorSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, f := range []string{
		"../internal/cli/doctor/doctor.go",
		"../internal/cli/doctor/probes_isolation.go",
		"../internal/cli/doctor/probes_ops.go",
	} {
		blob, err := os.ReadFile(f) // #nosec G304 -- fixed literal list of the repo's own committed doctor sources; no external input reaches this path (CWE-22)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b.Write(blob)
	}
	return b.String()
}

// TestDoctorDocCoversEveryProbe: every probe id the command can emit is named
// on the runbook page. Delete a row from the page, or add a probe without one,
// and this fails.
func TestDoctorDocCoversEveryProbe(t *testing.T) {
	page := read(t, "operations/doctor.md")
	src := doctorSources(t)

	seen := map[string]bool{}
	for _, m := range probeIDRe.FindAllStringSubmatch(src, -1) {
		seen[m[1]] = true
	}
	// Vacuity floor: the command ships five probe groups. If the extraction
	// suddenly finds almost nothing, the assertions below mean nothing.
	if len(seen) < 15 {
		ids := make([]string, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Fatalf("found only %d probe ids in the doctor sources (%v); the extraction is broken, not the docs", len(seen), ids)
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !strings.Contains(page, id) {
			t.Errorf("probe %q is emitted by trstctl doctor but never named in docs/operations/doctor.md; every probe in a signed receipt needs a stated meaning and a stated limit", id)
		}
	}
}

// TestDoctorDocCoversEveryFlag: every flag the command parses is documented,
// so an operator reading the page sees the whole surface.
func TestDoctorDocCoversEveryFlag(t *testing.T) {
	page := read(t, "operations/doctor.md")
	src := doctorSources(t)

	flags := flagRe.FindAllStringSubmatch(src, -1)
	if len(flags) < 5 {
		t.Fatalf("found only %d doctor flags; the extraction is broken", len(flags))
	}
	for _, m := range flags {
		if !strings.Contains(page, "--"+m[1]) {
			t.Errorf("flag --%s is parsed by trstctl doctor but not documented in docs/operations/doctor.md", m[1])
		}
	}
}

// TestDoctorDocStatesTheRealContract pins the facts an operator acts on: the
// exit-code contract, the reserved probe-tenant prefix, and the receipt schema.
// If the code changes any of them, the page must change in the same commit.
func TestDoctorDocStatesTheRealContract(t *testing.T) {
	page := read(t, "operations/doctor.md")
	src := doctorSources(t)

	for _, want := range []string{
		`"trstctl.doctor.v1"`, // receipt schema
		`"00000000-d0c7"`,     // reserved probe-tenant prefix
	} {
		lit := strings.Trim(want, `"`)
		if !strings.Contains(src, want) {
			t.Fatalf("doctor sources no longer contain %s; this guard is pinned to a stale fact", want)
		}
		if !strings.Contains(page, lit) {
			t.Errorf("docs/operations/doctor.md does not state %s, which the command emits", lit)
		}
	}

	// The exit-code contract is the thing a customer gates their own CI on.
	for _, want := range []string{"ExitError{1}", "ExitError{2}"} {
		if !strings.Contains(src, want) {
			t.Fatalf("doctor no longer returns %s; the documented exit contract is stale", want)
		}
	}
	for _, want := range []string{
		"**0** every probe passed",
		"**1** at least one probe FAILED",
		"**2** a configuration or connectivity error",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/operations/doctor.md does not state the exit code line %q", want)
		}
	}

	// A skipped proof must never read as a passed one — the page has to say so.
	if !strings.Contains(page, "A skipped proof never\nlooks like a passed proof") &&
		!strings.Contains(page, "A skipped proof never looks like a passed proof") {
		t.Error("docs/operations/doctor.md must state that a skipped proof is not a passed proof")
	}
}
