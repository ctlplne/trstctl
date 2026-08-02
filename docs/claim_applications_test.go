// SPDX-License-Identifier: MPL-2.0

package docs

// LEGAL-002 (audit finding AH-66d5d899): the "Applications" table in
// ee/docs/claim-traceability.md must be able to hold real filing data.
//
// The page is generated: scripts/ci/extract-claim-traceability.py writes it and
// `make claim-traceability-check` byte-compares the committed copy, so a hand
// edit is reverted by the next regeneration. The generator used to emit the
// Applications rows as a constant f-string of _[FILL]_ cells with no data source
// behind them, which meant no filing date, no application serial and no
// conversion deadline could be recorded anywhere — not in the page (generated)
// and not in the generator (no input to read). certctl LLC filed four US
// provisional applications in July 2026 and a US provisional must be converted
// within twelve months of filing, so the deadline is the single most
// time-critical fact this artifact carries, and it was the one fact the artifact
// structurally could not hold.
//
// The data now lives in ee/docs/claim-verification.json — the human-maintained
// sidecar the page already pointed readers at, and which did not exist until
// this change. These guards keep it load-bearing:
//
//   - TestClaimApplicationsTableIsDataDriven writes fixture values into a copy of
//     the sidecar and proves they reach the rendered table, so the row cannot
//     drift back to a constant.
//   - TestClaimGeneratorRefusesUndeclaredFamily proves the generator fails loudly,
//     rather than rendering a placeholder, when a family cited in ee/ source has
//     no application entry.
//   - TestClaimVerificationSidecarCarriesEveryFiling proves the checked-in sidecar
//     declares all four filed families with a filing date, and that the published
//     page shows the computed conversion deadline for each.
//
// Helper `read` is defined in docs/docs_test.go (same package).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// claimVerificationSidecar is the repository-relative path of the one
// human-maintained input to the traceability page.
const claimVerificationSidecar = "ee/docs/claim-verification.json"

// claimTraceabilityPage is the generated artifact those values are rendered into.
const claimTraceabilityPage = "ee/docs/claim-traceability.md"

// claimTraceabilityGenerator writes the page from ee/ citations plus the sidecar.
const claimTraceabilityGenerator = "scripts/ci/extract-claim-traceability.py"

// filedFamilies are the four families certctl LLC has provisional applications on
// file for (see docs/patent_marking_test.go). Each needs a row carrying its filing
// date and conversion deadline — including XREC, which no ee/ Go file cites a
// claim number for yet and which therefore has no per-family section on the page.
var filedFamilies = []string{"AGID", "PCAS", "VDEC", "XREC"}

// runClaimTraceability runs the repository's own committed generator from the
// repository root and returns its combined output.
func runClaimTraceability(t *testing.T, args ...string) (string, error) {
	t.Helper()
	argv := append([]string{claimTraceabilityGenerator}, args...)
	cmd := exec.Command("python3", argv...) // #nosec G204 -- test runs the repository's own committed generator against tempdir fixtures it just wrote itself (CWE-78)
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// objectAt returns doc[key] as a JSON object, failing the test rather than
// panicking when the sidecar's shape is not what this guard assumes.
func objectAt(t *testing.T, doc map[string]any, key string) map[string]any {
	t.Helper()
	obj, ok := doc[key].(map[string]any)
	if !ok {
		t.Fatalf("LEGAL-002: %s has no %q object; the Applications table has no data source", claimVerificationSidecar, key)
	}
	return obj
}

// sidecarFixture copies the checked-in sidecar into a temp file, applies mutate,
// and returns the path. Starting from the real file keeps the fixture
// structurally honest instead of asserting against a shape nothing ships.
func sidecarFixture(t *testing.T, mutate func(applications map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, filepath.FromSlash("../"+claimVerificationSidecar))), &doc); err != nil {
		t.Fatalf("LEGAL-002: %s is not valid JSON: %v", claimVerificationSidecar, err)
	}
	mutate(objectAt(t, doc, "applications"))
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("LEGAL-002: re-encode sidecar fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "claim-verification.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("LEGAL-002: write sidecar fixture: %v", err)
	}
	return path
}

// TestClaimApplicationsTableIsDataDriven is the load-bearing half of LEGAL-002:
// a value written into the sidecar must appear in the rendered table. A generator
// that hard-codes the row again cannot pass this.
func TestClaimApplicationsTableIsDataDriven(t *testing.T) {
	const (
		subject = "fixture subject for LEGAL-002"
		serial  = "63/000000-LEGAL-002-FIXTURE"
		filed   = "2026-07-14"
		expires = "2027-07-14" // filed + twelve months, computed by the generator
	)
	sidecar := sidecarFixture(t, func(applications map[string]any) {
		pcas := objectAt(t, applications, "PCAS")
		pcas["subject"] = subject
		pcas["application_no"] = serial
		pcas["filed"] = filed
		pcas["converted_by"] = "" // force the deadline to be computed, not copied
	})

	out := filepath.Join(t.TempDir(), "claim-traceability.md")
	log, err := runClaimTraceability(t, "--verification", sidecar, "--out", out)
	if err != nil {
		t.Fatalf("LEGAL-002: generator failed on a fixture sidecar: %v\n%s", err, log)
	}

	body := read(t, out)
	for _, want := range []string{subject, serial, filed, expires} {
		if !strings.Contains(body, want) {
			t.Errorf("LEGAL-002: %q was set in the sidecar but never reached the Applications table; the row is not data-driven, so no filing data can be recorded", want)
		}
	}
	if strings.Contains(body, "_[FILL") {
		t.Errorf("LEGAL-002: the rendered page still carries a hard-coded _[FILL]_ cell:\n%s", body[:min(len(body), 1200)])
	}
}

// TestClaimGeneratorRefusesUndeclaredFamily proves the failing direction: a
// family cited in ee/ source with no application entry must stop the generator,
// not render as a placeholder. Without this, a new family silently reintroduces
// the defect for itself.
func TestClaimGeneratorRefusesUndeclaredFamily(t *testing.T) {
	sidecar := sidecarFixture(t, func(applications map[string]any) {
		delete(applications, "PCAS")
	})

	out := filepath.Join(t.TempDir(), "claim-traceability.md")
	log, err := runClaimTraceability(t, "--verification", sidecar, "--out", out)
	if err == nil {
		t.Fatalf("LEGAL-002: generator accepted a sidecar with no application entry for the cited PCAS family:\n%s", log)
	}
	if !strings.Contains(log, "no application entry for cited") {
		t.Fatalf("LEGAL-002: expected a refusal naming the undeclared family, got:\n%s", log)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Errorf("LEGAL-002: the generator wrote %s despite refusing the sidecar; a partial page is worse than none", out)
	}
}

// TestClaimVerificationSidecarCarriesEveryFiling holds the committed data itself:
// every filed application has an entry with a filing date, and the published page
// shows the conversion deadline derived from it.
func TestClaimVerificationSidecarCarriesEveryFiling(t *testing.T) {
	var doc struct {
		Applications map[string]struct {
			Subject       string `json:"subject"`
			ApplicationNo string `json:"application_no"`
			Filed         string `json:"filed"`
			ConvertedBy   string `json:"converted_by"`
		} `json:"applications"`
	}
	if err := json.Unmarshal([]byte(read(t, filepath.FromSlash("../"+claimVerificationSidecar))), &doc); err != nil {
		t.Fatalf("LEGAL-002: %s is not valid JSON: %v", claimVerificationSidecar, err)
	}

	page := read(t, filepath.FromSlash("../"+claimTraceabilityPage))
	for _, fam := range filedFamilies {
		entry, ok := doc.Applications[fam]
		if !ok {
			t.Errorf("LEGAL-002: %s has no application entry for %s; certctl LLC has a provisional application on file for it and its conversion deadline has nowhere to live", claimVerificationSidecar, fam)
			continue
		}
		if entry.Filed == "" {
			t.Errorf("LEGAL-002: %s records no filing date for %s; the twelve-month conversion deadline is computed from it", claimVerificationSidecar, fam)
		}
		if !strings.Contains(page, "| "+fam+" | ") {
			t.Errorf("LEGAL-002: %s has no Applications row for %s; regenerate it with %s", claimTraceabilityPage, fam, claimTraceabilityGenerator)
		}
		if entry.ConvertedBy != "" || len(entry.Filed) < 4 {
			continue // an explicitly recorded deadline is counsel's, not derived
		}
		if strings.HasSuffix(entry.Filed, "-02-29") {
			continue // the generator clamps the leap-day anniversary; not restated here
		}
		year, err := strconv.Atoi(entry.Filed[:4])
		if err != nil {
			t.Errorf("LEGAL-002: %s records %s filed as %q, which is not YYYY-MM[-DD]", claimVerificationSidecar, fam, entry.Filed)
			continue
		}
		deadline := strconv.Itoa(year+1) + entry.Filed[4:]
		if !strings.Contains(page, deadline) {
			t.Errorf("LEGAL-002: %s shows no %s conversion deadline for %s (filed %s, due %s); the twelve-month clock is the fact this table exists to carry", claimTraceabilityPage, deadline, fam, entry.Filed, deadline)
		}
	}

	if strings.Contains(page, "_[FILL") {
		t.Errorf("LEGAL-002: %s still carries _[FILL]_ placeholders; filing data cannot be recorded through a generated page", claimTraceabilityPage)
	}
	if strings.Contains(read(t, filepath.FromSlash("../"+claimTraceabilityGenerator)), "_[FILL") {
		t.Errorf("LEGAL-002: %s hard-codes a _[FILL]_ row again; the Applications table must come from %s", claimTraceabilityGenerator, claimVerificationSidecar)
	}
}
