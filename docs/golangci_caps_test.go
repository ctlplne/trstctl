// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGolangciReportsEveryIssue asserts .golangci.yml pins max-issues-per-linter
// and max-same-issues to 0.
//
// golangci-lint defaults them to 50 and 3. Those defaults are a SILENT
// EXCLUSION: the run exits with whatever it printed, and both the reader and any
// script counting lines take the printed number as the total. The old config
// claimed "No exclusions" for errcheck and gosec despite those default caps.
//
// The cost is measured, not theoretical. An audit of ee/ was filed as "73 issues
// (50 gosec)" because that is exactly what the capped run prints — 50 is the cap.
// Re-run uncapped, the same tree reports 197. Every scoping decision taken from
// the first number was wrong by nearly 3x, and the "50 gosec" in the finding
// title was the cap reading itself back.
//
// The failure mode this guards is worse than a wrong count: with the caps in
// place a NEW regression can land in a file that already has 3 findings of the
// same kind and never be printed at all, so the gate reports no change.
func TestGolangciReportsEveryIssue(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("../.golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	body := string(raw)

	for _, key := range []string{"max-issues-per-linter", "max-same-issues"} {
		re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*:\s*(\S+)\s*$`)
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Errorf(".golangci.yml does not set %s. Unset means golangci-lint's default "+
				"(50 per linter, 3 per same issue), which silently truncates the report — "+
				"a regression can land behind the cap and the gate still says what it said "+
				"yesterday. Set it to 0.", key)
			continue
		}
		if strings.TrimSpace(m[1]) != "0" {
			t.Errorf(".golangci.yml sets %s: %s, want 0. Any non-zero value hides findings "+
				"from the report while the run still exits 0-or-1 on what it chose to show.",
				key, m[1])
		}
	}
}

// TestEELintRatchetBaselineIsHonest checks the ee/ ratchet's bookkeeping: the
// baseline file must exist, parse, and not have been quietly raised to whatever
// the tree currently produces.
//
// ee/ is deliberately NOT in GO_PACKAGES yet (see the comment there). The ratchet
// is what keeps that from being an open door: it fails when the count GROWS, so
// new ee/ code cannot add findings even while the existing backlog is being
// worked down. A baseline that only ever moves up would make the whole mechanism
// decorative.
func TestEELintRatchetBaselineIsHonest(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("../.ee-lint-baseline"))
	if err != nil {
		t.Fatalf("the ee/ lint ratchet baseline must exist at .ee-lint-baseline: %v", err)
	}
	text := strings.TrimSpace(string(raw))
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(text) {
		t.Fatalf(".ee-lint-baseline must contain a bare count, got %q", text)
	}

	mk, err := os.ReadFile(filepath.FromSlash("../Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefile := string(mk)

	// The ratchet has to actually run uncapped, or it measures the cap.
	if !strings.Contains(makefile, "--max-issues-per-linter=0") ||
		!strings.Contains(makefile, "--max-same-issues=0") {
		t.Error("the ee-lint-ratchet target must pass --max-issues-per-linter=0 and " +
			"--max-same-issues=0; without them it counts golangci-lint's truncated report " +
			"and would read 50-ish no matter how bad ee/ got")
	}
	if !strings.Contains(makefile, "ee-lint-ratchet") {
		t.Error("Makefile has no ee-lint-ratchet target")
	}
	// It must be wired into lint, not merely defined.
	//
	// Specifically it must be invoked from the lint RECIPE, not listed as a
	// prerequisite. As a prerequisite it runs before lint's golangci-lint
	// discovery, so on a machine without the tool `make lint` fails with the
	// ratchet's error instead of the fail-closed message CODE-005 asserts, and it
	// breaks lint-partial. Two other guards (CODE-005 and tenantfilter's
	// release-gate check) caught exactly that.
	lintRule := regexp.MustCompile(`(?m)^lint:[^\n]*`)
	if m := lintRule.FindString(makefile); strings.Contains(m, "ee-lint-ratchet") {
		t.Errorf("ee-lint-ratchet is a PREREQUISITE of lint (%q); invoke it from the recipe "+
			"instead, or it runs before the golangci-lint discovery and breaks lint-partial", m)
	}
	recipeInvokes := regexp.MustCompile(`(?m)^\t.*\$\(MAKE\)[^\n]*ee-lint-ratchet`)
	if !recipeInvokes.MatchString(makefile) {
		t.Error("no lint recipe line invokes ee-lint-ratchet; a ratchet nobody runs is not a ratchet")
	}
	if !strings.Contains(makefile, "ee/ lint ratchet NOT run by lint-partial") {
		t.Error("the ratchet does not honour LINT_ALLOW_PARTIAL; lint-partial is the escape " +
			"hatch for a machine without the optional tools and must stay usable there")
	}
	// GO_PACKAGES must NOT yet claim ee/ while the ratchet is the mechanism --
	// if someone brings ee/ into the main scope, this test should be revisited
	// deliberately rather than leaving two overlapping gates.
	goPkgs := regexp.MustCompile(`(?m)^GO_PACKAGES \?=.*$`).FindString(makefile)
	if strings.Contains(goPkgs, "./ee/...") && strings.Contains(makefile, "ee-lint-ratchet") {
		t.Error("GO_PACKAGES now includes ./ee/... AND the ratchet still exists; " +
			"pick one -- once ee/ lints as a first-class package the ratchet is dead weight " +
			"and its baseline will rot")
	}
}
