// SPDX-License-Identifier: MPL-2.0

package docs

// Pull-request template guard (AH-84e66676). GitHub renders
// .github/pull_request_template.md straight into the compose box, so it is the one
// page nothing else in the repository can correct: whatever it asks for is what the
// author tries to supply. It asked them to "link the issue or sprint card", and a
// sprint card is a planning artefact that exists only in the maintainer's ignored
// docs-internal/ tree — a reader who has just cloned the repository would go looking
// for a board that is not there. AGENTS.md already states the rule this broke: no
// sprint/REPORT/DoD process identifiers on reader pages unless a test requires them.
// This is that test, for the one reader page a reader cannot navigate away from.
//
// Two things are locked here. First, the template stays addressed to someone who has
// only the repository and the issue tracker: no private-process vocabulary. Second,
// every checklist item keeps mapping to something that actually gates the merge —
// DCO sign-off, the ee/ CLA, a test written first, `make lint test`, the CHANGELOG
// entry — because a box with no gate behind it trains authors to tick without
// reading, which is how the boxes that do matter stop being read too.
// TestLicenseStatusIsConsistent in docs_test.go already tells readers that this
// template requires DCO for core and a CLA for ee/; until this guard existed,
// nothing checked that it did.
//
// Helper `read` is defined in docs/docs_test.go and reused here.

import (
	"regexp"
	"strings"
	"testing"
)

// prTemplatePath is the compose-box page this guard reads, relative to docs/.
const prTemplatePath = "../.github/pull_request_template.md"

// prTemplatePrivateVocabulary are terms whose referent lives only in the
// maintainer's private working copy or in this project's internal process notes.
// A pull-request author outside that working copy cannot satisfy a request that
// names one, so asking is worse than not asking: it reads as a missing prerequisite.
var prTemplatePrivateVocabulary = []struct {
	pattern *regexp.Regexp
	why     string
}{
	{
		regexp.MustCompile(`(?i)\bsprints?\b`),
		"there is no public sprint board — sprint planning lives in the docs-internal/ tree .gitignore excludes",
	},
	{
		regexp.MustCompile(`(?i)\bacceptance criteria\b`),
		"nothing an author can read enumerates acceptance criteria; they came off the private card",
	},
	{
		regexp.MustCompile(`\bDoD\b`),
		"a definition-of-done identifier is internal process vocabulary (AGENTS.md)",
	},
	{
		regexp.MustCompile(`\bREPORT-\d`),
		"REPORT identifiers name internal working documents that are not published",
	},
}

// TestPullRequestTemplateSpeaksToOutsideReaders locks .github/pull_request_template.md
// as a page a first-time contributor can act on end to end: it asks only for things
// they can produce (a description, a link to the issue, the command that verifies the
// change), and its checklist names only gates that really run.
func TestPullRequestTemplateSpeaksToOutsideReaders(t *testing.T) {
	t.Parallel()

	tpl := read(t, prTemplatePath)

	for _, banned := range prTemplatePrivateVocabulary {
		if hit := banned.pattern.FindString(tpl); hit != "" {
			t.Errorf("the pull-request template asks the author about %q, which they cannot have: %s", hit, banned.why)
		}
	}

	// What a reviewer actually needs, and what the merge actually requires.
	for _, want := range []struct{ needle, why string }{
		{"## What this changes", "a reviewer reads the summary before the diff"},
		{"## How to verify", "a reviewer needs the command that demonstrates the change, not a claim that it works"},
		{"## Checklist", "the merge requirements belong on the page where they are met"},
		{"git commit -s", "the DCO sign-off is a real gate on every core commit (CONTRIBUTING.md)"},
		{"CLA", "an ee/ contribution needs a signed CLA; this template is where the author first learns that"},
		{"ee/", "the core-vs-ee/ split decides which paperwork applies, so the template must name the tree"},
		{"make lint test", "the lint and test gate, including the architecture linter, is what CI runs"},
		{"CHANGELOG", "a release note that is not written with the change is not written at all"},
		{"[Unreleased]", "the CHANGELOG section a contributor is expected to edit"},
	} {
		if !strings.Contains(tpl, want.needle) {
			t.Errorf("pull-request template no longer contains %q: %s", want.needle, want.why)
		}
	}

	// The replacement for the sprint card: the one link an outside author can supply.
	if !regexp.MustCompile(`(?i)link the issue`).MatchString(tpl) {
		t.Error("pull-request template no longer asks the author to link the issue; " +
			"that link is the only pointer to prior context a reader outside this working copy can provide")
	}

	// Checklist items must ship unticked. A pre-ticked box is an assertion the
	// author never made, and a reviewer who spots one stops trusting the rest.
	boxes := regexp.MustCompile(`(?m)^- \[(.)\] `).FindAllStringSubmatch(tpl, -1)
	if len(boxes) < 6 {
		t.Errorf("pull-request template has %d checklist items, want at least the 6 that map to gates "+
			"(DCO, ee/ CLA, tests first, make lint test, docs+CHANGELOG, one scoped change)", len(boxes))
	}
	for _, box := range boxes {
		if box[1] != " " {
			t.Errorf("pull-request template ships a pre-ticked checklist box (%q); every box must start empty", box[0])
		}
	}

	// Anti-drift, both directions: the template is where CONTRIBUTING.md's two
	// contribution workflows are enforced, so retiring one in either file without
	// the other leaves an author following an instruction nobody honours.
	lower := strings.ToLower(tpl)
	contributing := strings.ToLower(read(t, "../CONTRIBUTING.md"))
	for _, w := range []struct{ workflow, tplPhrase, contribPhrase string }{
		{"DCO", "dco", "developer certificate of origin"},
		{"CLA", "cla", "contributor license agreement"},
	} {
		switch {
		case strings.Contains(contributing, w.contribPhrase) && !strings.Contains(lower, w.tplPhrase):
			t.Errorf("CONTRIBUTING.md operates the %s workflow (%q) but the pull-request template never mentions it; "+
				"the checklist is where that requirement is actually enforced", w.workflow, w.contribPhrase)
		case !strings.Contains(contributing, w.contribPhrase) && strings.Contains(lower, w.tplPhrase):
			t.Errorf("the pull-request template requires %s but CONTRIBUTING.md no longer operates it; "+
				"retire it in both files or in neither", w.workflow)
		}
	}
}
