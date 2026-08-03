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
		{"not accepting contributions", "the project is closed to outside contributions and the template is where somebody about to open a pull request finds that out"},
		{"CONTRIBUTING.md", "the template must point at the page carrying the reasoning and what IS welcome"},
		{"ee/", "the core-vs-ee/ split is part of why the project is closed, so the template must name the tree"},
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
	if len(boxes) < 4 {
		t.Errorf("pull-request template has %d checklist items, want at least the 4 that map to real gates "+
			"(tests first, make lint test, docs+CHANGELOG, one scoped change)", len(boxes))
	}
	for _, box := range boxes {
		if box[1] != " " {
			t.Errorf("pull-request template ships a pre-ticked checklist box (%q); every box must start empty", box[0])
		}
	}

	// Anti-drift, both directions. The project is closed to contributions, and
	// the two files that a would-be contributor reads must agree about that.
	//
	// The check is on whether a workflow is OPERATED, not on whether the words
	// appear: CONTRIBUTING.md legitimately explains that there is no CLA, and a
	// naive substring match on "contributor license agreement" would read that
	// sentence as evidence the project runs one.
	lower := strings.ToLower(tpl)
	contributing := strings.ToLower(read(t, "../CONTRIBUTING.md"))
	closed := strings.Contains(contributing, "not accepting contributions")
	if !closed {
		t.Fatal("CONTRIBUTING.md no longer states that the project is closed to contributions; " +
			"if that changed deliberately, this guard and the pull-request template both need " +
			"rewriting to describe whatever replaced it")
	}
	for _, w := range []struct{ workflow, tplPhrase string }{
		{"DCO", "git commit -s"},
		{"CLA", "signed cla"},
	} {
		if strings.Contains(lower, strings.ToLower(w.tplPhrase)) {
			t.Errorf("the pull-request template still asks for %s, but the project is not accepting "+
				"contributions; asking an outside author for paperwork on a change nobody will read "+
				"is worse than saying no", w.workflow)
		}
	}
	if !strings.Contains(lower, "closed unread") {
		t.Error("the pull-request template does not say outside pull requests are closed unread; " +
			"somebody deserves to learn that before they write the patch, not after")
	}
}
