// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom/coverage"
)

// TestRenderIsDeterministic: the page must regenerate byte-identical, or the
// -check gate is noise that trains people to ignore it.
func TestRenderIsDeterministic(t *testing.T) {
	first := render()
	second := render()
	if first != second {
		t.Fatal("render() is not deterministic; the -check gate would flap")
	}
	// Map iteration is the realistic source of instability here, and two
	// passes in one process can agree by luck. Re-render enough times that a
	// genuinely unordered range would have to be lucky every time.
	for i := 0; i < 20; i++ {
		if render() != first {
			t.Fatalf("render() diverged on pass %d; an unordered range is leaking into the page", i+3)
		}
	}
}

// TestCommittedPageIsCurrent is the freshness guard in test form, so a stale
// page fails `make test` and not only the CI step.
func TestCommittedPageIsCurrent(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", outPathDefault))
	if err != nil {
		t.Fatalf("read committed page: %v — run 'go run ./tools/cbomcoveragedoc'", err)
	}
	if string(committed) != render() {
		t.Fatalf("%s is stale — run 'go run ./tools/cbomcoveragedoc' and commit the result", outPathDefault)
	}
}

// TestPageCoversTheWholeModel is the anti-vacuity guard: the generated page
// must name every served source kind, every asset class an envelope declares,
// and every structurally-unobservable class. A generator that silently stopped
// emitting a table would otherwise still produce a plausible-looking page that
// -check happily accepts, because -check only compares the page to the
// generator, never the generator to the model.
func TestPageCoversTheWholeModel(t *testing.T) {
	page := render()

	envs := coverage.Envelopes()
	if len(envs) < 10 {
		t.Fatalf("envelope registry has only %d kinds; this guard is not meaningful", len(envs))
	}
	for kind, e := range envs {
		if !strings.Contains(page, "`"+kind+"`") {
			t.Errorf("source kind %q is in the envelope registry but absent from the generated page", kind)
		}
		for _, c := range e.Observes {
			if !strings.Contains(page, "`"+string(c)+"`") {
				t.Errorf("asset class %q is declared by kind %q but absent from the generated page", c, kind)
			}
		}
		for _, p := range e.Preconditions {
			if !strings.Contains(page, string(p)) {
				t.Errorf("precondition %q is declared by kind %q but absent from the generated page", p, kind)
			}
		}
	}

	unobs := coverage.StructurallyUnobservable()
	if len(unobs) == 0 {
		t.Fatal("no structurally-unobservable classes; this guard is not meaningful")
	}
	for _, u := range unobs {
		if !strings.Contains(page, "`"+string(u.Class)+"`") {
			t.Errorf("unobservable class %q is enumerated in code but absent from the generated page", u.Class)
		}
		if !strings.Contains(page, u.Reason) {
			t.Errorf("unobservable class %q's stated reason is absent from the generated page; a class without its reason is the prose-comment problem this model replaced", u.Class)
		}
	}

	for _, bucket := range []coverage.Status{
		coverage.StatusObserved, coverage.StatusUnobserved, coverage.StatusStructural,
	} {
		if !strings.Contains(page, string(bucket)) {
			t.Errorf("bucket %q is absent from the generated page", bucket)
		}
	}
}

// TestWorkedExampleExercisesEveryUnobservedReason: the fixture must actually
// demonstrate all four UNOBSERVED causes. A fixture that drifted into only
// "no source configured" would make the page's worked example misleading
// about what the classifier distinguishes.
func TestWorkedExampleExercisesEveryUnobservedReason(t *testing.T) {
	page := render()
	for _, want := range []string{
		"no configured source observes this class",
		"is configured but has never completed a run",
		"older than the",
		`not "succeeded"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the worked example no longer demonstrates the %q reason branch", want)
		}
	}
	// And the good case, or the example only shows failure.
	if !strings.Contains(page, "observed by ") {
		t.Error("the worked example no longer demonstrates an OBSERVED class with attribution")
	}
}
