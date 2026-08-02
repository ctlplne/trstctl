// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// ---- ARCH-012: the reader-facing invariant pages count the same nine -----------
//
// README.md carries the canonical `| **AN-n** |` non-negotiables table. The two
// reader-facing pages that restate the same rules had both drifted to eight:
//
//   - docs/design/architecture-invariants.md headed its table "The eight
//     invariants" and used ZERO AN-n identifiers, so AN-9 (the `ee/` editions
//     boundary) was silently absent and the page could not be cited as the
//     destination for any AN-n claim; and
//   - docs/glossary.md described "trstctl's eight architectural rules" under a
//     heading literally titled "Non-negotiables (AN-1 … AN-9)", enumerating only
//     AN-1..AN-8.
//
// ARCH-010 (docs/linter_scope_claims_test.go) already binds README.md,
// .github/CODEOWNERS and MAINTAINERS.md to the analyzer registry, but it does not
// look at the docs/ pages at all — which is how this drift survived. ELI5: if the
// documentation cannot agree on how many load-bearing walls the building has, a
// reader has no way to notice which wall is missing.
//
// This guard derives the count and the ID set from the README table instead of
// hard-coding nine, so adding AN-10 turns it red until every page is updated.

// invariantCountWords maps an invariant-table size to the spelled-out count the
// prose is required to use. Every entry other than the real size is also treated
// as a STALE claim, so a page cannot merely add the right number alongside the
// wrong one.
var invariantCountWords = map[int]string{
	6:  "six",
	7:  "seven",
	8:  "eight",
	9:  "nine",
	10: "ten",
	11: "eleven",
	12: "twelve",
}

// invariantSummaryPages are the reader-facing docs pages that restate the README
// table, each with the noun that follows the spelled-out count on that page.
var invariantSummaryPages = []struct {
	path string
	noun string
}{
	{"design/architecture-invariants.md", " invariants"},
	{"glossary.md", " architectural rules"},
}

// TestInvariantPagesAgreeWithReadmeOnTheCount locks ARCH-012.
func TestInvariantPagesAgreeWithReadmeOnTheCount(t *testing.T) {
	rows := linterANRowRe.FindAllStringSubmatch(read(t, "../README.md"), -1)
	if len(rows) < 2 {
		t.Fatal("ARCH-012: README.md no longer has a `| **AN-n** |` non-negotiables table; the canonical list moved — re-point this guard")
	}
	seen := map[string]bool{}
	var ans []string
	for _, m := range rows {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		ans = append(ans, m[1])
	}
	linterSortANs(ans)

	word, ok := invariantCountWords[len(ans)]
	if !ok {
		t.Fatalf("ARCH-012: README.md now defines %d non-negotiables (%v); add that size to invariantCountWords and update the summary pages in the same change", len(ans), ans)
	}

	for _, page := range invariantSummaryPages {
		body := read(t, page.path)

		if want := word + page.noun; !strings.Contains(body, want) {
			t.Errorf("ARCH-012: docs/%s must state %q — README.md's table defines %d non-negotiables (%v)", page.path, want, len(ans), ans)
		}
		for size, stale := range invariantCountWords {
			if size == len(ans) {
				continue
			}
			if bad := stale + page.noun; strings.Contains(body, bad) {
				t.Errorf("ARCH-012: docs/%s still says %q, but README.md defines %d non-negotiables (%v)", page.path, bad, len(ans), ans)
			}
		}
		for _, an := range ans {
			if !strings.Contains(body, an) {
				t.Errorf("ARCH-012: docs/%s never names %s, so a reader cannot map the page onto README.md's AN-n table — the page must carry the identifiers, not only the prose names", page.path, an)
			}
		}
	}
}
