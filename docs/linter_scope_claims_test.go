// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---- ARCH-010: the linter's advertised scope equals its registered scope --------
//
// tools/trstctllint/docs_test.go (ARCH-005) already keeps the linter's OWN docs in
// sync with its multichecker list. Nothing kept the repo-level claims honest, and
// they drifted three different ways at once: README.md's "How it's built" intro
// said eight of the nine invariants are linter-enforced, README.md's repository
// layout said the linter "enforces AN-1..AN-8", .github/CODEOWNERS said it
// enforces "AN-1/AN-3/AN-5/AN-8", and MAINTAINERS.md correctly said three
// invariants have no analyzer at all. Only one of those can be true.
//
// This guard derives the truth from the binary — the multichecker registration
// list in tools/trstctllint/main.go — and requires every repo-level claim to name
// exactly that set, with the remaining invariants described as test-enforced. It
// is deliberately data-driven: registering a new AN-scoped analyzer (or dropping
// one) turns this red until the README and CODEOWNERS are updated with it.

// linterANByAnalyzer maps each registered analyzer that enforces a numbered
// architecture invariant to that invariant. licenseboundary is registered under
// its packaging ID (PACKAGING-007) but is the AN-9 editions boundary: it is what
// makes "core never imports ee/" a build failure rather than a convention, on top
// of the trstctl_core build fence.
var linterANByAnalyzer = map[string]string{
	"cryptoboundary":  "AN-3",
	"tenantfilter":    "AN-1",
	"keymaterial":     "AN-8",
	"idempotency":     "AN-5",
	"eventsource":     "AN-2",
	"licenseboundary": "AN-9",
}

// linterNonANAnalyzers are the registered analyzers that enforce non-AN rules, so
// they contribute nothing to the AN coverage set. Listing them explicitly (rather
// than ignoring unknown names) means a NEW analyzer must be classified here or in
// linterANByAnalyzer before this guard will pass — the docs cannot silently fall
// behind the binary.
var linterNonANAnalyzers = map[string]bool{
	"cryptoagility": true, // PQC-00
	"netexec":       true, // SEC-005
	"tlsverify":     true, // SEC-CWE-295
	"upsertarbiter": true, // OPP-C01 (DP2-043/DP2-046 upsert-arbiter race class)
}

var (
	// `	cryptoboundary.Analyzer,  // AN-3`
	linterRegisterRe = regexp.MustCompile(`(?m)^\s*([a-z][a-z0-9]*)\.Analyzer\s*,`)
	// `| **AN-1** | **Tenants can't see each other ...`
	linterANRowRe = regexp.MustCompile(`(?m)^\|\s*\*\*(AN-\d+)\*\*\s*\|`)
	linterANRefRe = regexp.MustCompile(`AN-\d+`)
	// a backticked path such as `cmd/trstctl-signer/core_boundary_test.go`
	linterTestPathRe = regexp.MustCompile("`([A-Za-z0-9_./-]+_test\\.go)`")
)

// linterANScope returns (analyzer-enforced invariants, test-enforced invariants).
// The first set comes from the multichecker registration list; the second is every
// other invariant in the README's own AN table.
func linterANScope(t *testing.T) (enforced, tested []string) {
	t.Helper()

	main := read(t, "../tools/trstctllint/main.go")
	registered := linterRegisterRe.FindAllStringSubmatch(main, -1)
	if len(registered) == 0 {
		t.Fatal("ARCH-010: found no `<pkg>.Analyzer,` registrations in tools/trstctllint/main.go; the registration shape changed — re-point this guard")
	}
	enforcedSet := map[string]bool{}
	for _, m := range registered {
		name := m[1]
		if an, ok := linterANByAnalyzer[name]; ok {
			enforcedSet[an] = true
			continue
		}
		if !linterNonANAnalyzers[name] {
			t.Errorf("ARCH-010: tools/trstctllint/main.go registers analyzer %q, which this guard does not classify; add it to linterANByAnalyzer (with the AN-* it enforces) or linterNonANAnalyzers, then update README.md and .github/CODEOWNERS to match", name)
		}
	}

	readme := read(t, "../README.md")
	rows := linterANRowRe.FindAllStringSubmatch(readme, -1)
	if len(rows) == 0 {
		t.Fatal("ARCH-010: README.md no longer has a `| **AN-n** |` invariant table; re-point this guard")
	}
	for _, m := range rows {
		an := m[1]
		if enforcedSet[an] {
			continue
		}
		tested = append(tested, an)
	}
	for an := range enforcedSet {
		enforced = append(enforced, an)
	}
	linterSortANs(enforced)
	linterSortANs(tested)

	if len(enforced) == 0 || len(tested) == 0 {
		t.Fatalf("ARCH-010: derived a degenerate split (analyzer-enforced=%v, test-enforced=%v); this guard would assert nothing", enforced, tested)
	}
	return enforced, tested
}

// linterSortANs orders AN IDs numerically (so AN-9 does not sort before AN-10).
func linterSortANs(ids []string) {
	num := func(s string) int {
		n, _ := strconv.Atoi(strings.TrimPrefix(s, "AN-"))
		return n
	}
	sort.Slice(ids, func(i, j int) bool { return num(ids[i]) < num(ids[j]) })
}

// linterJoinANs renders an AN set the way the prose must: "AN-1, AN-2 and AN-3".
func linterJoinANs(ids []string) string {
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return ids[0]
	}
	return strings.Join(ids[:len(ids)-1], ", ") + " and " + ids[len(ids)-1]
}

// linterANSetOnLine returns the AN IDs referenced on the last line of body that
// contains marker, so a claim line can be compared against the derived set.
func linterANSetOnLine(t *testing.T, artifact, body, marker string) (string, []string) {
	t.Helper()
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, marker) {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("ARCH-010: %s no longer has a line containing %q; the linter-scope claim moved — re-point this guard", artifact, marker)
	}
	ids := linterANRefRe.FindAllString(line, -1)
	seen := map[string]bool{}
	var uniq []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	linterSortANs(uniq)
	return line, uniq
}

// TestLinterEnforcementClaimsMatchAnalyzerRegistry locks ARCH-010. ELI5: the README
// tells a reader which architectural rules the compiler will stop them from
// breaking. If it names more rules than the linter actually has, a contributor
// trusts a wall that is not there.
func TestLinterEnforcementClaimsMatchAnalyzerRegistry(t *testing.T) {
	enforced, tested := linterANScope(t)
	enforcedList := linterJoinANs(enforced)
	testedList := linterJoinANs(tested)

	readme := read(t, "../README.md")

	// (1) The "How it's built" intro must split the invariants the way the binary
	// does: the analyzer-enforced set named as linter-enforced, and the remainder
	// named as having no analyzer.
	start := strings.Index(readme, "## How it's built")
	if start < 0 {
		t.Fatal("ARCH-010: README.md no longer has a `## How it's built` section; re-point this guard")
	}
	rest := readme[start:]
	end := strings.Index(rest, "\n|          | Principle (in plain terms)")
	if end < 0 {
		t.Fatal("ARCH-010: README.md `## How it's built` no longer precedes the invariant table; re-point this guard")
	}
	intro := rest[:end]
	// Collapse whitespace so a claim that wraps across lines still matches.
	flat := strings.Join(strings.Fields(intro), " ")

	if want := enforcedList + " are enforced by"; !strings.Contains(flat, want) {
		t.Errorf("ARCH-010: README.md `How it's built` must state %q — tools/trstctllint/main.go registers an analyzer for exactly %v. Intro reads: %s", want, enforced, flat)
	}
	if want := testedList + " have no analyzer"; !strings.Contains(flat, want) {
		t.Errorf("ARCH-010: README.md `How it's built` must state %q — those invariants are held by tests, not by the linter (MAINTAINERS.md says so already). Intro reads: %s", want, flat)
	}
	if strings.Contains(flat, "eight are enforced") {
		t.Error("ARCH-010: README.md still claims eight of the nine invariants are linter-enforced; the linter has an analyzer for six of them")
	}
	// The tests the intro credits must exist, so the replacement claim is not itself
	// an unverified assertion.
	paths := linterTestPathRe.FindAllStringSubmatch(intro, -1)
	if len(paths) == 0 {
		t.Error("ARCH-010: README.md `How it's built` must name at least one concrete _test.go that holds an un-lintable invariant")
	}
	for _, m := range paths {
		if _, err := os.Stat(filepath.FromSlash("../" + m[1])); err != nil {
			t.Errorf("ARCH-010: README.md cites %s as the proof for an un-lintable invariant, but it does not exist: %v", m[1], err)
		}
	}

	// (2) The repository-layout entry for tools/ must name the same set.
	layoutLine, layoutANs := linterANSetOnLine(t, "README.md", readme, "trstctllint — the architecture linter")
	if !linterEqualANs(layoutANs, enforced) {
		t.Errorf("ARCH-010: README.md repository layout says the architecture linter covers %v, but tools/trstctllint/main.go registers analyzers for %v. Line: %s", layoutANs, enforced, strings.TrimSpace(layoutLine))
	}

	// (3) .github/CODEOWNERS gave a third, different count. It must name the same set.
	codeowners := read(t, "../.github/CODEOWNERS")
	coLine, coANs := linterANSetOnLine(t, ".github/CODEOWNERS", codeowners, "architecture linter that enforces")
	if !linterEqualANs(coANs, enforced) {
		t.Errorf("ARCH-010: .github/CODEOWNERS says the architecture linter enforces %v, but tools/trstctllint/main.go registers analyzers for %v. Line: %s", coANs, enforced, strings.TrimSpace(coLine))
	}

	// (4) MAINTAINERS.md was the file that had it right; keep it that way, so the
	// three artifacts cannot drift apart again from the other direction.
	maintainers := read(t, "../MAINTAINERS.md")
	idx := strings.Index(maintainers, "no analyzer")
	if idx < 0 {
		t.Fatal("ARCH-010: MAINTAINERS.md no longer records that some invariants have no analyzer; the README's split now has no maintainer-facing source")
	}
	// The paragraph that makes the claim, so an enforced invariant cannot be listed
	// as un-analyzed elsewhere in the file without this noticing.
	para := maintainers[idx:]
	if stop := strings.Index(para, "\n\n"); stop >= 0 {
		para = para[:stop]
	}
	for _, an := range tested {
		if !strings.Contains(para, an) {
			t.Errorf("ARCH-010: MAINTAINERS.md's no-analyzer paragraph no longer names %s among the invariants that lean on tests instead", an)
		}
	}
	for _, an := range enforced {
		if strings.Contains(para, an) {
			t.Errorf("ARCH-010: MAINTAINERS.md's no-analyzer paragraph lists %s, but tools/trstctllint/main.go registers an analyzer for it", an)
		}
	}
}

// linterEqualANs reports whether two already-sorted AN ID sets are identical.
func linterEqualANs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---- ARCH-011: the reader-facing invariants page states the same split --------
//
// ARCH-010 above keeps README.md, .github/CODEOWNERS and MAINTAINERS.md honest
// about which invariants the linter actually enforces. The page the docs site
// publishes as the engineer and operator handoff document,
// docs/design/architecture-invariants.md, was outside that scope and drifted the
// other way: it named the invariants in prose with zero AN-n identifiers, called
// them "the eight invariants" while README.md defines nine, and offered "The
// architecture guard is a custom `go/analysis` linter that runs under `make
// lint`" as its only enforcement statement, placed directly under the invariant
// table. A reader reasonably concluded every invariant was analyzer-enforced.
// AGENTS.md and MAINTAINERS.md already disclosed the asymmetry; the public page
// was the one overclaiming.
//
// This guard reuses linterANScope, so the page is checked against the same
// multichecker registration list ARCH-010 derives from and the two artifacts
// cannot drift apart.

// TestInvariantsPageStatesEnforcementAsymmetry locks ARCH-011. ELI5: the page a
// new engineer reads to learn the architecture rules has to say which rules the
// build stops them from breaking and which ones only tests hold, or they lean on
// a wall that is not there.
func TestInvariantsPageStatesEnforcementAsymmetry(t *testing.T) {
	enforced, tested := linterANScope(t)
	page := read(t, "design/architecture-invariants.md")
	// Collapse whitespace so a claim that wraps across lines still matches.
	flat := strings.Join(strings.Fields(page), " ")

	// (1) Every invariant README defines must be identifiable on the page by its
	// AN-n ID, so a reader can map the page onto the contract and onto a linter
	// diagnostic. The page used to name none of them.
	all := append(append([]string{}, enforced...), tested...)
	linterSortANs(all)
	for _, an := range all {
		if !strings.Contains(flat, an) {
			t.Errorf("ARCH-011: docs/design/architecture-invariants.md never names %s; the page must use the same AN-n identifiers as README.md so a reader can map it onto the contract and onto linter diagnostics", an)
		}
	}

	// (2) The page's own count must match how many invariants README defines.
	counts := map[int]string{7: "seven", 8: "eight", 9: "nine", 10: "ten"}
	word, ok := counts[len(all)]
	if !ok {
		t.Fatalf("ARCH-011: README.md now defines %d invariants; teach this guard the English word for that count", len(all))
	}
	if !strings.Contains(flat, word+" invariants") {
		t.Errorf("ARCH-011: docs/design/architecture-invariants.md must say %q — README.md defines %d invariants (%v analyzer-enforced, %v test-enforced)", word+" invariants", len(all), enforced, tested)
	}
	for n, w := range counts {
		if n != len(all) && strings.Contains(flat, w+" invariants") {
			t.Errorf("ARCH-011: docs/design/architecture-invariants.md says %q, but README.md defines %d invariants", w+" invariants", len(all))
		}
	}

	// (3) The asymmetry itself, derived from the multichecker registration list
	// rather than restated by hand: registering a new AN-scoped analyzer (or
	// dropping one) turns this red until the page is updated with it.
	if want := linterJoinANs(enforced) + " have a dedicated analyzer"; !strings.Contains(flat, want) {
		t.Errorf("ARCH-011: docs/design/architecture-invariants.md must state %q — tools/trstctllint/main.go registers an analyzer for exactly %v", want, enforced)
	}
	if want := linterJoinANs(tested) + " have no dedicated analyzer"; !strings.Contains(flat, want) {
		t.Errorf("ARCH-011: docs/design/architecture-invariants.md must state %q — %v are held by tests, not by the linter, and this page is where a reader looks for that", want, tested)
	}

	// (4) The tests the page credits must exist, so the disclosure is not itself
	// an unverified claim.
	paths := linterTestPathRe.FindAllStringSubmatch(page, -1)
	if len(paths) == 0 {
		t.Error("ARCH-011: docs/design/architecture-invariants.md must name at least one concrete _test.go that holds an un-lintable invariant")
	}
	for _, m := range paths {
		if _, err := os.Stat(filepath.FromSlash("../" + m[1])); err != nil {
			t.Errorf("ARCH-011: docs/design/architecture-invariants.md cites %s as the proof for an un-lintable invariant, but it does not exist: %v", m[1], err)
		}
	}
}
