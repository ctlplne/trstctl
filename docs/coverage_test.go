package docs

// Documentation coverage gate — the in-repo, CI-enforced port of docs-harness/verify.sh.
//
// The external docs-harness authors pages to a contract; this test makes the
// mechanical half of that contract part of `go test ./docs/...`, so docs can never
// silently regress the way code can't pass `make lint`. It is deliberately STRICTER
// than a bare-ID grep:
//
//   - coverage is keyed on the page's **Covers:** footer (a deliberate authorship
//     act), not an incidental mention of the feature ID anywhere in prose;
//   - every feature page must have the full skeleton + a worked example (anti-stub);
//   - every term of art used in a feature page must be defined in the glossary
//     (the zero-knowledge-reader guarantee), not merely counted.
//
// Accuracy (does a claim match the code?) is covered by the sibling reality tests
// (docs_test.go, docs_drift_test.go, …); this file covers completeness + structure.
// It reuses read() and allMarkdown() from docs_test.go (same package).

import (
	_ "embed"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// features.tsv is the in-repo source of truth for the product feature catalog
// (mirror of docs-harness/features.tsv; regenerated from the PRD). Vendored here so
// the gate runs from a plain checkout in CI with no external harness.
//
//go:embed features.tsv
var featuresTSV string

var fidLineRE = regexp.MustCompile(`^(F[0-9]+[a-z]?)\t(.+)$`)
var fidRE = regexp.MustCompile(`F[0-9]+[a-z]?`)
var navFeatureIDsRE = regexp.MustCompile(`featureIds:\s*\[([^\]]*)\]`)

type feature struct{ id, title string }

func featureCatalog(t *testing.T) []feature {
	t.Helper()
	var out []feature
	for _, ln := range strings.Split(featuresTSV, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasPrefix(ln, "#") || strings.TrimSpace(ln) == "" {
			continue
		}
		if m := fidLineRE.FindStringSubmatch(ln); m != nil {
			out = append(out, feature{id: m[1], title: m[2]})
		}
	}
	if len(out) == 0 {
		t.Fatal("features.tsv parsed to zero features — vendored catalog missing or malformed")
	}
	return out
}

// wordRE matches term as a whole token (so "RA" never matches inside "ORACLE", and
// "F7" never matches inside "F70"). Term is quoted so "X.509" is literal.
func wordRE(term string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^0-9A-Za-z_])` + regexp.QuoteMeta(term) + `([^0-9A-Za-z_]|$)`)
}

// TestEveryFeatureHasACoversFooter is the coverage gate: each catalog feature must
// be claimed by a page's **Covers:** footer (not just mentioned in passing). This is
// what makes "every feature is documented" mean "a page deliberately teaches it".
func TestEveryFeatureHasACoversFooter(t *testing.T) {
	covered := map[string]string{} // fid -> page that Covers it
	for _, f := range allMarkdown(t) {
		base := filepath.Base(f)
		if base == "features.md" || base == "glossary.md" {
			continue // the index and the dictionary don't count as teaching a feature
		}
		for _, ln := range strings.Split(read(t, f), "\n") {
			if !strings.Contains(ln, "**Covers:**") {
				continue
			}
			for _, m := range fidRE.FindAllString(ln, -1) {
				covered[m] = f
			}
		}
	}
	var missing []string
	for _, ft := range featureCatalog(t) {
		if covered[ft.id] == "" {
			missing = append(missing, fmt.Sprintf("%s (%s)", ft.id, ft.title))
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d feature(s) not claimed by any page's **Covers:** footer:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestFeatureIndexListsEveryFeature: docs/features.md is the reader-facing
// traceability matrix; it must list every feature ID.
func TestFeatureIndexListsEveryFeature(t *testing.T) {
	idx := read(t, "features.md")
	var missing []string
	for _, ft := range featureCatalog(t) {
		if !wordRE(ft.id).MatchString(idx) {
			missing = append(missing, ft.id)
		}
	}
	if len(missing) > 0 {
		t.Errorf("docs/features.md missing %d feature ID(s): %s", len(missing), strings.Join(missing, ", "))
	}
}

func TestFeatureCatalogCoversWebNavigationFeatureIDs(t *testing.T) {
	catalog := map[string]bool{}
	for _, ft := range featureCatalog(t) {
		catalog[ft.id] = true
	}

	navigation := read(t, "../web/src/lib/navigation.ts")
	missing := map[string]bool{}
	for _, match := range navFeatureIDsRE.FindAllStringSubmatch(navigation, -1) {
		for _, id := range fidRE.FindAllString(match[1], -1) {
			if !catalog[id] {
				missing[id] = true
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	var ids []string
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Errorf("web navigation declares feature ID(s) absent from docs/features.tsv: %s", strings.Join(ids, ", "))
}

// TestEveryFeaturePageHasSkeleton is the anti-stub check: a page that Covers a
// feature must actually have the protocol skeleton + a worked example, so a bare
// "F37 exists" line can never satisfy the gate.
func TestEveryFeaturePageHasSkeleton(t *testing.T) {
	requiredHeadings := []string{"What it is", "Why it exists", "How it works", "Use it", "Pitfalls", "Reference"}
	const minLines = 40
	for _, f := range allMarkdown(t) {
		body := read(t, f)
		if !strings.Contains(body, "**Covers:**") {
			continue // only pages that claim a feature must meet the skeleton
		}
		var problems []string
		var headingText strings.Builder
		for _, ln := range strings.Split(body, "\n") {
			if strings.HasPrefix(ln, "#") {
				headingText.WriteString(ln)
				headingText.WriteString("\n")
			}
		}
		hs := headingText.String()
		for _, h := range requiredHeadings {
			if !strings.Contains(hs, h) {
				problems = append(problems, "missing section heading containing "+strconv.Quote(h))
			}
		}
		if strings.Count(body, "\n```") < 1 { // at least one fenced code block (the worked example)
			problems = append(problems, "no fenced code example (the 'Use it' block)")
		}
		if n := strings.Count(body, "\n"); n < minLines {
			problems = append(problems, fmt.Sprintf("only %d lines (<%d) — looks like a stub", n, minLines))
		}
		if len(problems) > 0 {
			t.Errorf("%s does not meet the page contract:\n  - %s", f, strings.Join(problems, "\n  - "))
		}
	}
}

// termsOfArt are acronyms/terms a zero-knowledge reader cannot be assumed to know.
// If one appears in a feature page, the glossary must DEFINE it (as a heading or a
// bold lead), not merely count toward a total. This is the real enforcement of the
// "assume no prior knowledge" rule.
var termsOfArt = []string{
	"X.509", "CSR", "CA", "RA", "ACME", "EST", "SCEP", "CMP", "ARI", "CAA",
	"SPIFFE", "SVID", "SAN", "CRL", "OCSP", "TSA", "mTLS", "TLS",
	"KEK", "DEK", "RLS", "CBOM", "HSM", "KMIP", "PQC",
	"OIDC", "SSO", "MDM", "JIT", "NHI",
}

// TestGlossaryDefinesUsedTermsOfArt: every term of art that actually appears in a
// feature page has a glossary entry (heading or bold lead) defining it.
func TestGlossaryDefinesUsedTermsOfArt(t *testing.T) {
	// Defined terms = the text of glossary headings + bold leads (where a term is
	// defined), not the whole file (a passing mention in a definition body doesn't
	// count as defining the term).
	var defLines []string
	for _, ln := range strings.Split(read(t, "glossary.md"), "\n") {
		ls := strings.TrimSpace(ln)
		if strings.HasPrefix(ls, "### ") || strings.HasPrefix(ls, "**") || strings.HasPrefix(ls, "- **") {
			defLines = append(defLines, ls)
		}
	}
	defined := strings.Join(defLines, "\n")

	// Concatenate the feature pages once to test "is this term used anywhere".
	var featurePages strings.Builder
	for _, f := range allMarkdown(t) {
		if strings.HasPrefix(filepath.ToSlash(f), "features/") {
			featurePages.WriteString(read(t, f))
			featurePages.WriteString("\n")
		}
	}
	used := featurePages.String()

	var missing []string
	for _, term := range termsOfArt {
		if wordRE(term).MatchString(used) && !wordRE(term).MatchString(defined) {
			missing = append(missing, term)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d term(s) of art used in feature pages but not defined in docs/glossary.md "+
			"(a zero-knowledge reader would be lost): %s", len(missing), strings.Join(missing, ", "))
	}
}
