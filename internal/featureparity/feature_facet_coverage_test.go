// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var featureFacetNames = []string{
	"served",
	"ui",
	"cli",
	"api",
	"test",
	"docs",
	"rbac",
	"audit",
	"telemetry",
	"a11y",
	"i18n",
}

var gaServedStates = map[string]bool{
	"served":      true,
	"conditional": true,
	"partial":     true,
}

var gaEvidenceRequired = map[string]bool{
	"served": true,
	"ui":     true,
	"test":   true,
	"docs":   true,
	"a11y":   true,
	"i18n":   true,
}

const featureSpecificA11yReceiptRef = "web/src/__tests__/feature_a11y_receipts.test.tsx"

var genericShellA11yEvidence = regexp.MustCompile(`(?i)\b(primary navigation|registered customer routes|keyboard traversal|mobile drawer|skip link|shell accessibility|app shell)\b`)

// TestFeatureFacetCoverage is the generated acceptance contract for COVER-006:
// every catalog row must have explicit evidence or an explicit N/A for each
// feature facet, and GA-ish rows must carry concrete evidence for the facets that
// are always applicable to a shipped operator surface.
func TestFeatureFacetCoverage(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	for _, item := range catalog.Items {
		cells := item.FacetEvidence.Cells()
		isGA := gaServedStates[item.ServedState]
		for _, facet := range featureFacetNames {
			cell := cells[facet]
			hasEvidence := len(nonBlank(cell.Evidence)) > 0
			hasNA := strings.TrimSpace(cell.NA) != ""
			if !hasEvidence && !hasNA {
				t.Errorf("%s (%s) facet %q has no evidence and no explicit N/A", item.FeatureID, item.Feature, facet)
				continue
			}
			if hasEvidence && hasNA {
				t.Errorf("%s (%s) facet %q declares both evidence and N/A", item.FeatureID, item.Feature, facet)
			}
			if isGA && gaEvidenceRequired[facet] && !hasEvidence {
				t.Errorf("%s (%s) GA facet %q must have evidence, got N/A %q", item.FeatureID, item.Feature, facet, cell.NA)
			}
			if hasNA && !strings.HasPrefix(strings.TrimSpace(cell.NA), "N/A:") {
				t.Errorf("%s (%s) facet %q N/A reason must start with N/A:, got %q", item.FeatureID, item.Feature, facet, cell.NA)
			}
			for _, ref := range cell.Refs {
				if strings.TrimSpace(ref) == "" {
					t.Errorf("%s (%s) facet %q has a blank ref", item.FeatureID, item.Feature, facet)
					continue
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ref))); err != nil {
					t.Errorf("%s (%s) facet %q references missing file %q: %v", item.FeatureID, item.Feature, facet, ref, err)
				}
			}
		}
		checkFacetAlignment(t, item)
	}
}

// TestFeatureServedFacetCitesExecutedAcceptanceTest closes the old os.Stat-only
// loophole. A served row must point to a named Go test in one of its cited test
// files, and its served facet must cite the repository's `make test` command that
// CI actually executes. Prose plus an arbitrary existing path is not proof.
func TestFeatureServedFacetCitesExecutedAcceptanceTest(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if !strings.Contains(string(workflow), "run: make test") || !strings.Contains(string(makefile), "test: ## Run all tests") {
		t.Fatal("served acceptance command make test is not executed by CI")
	}

	testName := regexp.MustCompile(`\b(Test[A-Za-z0-9_]+)\b`)
	for _, item := range catalog.Items {
		if item.ServedState != "served" {
			continue
		}
		served := item.FacetEvidence.Served
		if !containsFeatureFacetString(served.Commands, "make test") {
			t.Errorf("%s (%s) served facet must cite CI-executed command make test", item.FeatureID, item.Feature)
		}

		evidence := item.AcceptanceTest + "\n" + strings.Join(item.FacetEvidence.Test.Evidence, "\n")
		candidates := testName.FindAllString(evidence, -1)
		proved := false
		var rejected []string
		for _, ref := range item.FacetEvidence.Test.Refs {
			if !strings.HasSuffix(ref, "_test.go") || strings.HasPrefix(ref, "internal/featureparity/") {
				continue
			}
			source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ref))) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				continue
			}
			if regexp.MustCompile(`(?m)^//go:build\s+`).Match(source) {
				rejected = append(rejected, ref+": default make test execution is not proven for build-tagged evidence")
				continue
			}
			packageRoot := strings.Split(filepath.ToSlash(ref), "/")[0]
			if !strings.Contains(string(makefile), "./"+packageRoot+"/...") {
				rejected = append(rejected, ref+": package root is outside Makefile GO_PACKAGES")
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), ref, source, 0)
			if err != nil {
				rejected = append(rejected, ref+": cannot parse cited test file")
				continue
			}
			for _, candidate := range candidates {
				for _, decl := range parsed.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Name.Name != candidate || fn.Body == nil {
						continue
					}
					hasSkip := false
					ast.Inspect(fn.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok {
							return true
						}
						sel, ok := call.Fun.(*ast.SelectorExpr)
						if ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
							hasSkip = true
						}
						return true
					})
					if hasSkip {
						rejected = append(rejected, ref+":"+candidate+": acceptance proof can skip")
						continue
					}
					proved = true
					break
				}
				if proved {
					break
				}
			}
			if proved {
				break
			}
		}
		if !proved {
			t.Errorf("%s (%s) served facet has no named, default-built, no-skip acceptance Test function in its non-circular test refs (rejected: %s)", item.FeatureID, item.Feature, strings.Join(rejected, "; "))
		}
	}
}

func TestFeatureA11yEvidenceIsWorkflowSpecific(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	for _, item := range catalog.Items {
		cells := item.FacetEvidence.Cells()
		ui := cells["ui"]
		a11y := cells["a11y"]
		if len(nonBlank(ui.Evidence)) == 0 || strings.TrimSpace(ui.NA) != "" {
			continue
		}

		a11yEvidence := strings.Join(nonBlank(a11y.Evidence), "\n")
		if item.FeatureID == "F12" {
			if !strings.Contains(strings.ToLower(a11yEvidence), "navigation-shell") {
				t.Errorf("%s (%s) is the navigation shell row and must explain why shell-level a11y evidence is intentional", item.FeatureID, item.Feature)
			}
			continue
		}

		if !containsFeatureFacetString(a11y.Refs, featureSpecificA11yReceiptRef) {
			t.Errorf("%s (%s) UI a11y evidence must cite %q", item.FeatureID, item.Feature, featureSpecificA11yReceiptRef)
		}
		if genericShellA11yEvidence.MatchString(a11yEvidence) {
			t.Errorf("%s (%s) UI a11y evidence must be workflow-specific, got shell-level text %q", item.FeatureID, item.Feature, a11yEvidence)
		}
	}
}

func checkFacetAlignment(t *testing.T, item Item) {
	t.Helper()
	cells := item.FacetEvidence.Cells()
	if gaServedStates[item.ServedState] && strings.TrimSpace(cells["served"].NA) != "" {
		t.Errorf("%s (%s) is %s but served facet is N/A", item.FeatureID, item.Feature, item.ServedState)
	}
	if !gaServedStates[item.ServedState] && len(nonBlank(cells["served"].Evidence)) > 0 {
		t.Errorf("%s (%s) is %s but served facet claims evidence", item.FeatureID, item.Feature, item.ServedState)
	}
	if len(item.APISurface) > 0 && len(nonBlank(cells["api"].Evidence)) == 0 {
		t.Errorf("%s (%s) has api_surface entries but API facet has no evidence", item.FeatureID, item.Feature)
	}
	if len(item.APISurface) == 0 && strings.TrimSpace(item.APINA) != "" && strings.TrimSpace(cells["api"].NA) == "" {
		t.Errorf("%s (%s) has api_na but API facet has no N/A reason", item.FeatureID, item.Feature)
	}
	if len(item.CLISurface) > 0 && len(nonBlank(cells["cli"].Evidence)) == 0 {
		t.Errorf("%s (%s) has cli_surface entries but CLI facet has no evidence", item.FeatureID, item.Feature)
	}
	if len(item.CLISurface) == 0 && strings.TrimSpace(item.CLINA) != "" && strings.TrimSpace(cells["cli"].NA) == "" {
		t.Errorf("%s (%s) has cli_na but CLI facet has no N/A reason", item.FeatureID, item.Feature)
	}
	if len(item.SourceDocs) > 0 {
		docRefs := map[string]bool{}
		for _, ref := range cells["docs"].Refs {
			docRefs[ref] = true
		}
		for _, doc := range item.SourceDocs {
			if !docRefs[doc] {
				t.Errorf("%s (%s) docs facet must cite source_docs ref %q", item.FeatureID, item.Feature, doc)
			}
		}
	}
}

func nonBlank(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func containsFeatureFacetString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
