package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type featureMapLedger struct {
	Items []featureMapServedState `json:"items"`
}

type featureMapServedState struct {
	FeatureID              string `json:"feature_id"`
	Feature                string `json:"feature"`
	ServedState            string `json:"served_state"`
	BackendStatus          string `json:"backend_status"`
	CurrentFrontendMapping string `json:"current_frontend_mapping"`
}

func featureServedStateLedger(t *testing.T) featureMapLedger {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash("../internal/featureparity/feature-map-backlog.json"))
	if err != nil {
		t.Fatalf("read feature-map backlog: %v", err)
	}
	var ledger featureMapLedger
	if err := json.Unmarshal(b, &ledger); err != nil {
		t.Fatalf("parse feature-map backlog: %v", err)
	}
	if len(ledger.Items) == 0 {
		t.Fatal("feature-map backlog has no items")
	}
	return ledger
}

func TestFeatureCatalogHasExplicitServedState(t *testing.T) {
	valid := map[string]bool{
		"served":      true,
		"conditional": true,
		"partial":     true,
		"library":     true,
		"roadmap":     true,
	}
	byID := map[string]featureMapServedState{}
	counts := map[string]int{}
	for _, item := range featureServedStateLedger(t).Items {
		if item.FeatureID == "" {
			t.Fatalf("feature-map backlog item %q has no feature_id", item.Feature)
		}
		if byID[item.FeatureID].FeatureID != "" {
			t.Fatalf("feature-map backlog duplicates %s", item.FeatureID)
		}
		if !valid[item.ServedState] {
			t.Errorf("%s has invalid served_state %q", item.FeatureID, item.ServedState)
		}
		byID[item.FeatureID] = item
		counts[item.ServedState]++
	}

	for _, ft := range featureCatalog(t) {
		item := byID[ft.id]
		if item.FeatureID == "" {
			t.Errorf("features.tsv row %s (%s) has no feature-map served_state row", ft.id, ft.title)
			continue
		}
		if item.Feature == "" || item.BackendStatus == "" {
			t.Errorf("%s served_state row must carry feature and backend status evidence", ft.id)
		}
	}
	if len(byID) != len(featureCatalog(t)) {
		t.Fatalf("feature-map served_state denominator = %d, features.tsv denominator = %d", len(byID), len(featureCatalog(t)))
	}

	for _, state := range []string{"served", "conditional", "partial", "library"} {
		if counts[state] == 0 {
			t.Errorf("served_state ledger should include at least one %q row so enum handling is exercised", state)
		}
	}

	for _, item := range byID {
		if item.ServedState != "library" && item.ServedState != "roadmap" {
			continue
		}
		lower := strings.ToLower(item.CurrentFrontendMapping)
		if !strings.Contains(lower, "roadmap-disclosure") && !strings.HasPrefix(lower, "disclosure:") {
			t.Errorf("%s is %s but current GUI mapping is not an explicit disclosure: %q", item.FeatureID, item.ServedState, item.CurrentFrontendMapping)
		}
	}
}

func TestFeatureIndexDoesNotOverclaimAllCatalogRowsAsServed(t *testing.T) {
	body := read(t, "features.md")
	lower := strings.ToLower(body)
	for _, stale := range []string{
		"trstctl ships **78 capabilities**",
		"ships 78 capabilities",
		"all 78 capabilities are served",
		"78 ga capabilities",
	} {
		if strings.Contains(lower, strings.ToLower(stale)) {
			t.Errorf("features.md over-claims the feature catalog with %q", stale)
		}
	}
	for _, want := range []string{
		"tracks **78 capabilities**",
		"served-state metadata",
		"`served_state`",
		"`api_surface`",
		"`cli_surface`",
		"`facet_evidence`",
		"feature-authz manifests",
		"FeatureFacetCoverage",
		"`library`",
		"`roadmap`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("features.md must explain the served-state catalog contract (missing %q)", want)
		}
	}
}

func TestFeatureMaturityVocabularyIsSharedByDocsAndWeb(t *testing.T) {
	statusVocab := read(t, "../web/src/lib/statusVocab.ts")
	featuresDoc := read(t, "features.md")
	limitations := strings.ToLower(read(t, "limitations.md"))
	readme := strings.ToLower(read(t, "../README.md"))

	if !strings.Contains(statusVocab, "featureMaturityLabels") {
		t.Fatal("DOCS-004: web maturity labels should be exported from statusVocab.ts so product copy cannot drift from docs vocabulary")
	}
	for _, retired := range []string{"../web/src/lib/featureCoverage.ts", "../web/src/pages/FeatureCoverage.tsx"} {
		if _, err := os.Stat(filepath.FromSlash(retired)); !os.IsNotExist(err) {
			t.Fatalf("DOCS-004: retired coverage artifact %s should stay removed; stat err=%v", retired, err)
		}
	}

	wantLabels := map[string]string{
		"served":      "Served",
		"conditional": "Conditional",
		"partial":     "Partial",
		"library":     "Library-only",
		"roadmap":     "Roadmap",
	}
	for state, label := range wantLabels {
		if !strings.Contains(statusVocab, state+":") || !strings.Contains(statusVocab, label) {
			t.Errorf("DOCS-004: shared maturity labels should map %s to %q", state, label)
		}
		if !strings.Contains(featuresDoc, "`"+state+"`") {
			t.Errorf("DOCS-004: features.md should document served_state value `%s`", state)
		}
	}
	for _, marker := range []string{
		"served by the running binary",
		"built and tested, but not yet served",
		"library code",
		"phase 2",
	} {
		if !strings.Contains(limitations, marker) {
			t.Errorf("DOCS-004: limitations.md should keep maturity marker %q", marker)
		}
	}
	for _, marker := range []string{
		"served end to end by the running",
		"library-complete and tested",
		"single authority",
	} {
		if !strings.Contains(readme, marker) {
			t.Errorf("DOCS-004: README should keep the served-vs-library spine marker %q", marker)
		}
	}
}
