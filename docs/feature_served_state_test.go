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

	for _, state := range []string{"served", "conditional", "partial"} {
		if counts[state] == 0 {
			t.Errorf("served_state ledger should include at least one %q row so enum handling is exercised", state)
		}
	}
	if counts["library"] != 0 {
		t.Errorf("served_state=library is no longer a GA catalog state; move built-but-unserved rows to roadmap or wire them as served/conditional/partial")
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
		"trstctl ships **79 capabilities**",
		"ships 79 capabilities",
		"all 79 capabilities are served",
		"79 ga capabilities",
	} {
		if strings.Contains(lower, strings.ToLower(stale)) {
			t.Errorf("features.md over-claims the feature catalog with %q", stale)
		}
	}
	for _, want := range []string{
		"tracks **79 capabilities**",
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

func TestReadmeRoadmapMatchesServedStateReality(t *testing.T) {
	roadmap := readmeMarkdownSection(t, read(t, "../README.md"), "## Roadmap")
	roadmapText := normalizeDocText(roadmap)

	domainFeatureIDs := map[string][]string{
		"enrollment protocols": {"F22", "F23", "F54", "F55", "F56"},
		"connectors":           {"F7", "F27"},
		"workload identity":    {"F24", "F25", "F30", "F59", "F61"},
		"secrets domain":       {"F35", "F36", "F37", "F38", "F39", "F58", "F60", "F63", "F64", "F65", "F66", "F67", "F68"},
	}
	for domain, ids := range domainFeatureIDs {
		if !servedStateDomainHasRuntimeRows(t, ids) {
			continue
		}
		if strings.Contains(roadmapText, domain) && strings.Contains(roadmapText, "wire the library-complete capabilities into the served binary") {
			t.Errorf("README Roadmap still says %s needs generic binary wiring even though feature-map served_state rows %s are already served, conditional, or partial", domain, strings.Join(ids, ", "))
		}
	}

	for _, stale := range []string{
		"enrollment protocols, connectors, workload identity, and the secrets domain",
		"wire the library-complete capabilities into the served binary",
	} {
		if strings.Contains(roadmapText, stale) {
			t.Errorf("README Roadmap must replace stale broad binary-wiring wording %q with exact residuals from limitations.md", stale)
		}
	}
	for _, want := range []string{
		"embedded/iot enrollment renewal",
		"automatic acme order-time dns-01 publish/cleanup",
		"cursor pagination and list virtualization",
		"terraform cloud/opentofu and arbitrary webhook secret-sync targets",
		"vault kv outbound sync",
		"broader kmip operations",
	} {
		if !strings.Contains(roadmapText, want) {
			t.Errorf("README Roadmap must name residual %q instead of broad served-domain wiring", want)
		}
	}
}

func TestLimitationsFeatureRowsMatchServedState(t *testing.T) {
	const (
		startMarker = "<!-- feature-served-state-matrix:start -->"
		endMarker   = "<!-- feature-served-state-matrix:end -->"
	)
	sectionByHeading := map[string]string{
		"Served":       "served",
		"Conditional":  "conditional",
		"Partial":      "partial",
		"Library-only": "library",
		"Roadmap":      "roadmap",
	}

	body := read(t, "limitations.md")
	start := strings.Index(body, startMarker)
	end := strings.Index(body, endMarker)
	if start == -1 || end == -1 || end <= start {
		t.Fatalf("limitations.md must contain the DOCS-003 served-state matrix markers %q and %q", startMarker, endMarker)
	}
	matrix := body[start+len(startMarker) : end]

	byID := map[string]featureMapServedState{}
	seen := map[string]int{}
	for _, item := range featureServedStateLedger(t).Items {
		byID[item.FeatureID] = item
	}

	sectionsSeen := map[string]bool{}
	currentSection := ""
	for _, line := range strings.Split(matrix, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "### ") {
			heading := strings.TrimSpace(strings.TrimPrefix(trimmed, "### "))
			state, ok := sectionByHeading[heading]
			if !ok {
				t.Fatalf("limitations.md DOCS-003 matrix has unknown section heading %q", heading)
			}
			currentSection = state
			sectionsSeen[state] = true
			continue
		}

		cells := markdownTableCells(trimmed)
		if len(cells) == 0 || !isFeatureID(cells[0]) {
			continue
		}
		if currentSection == "" {
			t.Fatalf("limitations.md feature row %s appears before a DOCS-003 served-state heading", cells[0])
		}
		item, ok := byID[cells[0]]
		if !ok {
			t.Fatalf("limitations.md feature row %s has no feature-map-backlog.json row", cells[0])
		}
		if currentSection != item.ServedState {
			t.Errorf("limitations.md feature row %s is under %q but feature-map-backlog.json says served_state=%q", item.FeatureID, currentSection, item.ServedState)
		}
		if len(cells) < 2 || cells[1] != item.Feature {
			t.Errorf("limitations.md feature row %s title = %q, want %q from feature-map-backlog.json", item.FeatureID, cellAt(cells, 1), item.Feature)
		}
		seen[item.FeatureID]++
	}

	for _, state := range []string{"served", "conditional", "partial", "library", "roadmap"} {
		if !sectionsSeen[state] {
			t.Errorf("limitations.md DOCS-003 matrix missing %q section", state)
		}
	}
	for _, item := range byID {
		switch seen[item.FeatureID] {
		case 0:
			t.Errorf("limitations.md DOCS-003 matrix missing %s (%s)", item.FeatureID, item.Feature)
		case 1:
		default:
			t.Errorf("limitations.md DOCS-003 matrix lists %s %d times", item.FeatureID, seen[item.FeatureID])
		}
	}
}

func readmeMarkdownSection(t *testing.T, body, heading string) string {
	t.Helper()
	start := strings.Index(body, heading)
	if start == -1 {
		t.Fatalf("README missing section heading %q", heading)
	}
	rest := body[start+len(heading):]
	next := strings.Index(rest, "\n## ")
	if next == -1 {
		return rest
	}
	return rest[:next]
}

func servedStateDomainHasRuntimeRows(t *testing.T, ids []string) bool {
	t.Helper()
	byID := map[string]featureMapServedState{}
	for _, item := range featureServedStateLedger(t).Items {
		byID[item.FeatureID] = item
	}

	hasRuntimeRow := false
	for _, id := range ids {
		item, ok := byID[id]
		if !ok {
			t.Fatalf("feature-map-backlog.json missing README roadmap domain feature %s", id)
		}
		switch item.ServedState {
		case "served", "conditional", "partial":
			hasRuntimeRow = true
		case "library", "roadmap":
		default:
			t.Fatalf("%s has invalid served_state %q", id, item.ServedState)
		}
	}
	return hasRuntimeRow
}

func normalizeDocText(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func markdownTableCells(line string) []string {
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	raw := strings.Split(strings.Trim(line, "|"), "|")
	cells := make([]string, 0, len(raw))
	for _, cell := range raw {
		cells = append(cells, strings.TrimSpace(cell))
	}
	return cells
}

func isFeatureID(s string) bool {
	if len(s) < 2 || s[0] != 'F' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cellAt(cells []string, idx int) string {
	if idx >= len(cells) {
		return ""
	}
	return cells[idx]
}
