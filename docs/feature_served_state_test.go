// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/secretsync"
)

type featureMapLedger struct {
	Items []featureMapServedState `json:"items"`
}

type featureMapServedState struct {
	FeatureID              string            `json:"feature_id"`
	Feature                string            `json:"feature"`
	ServedState            string            `json:"served_state"`
	BackendStatus          string            `json:"backend_status"`
	CurrentFrontendMapping string            `json:"current_frontend_mapping"`
	DoDCapabilities        []string          `json:"dod_capabilities,omitempty"`
	DoDResiduals           map[string]string `json:"dod_residuals,omitempty"`
}

type dodManifest struct {
	SchemaVersion   int                `json:"schema_version"`
	ManifestVersion int                `json:"manifest_version"`
	Entries         []dodManifestEntry `json:"entries"`
}

type dodManifestEntry struct {
	ID          string `json:"id"`
	Capability  string `json:"capability"`
	Inventory   bool   `json:"inventory"`
	Enforcement string `json:"enforcement"`
}

type dodCensus struct {
	Entries map[string]dodCensusEntry `json:"entries"`
}

type dodCensusEntry struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Enforcement string `json:"enforcement"`
}

func censusEntryClaimable(entry dodCensusEntry) bool {
	return entry.Status == "served" && entry.Enforcement == "required"
}

func liveDoDCensus(t *testing.T) (dodManifest, dodCensus) {
	t.Helper()
	root := filepath.Clean("..")
	manifestPath := filepath.Join(root, "tools", "dodcensus", "manifest.json")
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read repo-native DoD manifest: %v", err)
	}
	var manifest dodManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatalf("parse repo-native DoD manifest: %v", err)
	}
	if manifest.SchemaVersion != 1 || manifest.ManifestVersion != 1 || len(manifest.Entries) == 0 {
		t.Fatalf("unexpected DoD manifest contract: schema=%d manifest=%d entries=%d", manifest.SchemaVersion, manifest.ManifestVersion, len(manifest.Entries))
	}

	out := filepath.Join(t.TempDir(), "wiring-census.json")
	cmd := exec.Command("go", "run", "./tools/dodcensus", "--repo", ".", "--manifest", "tools/dodcensus/manifest.json", "--out", out)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOCACHE="+filepath.Join(t.TempDir(), "go-cache"),
		"GOFLAGS=",
	)
	commandOutput, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("execute fresh repo-native DoD census: %v\n%s", err, commandOutput)
	}
	b, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatalf("fresh DoD census did not write %s (command err=%v): %v\n%s", out, err, readErr, commandOutput)
	}
	var census dodCensus
	if err := json.Unmarshal(b, &census); err != nil {
		t.Fatalf("parse fresh DoD census: %v", err)
	}
	if len(census.Entries) != len(manifest.Entries) {
		t.Fatalf("fresh DoD census entries=%d, manifest entries=%d", len(census.Entries), len(manifest.Entries))
	}
	return manifest, census
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

	if counts["served"] == 0 {
		t.Error("served_state ledger should include at least one served row")
	}
	if counts["conditional"] == 0 || counts["partial"] == 0 {
		t.Errorf("honest served-state ledger must exercise conditional and partial states, got %#v", counts)
	}
	// Library and roadmap remain valid values but are not quota categories. Once a
	// formerly library-only mechanism is wired, forcing at least one feature to keep
	// that label would make the claims ledger lie. The live-census test below, not a
	// taxonomy quota, is the fail-closed proof for every DoD-gated feature.

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

// TestFeatureServedStateMatchesLiveWiringCensus is the W0 honesty lock. It runs
// the same repo-native evaluator as make dod-gate into a temporary receipt, then
// rejects a served feature claim when any capability breadth attached to that
// feature is still library-only, a stub, or unknown. Reading a previously
// generated wiring-census.json would let stale output certify a new overclaim, so
// this test deliberately evaluates the current source tree every time.
func TestFeatureServedStateMatchesLiveWiringCensus(t *testing.T) {
	manifest, census := liveDoDCensus(t)
	manifestCapabilities := map[string]bool{}
	for _, entry := range manifest.Entries {
		manifestCapabilities[entry.Capability] = true
		got, ok := census.Entries[entry.ID]
		if !ok {
			t.Errorf("fresh DoD census is missing manifest entry %s", entry.ID)
			continue
		}
		if got.Capability != entry.Capability {
			t.Errorf("fresh DoD census entry %s capability=%q, manifest=%q", entry.ID, got.Capability, entry.Capability)
		}
		if got.Enforcement != entry.Enforcement {
			t.Errorf("fresh DoD census entry %s enforcement=%q, manifest=%q", entry.ID, got.Enforcement, entry.Enforcement)
		}
	}

	mappedCapabilities := map[string]bool{}
	for _, item := range featureServedStateLedger(t).Items {
		for _, capability := range item.DoDCapabilities {
			if !manifestCapabilities[capability] {
				t.Errorf("%s maps unknown DoD capability %q", item.FeatureID, capability)
				continue
			}
			mappedCapabilities[capability] = true
			capabilityServed := true
			for id, entry := range census.Entries {
				if entry.Capability != capability || censusEntryClaimable(entry) {
					continue
				}
				capabilityServed = false
				if item.ServedState == "served" {
					t.Errorf("%s (%s) claims served while fresh DoD census entry %s is status=%s enforcement=%s", item.FeatureID, item.Feature, id, entry.Status, entry.Enforcement)
				}
			}
			residual := strings.TrimSpace(item.DoDResiduals[capability])
			if !capabilityServed && len(strings.Fields(residual)) < 8 {
				t.Errorf("%s (%s) must explain the non-served %s census residual, got %q", item.FeatureID, item.Feature, capability, residual)
			}
			if capabilityServed && item.ServedState == "library" {
				t.Errorf("%s (%s) is still library-only after every %s census entry became served; promote its maturity in the wiring commit", item.FeatureID, item.Feature, capability)
			}
			if capabilityServed && residual != "" {
				t.Errorf("%s (%s) keeps stale %s census residual after every entry became served: %q", item.FeatureID, item.Feature, capability, residual)
			}
		}
	}
	for capability := range manifestCapabilities {
		if !mappedCapabilities[capability] {
			t.Errorf("DoD capability %q has no feature-map row, so its census state cannot constrain product claims", capability)
		}
	}
}

// TestFeatureServedStateClassifiesRuntimeConditionsAndResiduals keeps the
// catalog's single maturity word honest. Conditional rows have a real path that
// is off until configuration or a license enables it. Partial rows keep a served
// spine visible while naming missing breadth. Library rows have code but no usable
// shipped path yet.
func TestFeatureServedStateClassifiesRuntimeConditionsAndResiduals(t *testing.T) {
	want := map[string]string{
		"F3":  "conditional", // agent_channel.enabled gates the actual agent transport
		"F4":  "partial",     // built-in and external CA issuance are served; Kubernetes posture routes remain
		"F5":  "conditional", // protocols.acme.enabled
		"F7":  "conditional", // all 24 native connectors are assembled when their immutable targets are configured
		"F13": "conditional", // browser SSO needs operator IdP configuration
		"F16": "partial",     // classical agility is served; PQC residual remains
		"F22": "conditional", // protocols.est.enabled
		"F23": "conditional", // protocols.scep.enabled
		"F24": "conditional", // protocols.spiffe.enabled
		"F26": "conditional", // all six backends are served; Enterprise license/config remains the runtime condition
		"F27": "conditional", // the additional native connectors share the configured production target registry
		"F29": "served",      // all advertised channels are production-assembled
		"F31": "conditional", // Enterprise remediation license and configured connector target gate the served workflow
		"F32": "conditional", // Enterprise remediation license
		"F34": "partial",     // issuance works; break-glass rotation residual remains
		"F37": "conditional", // secrets.enable_api
		"F39": "conditional", // secrets.enable_api
		"F41": "conditional", // Enterprise HA license plus federation.enabled
		"F43": "conditional", // protocols.ssh.enabled
		"F50": "conditional", // code_signing.enabled plus signer/Rekor trust
		"F51": "conditional", // protocols.tsa.enabled
		"F54": "conditional", // agent_channel.enabled gates embedded-client renewal
		"F55": "conditional", // protocols.cmp.enabled
		"F56": "conditional", // live MDM enrollment depends on configured SCEP
		"F57": "partial",     // licensed PQC spine exists; end-to-end residuals remain
		"F58": "conditional", // secrets.enable_api
		"F60": "conditional", // secrets.enable_api
		"F62": "conditional", // Enterprise governance/evidence-pack license
		"F63": "conditional", // secrets.enable_api
		"F64": "partial",     // served SDK spine; Vault/Terraform residuals remain
		"F65": "conditional", // all eight providers are assembled when tenant endpoints and credentials are configured
		"F66": "partial",     // transit is served; KMIP residuals/config remain
		"F67": "conditional", // secrets.enable_api
		"F68": "partial",     // eight native pushers are served; explicit secrets_residuals remain
		"F69": "conditional", // ACME plus provider configuration
		"F70": "conditional",
		"F71": "conditional",
		"F72": "conditional",
		"F73": "conditional",
		"F74": "conditional",
		"F75": "conditional", // ai.enable_api
		"F76": "conditional", // ai.enable_api
		"F77": "conditional", // ai.enable_api
		"F78": "conditional", // ai.enable_api
	}
	byID := map[string]featureMapServedState{}
	for _, item := range featureServedStateLedger(t).Items {
		byID[item.FeatureID] = item
	}
	for id, state := range want {
		if got := byID[id].ServedState; got != state {
			t.Errorf("%s served_state=%q, want truthful %q", id, got, state)
		}
	}
}

func TestHonestyAuthorityRejectsKnownW0Overclaims(t *testing.T) {
	limitations := read(t, "limitations.md")
	normalizedLimitations := strings.Join(strings.Fields(limitations), " ")
	for _, want := range []string{
		"queued receipt is not external-effect evidence.",
		"not production-assembled",
		"not independent authenticated approvals",
		"six of six backends served",
		"fsync-backed journal",
	} {
		if !strings.Contains(normalizedLimitations, want) {
			t.Errorf("limitations.md must keep the W0 honesty disclosure %q", want)
		}
	}
	for _, forbidden := range []string{
		"No current `feature-map-backlog.json` row uses `served_state=library`",
		"it records an unrouted receipt",
		"online m-of-n break-glass issuance is served",
		"zero of six backends served",
		"provider operations and credentials are not yet isolated",
	} {
		if strings.Contains(normalizedLimitations, forbidden) {
			t.Errorf("limitations.md keeps disproven W0 claim %q", forbidden)
		}
	}
	for _, name := range []string{"features/deployment-connectors.md", "journeys/automate-fleet-tls.md"} {
		doc := strings.ToLower(read(t, name))
		if strings.Contains(doc, "unrouted") {
			t.Errorf("%s must not claim that unowned connector work is silently acknowledged", name)
		}
		if !strings.Contains(doc, "queued") || !strings.Contains(doc, "attempt") {
			t.Errorf("%s must explain that queued connector evidence has no receiver attempt", name)
		}
	}

	issuance := strings.ToLower(strings.Join(strings.Fields(read(t, "features/issuance-and-cas.md")), " "))
	if strings.Contains(issuance, "localstack-proven") {
		t.Error("issuance-and-cas.md must not turn an unexecuted LocalStack configuration into acceptance proof")
	}
	for _, want := range []string{"all six managed-key backends", "faithful vendor-protocol emulators", "cgo hsm signer artifact"} {
		if !strings.Contains(issuance, want) {
			t.Errorf("issuance-and-cas.md must keep hardware-custody qualification %q", want)
		}
	}

	readme := strings.ToLower(strings.Join(strings.Fields(read(t, "../README.md")), " "))
	for _, want := range []string{"not localstack conformance evidence", "six served census rows come from the gate's"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README demo text must keep LocalStack qualification %q", want)
		}
	}
}

func TestReadmeCapabilitiesSeparateInventoryFromServedBackends(t *testing.T) {
	manifest, census := liveDoDCensus(t)
	type count struct{ inventory, served int }
	counts := map[string]count{}
	for _, entry := range manifest.Entries {
		if !entry.Inventory {
			continue
		}
		c := counts[entry.Capability]
		c.inventory++
		if censusEntryClaimable(census.Entries[entry.ID]) {
			c.served++
		}
		counts[entry.Capability] = c
	}

	wantInventory := map[string]int{
		"connector":      24,
		"external_ca":    14,
		"dynamic_secret": 8,
		"secret_sync":    8,
		"hsm_kms":        6,
	}
	labels := map[string]string{
		"connector":      "Deployment connectors",
		"external_ca":    "CA integrations",
		"dynamic_secret": "Dynamic-secret backends",
		"secret_sync":    "Secret-sync targets",
		"hsm_kms":        "HSM/KMS backends",
	}
	readme := read(t, "../README.md")
	for capability, inventory := range wantInventory {
		got := counts[capability]
		if got.inventory != inventory {
			t.Errorf("DoD manifest %s inventory=%d, code-backed advertised inventory=%d", capability, got.inventory, inventory)
		}
		marker := labels[capability] + ": **" + strconv.Itoa(inventory) + " inventory / " + strconv.Itoa(got.served) + " served in the shipped binary**"
		if !strings.Contains(readme, marker) {
			t.Errorf("README capabilities must show the live inventory/runtime split %q", marker)
		}
	}

	for _, stale := range []string{
		"**7** dynamic-secret backends",
		"secret sync (**7** targets)",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("README keeps stale integration count %q; code and DoD manifest have 8", stale)
		}
	}
}

func TestReadmeCapabilityInventoryCountsMatchCode(t *testing.T) {
	connectorEntries, err := os.ReadDir(filepath.FromSlash("../internal/connector"))
	if err != nil {
		t.Fatal(err)
	}
	connectors := 0
	for _, entry := range connectorEntries {
		if entry.IsDir() && entry.Name() != "example" {
			connectors++
		}
	}
	if connectors != 24 {
		t.Fatalf("connector package inventory=%d, want 24", connectors)
	}

	dynamicSource := read(t, "../internal/dynsecret/providers.go")
	providerConstructor := regexp.MustCompile(`(?m)^func New(Postgres|MySQL|Mongo|AWSIAM|GCPIAM|AzureEntra|Kubernetes|Redis)Provider\(`)
	if got := len(providerConstructor.FindAllString(dynamicSource, -1)); got != 8 {
		t.Fatalf("dynamic-secret implementation inventory=%d, want 8", got)
	}
	if got := len(secretsync.ProviderCatalog()); got != 8 {
		t.Fatalf("secret-sync provider catalog inventory=%d, want 8", got)
	}

	kmsEntries, err := os.ReadDir(filepath.FromSlash("../internal/kms"))
	if err != nil {
		t.Fatal(err)
	}
	kms := 0
	for _, entry := range kmsEntries {
		if entry.IsDir() {
			kms++
		}
	}
	if kms != 6 {
		t.Fatalf("HSM/KMS package inventory=%d, want 6", kms)
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
		"embedded/iot enrollment renewal",
	} {
		if strings.Contains(roadmapText, stale) {
			t.Errorf("README Roadmap must replace stale broad binary-wiring wording %q with exact residuals from limitations.md", stale)
		}
	}
	for _, want := range []string{
		"cursor pagination and list virtualization",
		"terraform cloud/opentofu and arbitrary webhook secret-sync targets",
		"vault kv outbound sync",
		"kmip appliance profiles/wrapping",
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
