// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	journeyCensusStart = "<!-- trstctl:journey-census:start -->"
	journeyCensusEnd   = "<!-- trstctl:journey-census:end -->"
)

type journeyRequirements struct {
	SchemaVersion int                           `json:"schema_version"`
	Source        string                        `json:"source"`
	Journeys      map[string]journeyRequirement `json:"journeys"`
}

type journeyRequirement struct {
	CensusRows   []string `json:"census_rows"`
	CoreSurfaces []string `json:"core_surfaces"`
}

type journeyServedSnapshot struct {
	SchemaVersion int                              `json:"schema_version"`
	Source        string                           `json:"source"`
	Summary       journeyCensusSummary             `json:"summary"`
	Journeys      map[string]journeyServedEvidence `json:"journeys"`
}

type journeyCensusSummary struct {
	Total           int `json:"total"`
	Served          int `json:"served"`
	Required        int `json:"required"`
	RequiredFailed  int `json:"required_failed"`
	LibraryOnly     int `json:"library_only"`
	Stub            int `json:"stub"`
	Unknown         int `json:"unknown"`
	Pending         int `json:"pending"`
	Inventory       int `json:"inventory"`
	InventoryServed int `json:"inventory_served"`
}

type journeyServedEvidence struct {
	CensusRows   []journeyServedRow `json:"census_rows"`
	CoreSurfaces []string           `json:"core_surfaces"`
	Status       string             `json:"status"`
}

type journeyServedRow struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Enforcement string `json:"enforcement"`
}

func decodeJourneyJSON(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func TestJourneyServedBadgesAreBoundToTheWiringCensus(t *testing.T) {
	var requirements journeyRequirements
	decodeJourneyJSON(t, "journeys/census-requirements.json", &requirements)
	var snapshot journeyServedSnapshot
	decodeJourneyJSON(t, "journeys/served-census.json", &snapshot)

	if requirements.SchemaVersion != 1 || snapshot.SchemaVersion != 1 || requirements.Source != "wiring-census.json" || snapshot.Source != requirements.Source {
		t.Fatal("journey requirements and generated evidence must use schema 1 sourced from wiring-census.json")
	}
	if snapshot.Summary.Total == 0 || snapshot.Summary.Served != snapshot.Summary.Total || snapshot.Summary.Required != snapshot.Summary.Total {
		t.Fatalf("served badge is not backed by a fully served required census: %+v", snapshot.Summary)
	}
	if snapshot.Summary.RequiredFailed != 0 || snapshot.Summary.LibraryOnly != 0 || snapshot.Summary.Stub != 0 || snapshot.Summary.Unknown != 0 || snapshot.Summary.Pending != 0 {
		t.Fatalf("served badge cannot hide a non-served census state: %+v", snapshot.Summary)
	}
	if snapshot.Summary.InventoryServed != snapshot.Summary.Inventory {
		t.Fatalf("served badge cannot hide unserved backend inventory: %+v", snapshot.Summary)
	}

	docs, err := filepath.Glob(filepath.FromSlash("journeys/*.md"))
	if err != nil {
		t.Fatalf("glob journey docs: %v", err)
	}
	docIDs := make([]string, 0, len(docs))
	for _, path := range docs {
		docIDs = append(docIDs, strings.TrimSuffix(filepath.Base(path), ".md"))
	}
	sort.Strings(docIDs)
	requirementIDs := sortedJourneyKeys(requirements.Journeys)
	servedIDs := sortedJourneyKeys(snapshot.Journeys)
	if !reflect.DeepEqual(docIDs, requirementIDs) || !reflect.DeepEqual(requirementIDs, servedIDs) {
		t.Fatalf("every journey doc must have exactly one requirements row and generated served record: docs=%v requirements=%v served=%v", docIDs, requirementIDs, servedIDs)
	}

	for _, journeyID := range requirementIDs {
		requirement := requirements.Journeys[journeyID]
		evidence := snapshot.Journeys[journeyID]
		if len(requirement.CensusRows) == 0 && len(requirement.CoreSurfaces) == 0 {
			t.Errorf("journey %s has no declared served surface", journeyID)
		}
		if evidence.Status != "served" || !reflect.DeepEqual(evidence.CoreSurfaces, requirement.CoreSurfaces) {
			t.Errorf("journey %s generated evidence drifted from its requirements", journeyID)
		}
		if len(evidence.CensusRows) != len(requirement.CensusRows) {
			t.Errorf("journey %s has %d required census rows but %d generated rows", journeyID, len(requirement.CensusRows), len(evidence.CensusRows))
			continue
		}
		for i, row := range evidence.CensusRows {
			if row.ID != requirement.CensusRows[i] || row.Status != "served" || row.Enforcement != "required" {
				t.Errorf("journey %s references an unusable census row: %+v", journeyID, row)
			}
		}

		page := read(t, "journeys/"+journeyID+".md")
		lowerPage := strings.ToLower(page)
		for _, forbidden := range []string{"library-only", "library code you drive", "agent/library connector", "not yet served", "not wired"} {
			if strings.Contains(lowerPage, forbidden) {
				t.Errorf("journey %s still sends a beginner toward stale non-served wording %q", journeyID, forbidden)
			}
		}
		if strings.Count(page, journeyCensusStart) != 1 || strings.Count(page, journeyCensusEnd) != 1 {
			t.Errorf("journey %s must render exactly one generated census badge", journeyID)
		}
		badge := "Served path — wiring census " + strconv.Itoa(snapshot.Summary.Served) + "/" + strconv.Itoa(snapshot.Summary.Total)
		if !strings.Contains(page, badge) || !strings.Contains(page, "generated from `wiring-census.json`") {
			t.Errorf("journey %s badge is not visibly sourced from the wiring census", journeyID)
		}
		for _, rowID := range requirement.CensusRows {
			if !strings.Contains(page, "`"+rowID+"`") {
				t.Errorf("journey %s badge omits census row %s", journeyID, rowID)
			}
		}
		for _, surface := range requirement.CoreSurfaces {
			if !strings.Contains(page, "`"+surface+"`") {
				t.Errorf("journey %s badge omits core surface %s", journeyID, surface)
			}
		}
	}
}

func TestJourneyServedBadgeGenerationRunsAfterFreshCensusInCI(t *testing.T) {
	workflow := read(t, "../.github/workflows/ci.yml")
	requireOrderedTokens(t, "dod-gate CI job", workflow,
		"- name: Run the shipped-binary Definition-of-Done census",
		"run: make dod-gate",
		"- name: Verify journey served badges against the fresh census",
		"run: make journey-census-check",
	)
}

func sortedJourneyKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
