package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type normalizedRequirements struct {
	SourcePRD string                  `json:"source_prd"`
	Items     []normalizedRequirement `json:"items"`
}

type normalizedRequirement struct {
	RequirementID      string   `json:"requirement_id"`
	RequirementText    string   `json:"requirement_text"`
	Owner              string   `json:"owner"`
	Priority           string   `json:"priority"`
	AcceptanceCriteria string   `json:"acceptance_criteria"`
	Status             string   `json:"status"`
	ServedState        string   `json:"served_state"`
	BackendStatus      string   `json:"backend_status"`
	SourceDocs         []string `json:"source_docs"`
}

func TestCanonicalRequirementsExportCoversFeatureCatalog(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("requirements.normalized.json"))
	if err != nil {
		t.Fatalf("canonical normalized requirements export is missing: %v", err)
	}
	var reqs normalizedRequirements
	if err := json.Unmarshal(raw, &reqs); err != nil {
		t.Fatalf("parse requirements.normalized.json: %v", err)
	}
	if reqs.SourcePRD == "" {
		t.Fatal("requirements.normalized.json must name the source PRD/export")
	}

	validStatus := map[string]bool{
		"served": true, "conditional": true, "partial": true, "library": true, "roadmap": true,
	}
	byID := map[string]normalizedRequirement{}
	for _, item := range reqs.Items {
		if item.RequirementID == "" || item.RequirementText == "" || item.Owner == "" || item.Priority == "" || item.AcceptanceCriteria == "" || item.Status == "" {
			t.Fatalf("requirements export row has blank required metadata: %+v", item)
		}
		if !strings.Contains(item.RequirementText, item.RequirementID) && !strings.HasPrefix(item.RequirementText, "trstctl shall provide ") {
			t.Errorf("%s requirement_text should be a normative product requirement, got %q", item.RequirementID, item.RequirementText)
		}
		if item.Status != item.ServedState {
			t.Errorf("%s status %q must mirror served_state %q", item.RequirementID, item.Status, item.ServedState)
		}
		if !validStatus[item.Status] {
			t.Errorf("%s has invalid status %q", item.RequirementID, item.Status)
		}
		if item.BackendStatus == "" {
			t.Errorf("%s missing backend_status evidence", item.RequirementID)
		}
		if _, ok := byID[item.RequirementID]; ok {
			t.Fatalf("duplicate requirement_id %s", item.RequirementID)
		}
		byID[item.RequirementID] = item
	}

	for _, ft := range featureCatalog(t) {
		item := byID[ft.id]
		if item.RequirementID == "" {
			t.Errorf("feature catalog row %s (%s) has no normalized requirement row", ft.id, ft.title)
			continue
		}
		if !strings.Contains(item.RequirementText, ft.title) {
			t.Errorf("%s requirement_text %q does not include feature title %q", ft.id, item.RequirementText, ft.title)
		}
	}
	if len(byID) != len(featureCatalog(t)) {
		t.Fatalf("requirements denominator = %d, features.tsv denominator = %d", len(byID), len(featureCatalog(t)))
	}
}
