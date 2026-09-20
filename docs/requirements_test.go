// SPDX-License-Identifier: BUSL-1.1

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
	GAServedScope      string   `json:"ga_served_scope"`
	GAScopeReason      string   `json:"ga_scope_reason"`
	SourceDocs         []string `json:"source_docs"`
}

type featureMapRequirementScope struct {
	Items []struct {
		FeatureID     string `json:"feature_id"`
		Feature       string `json:"feature"`
		ServedState   string `json:"served_state"`
		GAServedScope string `json:"ga_served_scope"`
		GAScopeReason string `json:"ga_scope_reason"`
	} `json:"items"`
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
	featureScope := loadFeatureRequirementScopes(t)

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
		checkRequirementGAScope(t, item, featureScope[item.RequirementID])
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

func loadFeatureRequirementScopes(t *testing.T) map[string]struct {
	Feature       string
	ServedState   string
	GAServedScope string
	GAScopeReason string
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash("../internal/featureparity/feature-map-backlog.json"))
	if err != nil {
		t.Fatalf("feature-map backlog is missing: %v", err)
	}
	var parsed featureMapRequirementScope
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse feature-map backlog: %v", err)
	}
	out := map[string]struct {
		Feature       string
		ServedState   string
		GAServedScope string
		GAScopeReason string
	}{}
	for _, item := range parsed.Items {
		scope := strings.TrimSpace(item.GAServedScope)
		if scope == "" {
			scope = "in_ga"
		}
		out[item.FeatureID] = struct {
			Feature       string
			ServedState   string
			GAServedScope string
			GAScopeReason string
		}{
			Feature:       item.Feature,
			ServedState:   item.ServedState,
			GAServedScope: scope,
			GAScopeReason: strings.TrimSpace(item.GAScopeReason),
		}
	}
	return out
}

func checkRequirementGAScope(t *testing.T, item normalizedRequirement, scope struct {
	Feature       string
	ServedState   string
	GAServedScope string
	GAScopeReason string
}) {
	t.Helper()
	if scope.Feature == "" {
		t.Errorf("%s has no feature-map row for GA served-scope comparison", item.RequirementID)
		return
	}
	if item.ServedState != scope.ServedState {
		t.Errorf("%s served_state=%q must match feature-map served_state=%q", item.RequirementID, item.ServedState, scope.ServedState)
	}
	gotScope := strings.TrimSpace(item.GAServedScope)
	gotReason := strings.TrimSpace(item.GAScopeReason)
	switch item.ServedState {
	case "served":
		if gotScope != "" && gotScope != "in_ga" {
			t.Errorf("%s served requirement must be in GA scope, got ga_served_scope=%q", item.RequirementID, item.GAServedScope)
		}
		if gotReason != "" {
			t.Errorf("%s served requirement must not carry a residual GA reason, got %q", item.RequirementID, item.GAScopeReason)
		}
	default:
		if gotScope != "out_of_ga" {
			t.Errorf("%s residual requirement served_state=%s must export ga_served_scope=out_of_ga, got %q", item.RequirementID, item.ServedState, item.GAServedScope)
		}
		if gotScope != scope.GAServedScope {
			t.Errorf("%s requirement ga_served_scope=%q must match feature-map scope %q", item.RequirementID, gotScope, scope.GAServedScope)
		}
		if gotReason == "" || !strings.Contains(strings.ToLower(gotReason), "residual") {
			t.Errorf("%s residual requirement must export a human-readable residual ga_scope_reason, got %q", item.RequirementID, item.GAScopeReason)
		}
		if gotReason != scope.GAScopeReason {
			t.Errorf("%s requirement ga_scope_reason must match feature-map residual reason", item.RequirementID)
		}
	}
}
