// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Catalog struct {
	SchemaVersion     int             `json:"schema_version"`
	Items             []Item          `json:"items"`
	CanonicalTools    []CanonicalTool `json:"canonical_tools"`
	MaturityValues    []Maturity      `json:"maturity_values"`
	StageStatusValues []StageStatus   `json:"stage_status_values"`
}

type Item struct {
	FeatureID       string               `json:"feature_id"`
	Feature         string               `json:"feature"`
	ServedState     string               `json:"served_state"`
	GAServedScope   string               `json:"ga_served_scope,omitempty"`
	GAScopeReason   string               `json:"ga_scope_reason,omitempty"`
	DoDCapabilities []string             `json:"dod_capabilities,omitempty"`
	DoDResiduals    map[string]string    `json:"dod_residuals,omitempty"`
	BackendStatus   string               `json:"backend_status"`
	CurrentMapping  string               `json:"current_frontend_mapping"`
	TargetMapping   string               `json:"target_gui_mapping"`
	AcceptanceTest  string               `json:"acceptance_test"`
	SourceDocs      []string             `json:"source_docs"`
	SourceBackend   []string             `json:"source_backend"`
	SourceFrontend  []string             `json:"source_frontend"`
	APISurface      []string             `json:"api_surface"`
	APINA           string               `json:"api_na"`
	CLISurface      []string             `json:"cli_surface"`
	CLINA           string               `json:"cli_na"`
	FacetEvidence   FeatureFacetEvidence `json:"facet_evidence"`
	Contract        CapabilityContract   `json:"contract"`
}

type FeatureFacetEvidence struct {
	Served    FacetCell `json:"served"`
	UI        FacetCell `json:"ui"`
	CLI       FacetCell `json:"cli"`
	API       FacetCell `json:"api"`
	Test      FacetCell `json:"test"`
	Docs      FacetCell `json:"docs"`
	RBAC      FacetCell `json:"rbac"`
	Audit     FacetCell `json:"audit"`
	Telemetry FacetCell `json:"telemetry"`
	A11y      FacetCell `json:"a11y"`
	I18n      FacetCell `json:"i18n"`
}

type FacetCell struct {
	Evidence []string `json:"evidence,omitempty"`
	Refs     []string `json:"refs,omitempty"`
	Commands []string `json:"commands,omitempty"`
	NA       string   `json:"na,omitempty"`
}

func (f FeatureFacetEvidence) Cells() map[string]FacetCell {
	return map[string]FacetCell{
		"served":    f.Served,
		"ui":        f.UI,
		"cli":       f.CLI,
		"api":       f.API,
		"test":      f.Test,
		"docs":      f.Docs,
		"rbac":      f.RBAC,
		"audit":     f.Audit,
		"telemetry": f.Telemetry,
		"a11y":      f.A11y,
		"i18n":      f.I18n,
	}
}

func Load() (Catalog, error) {
	root, err := repoRoot()
	if err != nil {
		return Catalog{}, err
	}
	b, err := os.ReadFile(filepath.Join(root, "internal", "featureparity", "feature-map-backlog.json")) // #nosec G304 -- fixed repo-relative catalog path read by tools and tests (CWE-22)
	if err != nil {
		return Catalog{}, fmt.Errorf("read feature-map backlog: %w", err)
	}
	var catalog Catalog
	if err := json.Unmarshal(b, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("parse feature-map backlog: %w", err)
	}
	if len(catalog.Items) != 79 {
		return Catalog{}, fmt.Errorf("feature-map backlog rows = %d, want 79", len(catalog.Items))
	}
	if err := ValidateCatalog(catalog); err != nil {
		return Catalog{}, fmt.Errorf("validate canonical capability contracts: %w", err)
	}
	if err := validateEvidencePaths(root, catalog); err != nil {
		return Catalog{}, fmt.Errorf("validate canonical capability evidence paths: %w", err)
	}
	return catalog, nil
}

func validateEvidencePaths(root string, catalog Catalog) error {
	for _, item := range catalog.Items {
		for stageName, stage := range item.Contract.Stages.Cells() {
			for _, evidence := range stage.Evidence {
				if !isRepositoryEvidencePath(evidence) {
					continue
				}
				clean := filepath.Clean(evidence)
				rel, err := filepath.Rel(root, filepath.Join(root, clean))
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fmt.Errorf("%s stage %s evidence path %q escapes the repository", item.FeatureID, stageName, evidence)
				}
				if _, err := os.Stat(filepath.Join(root, clean)); err != nil {
					return fmt.Errorf("%s stage %s evidence path %q: %w", item.FeatureID, stageName, evidence, err)
				}
			}
		}
	}
	return nil
}

func isRepositoryEvidencePath(value string) bool {
	for _, prefix := range []string{"clients/", "cmd/", "deploy/", "docs/", "ee/", "internal/", "scripts/", "tools/", "web/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repository root containing go.mod")
		}
		dir = parent
	}
}
