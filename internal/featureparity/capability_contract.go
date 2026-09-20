// SPDX-License-Identifier: BUSL-1.1

package featureparity

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// CanonicalTool is the operator's stable mental model. Platform & Integrations
// supports the six product tools without pretending to be a seventh credential
// lifecycle product.
type CanonicalTool string

const (
	ToolDiscover             CanonicalTool = "discover"
	ToolCertificates         CanonicalTool = "certificates"
	ToolWorkloadsMachines    CanonicalTool = "workloads_machines"
	ToolSecrets              CanonicalTool = "secrets"
	ToolSoftwareTrust        CanonicalTool = "software_trust"
	ToolOperations           CanonicalTool = "operations"
	ToolPlatformIntegrations CanonicalTool = "platform_integrations"
)

type CapabilityClassification string

const (
	CapabilityPrimary    CapabilityClassification = "primary"
	CapabilitySupporting CapabilityClassification = "supporting"
)

type Maturity string

const (
	MaturityAbsent                Maturity = "absent"
	MaturityAPICLIOnly            Maturity = "api_cli_only"
	MaturityObserveOnly           Maturity = "observe_only"
	MaturityPartialWorkflow       Maturity = "partial_workflow"
	MaturityCompleteVerticalSlice Maturity = "complete_vertical_slice"
)

type StageStatus string

const (
	StageComplete           StageStatus = "complete"
	StageNotApplicable      StageStatus = "not_applicable"
	StageIntentionalAPIOnly StageStatus = "intentional_api_only"
	StageBlocked            StageStatus = "blocked"
	StageMissing            StageStatus = "missing"
)

// StageRecord is deliberately small. Complete stages cite proof; every other
// state explains why the stage is absent and what boundary the operator sees.
type StageRecord struct {
	Status   StageStatus `json:"status"`
	Reason   string      `json:"reason,omitempty"`
	Evidence []string    `json:"evidence,omitempty"`
}

type StageSet struct {
	Discover   StageRecord `json:"discover"`
	Understand StageRecord `json:"understand"`
	Configure  StageRecord `json:"configure"`
	Preview    StageRecord `json:"preview"`
	Execute    StageRecord `json:"execute"`
	Observe    StageRecord `json:"observe"`
	Recover    StageRecord `json:"recover"`
	Verify     StageRecord `json:"verify"`
	Automate   StageRecord `json:"automate"`
}

func (s StageSet) Cells() map[string]StageRecord {
	return map[string]StageRecord{
		"discover": s.Discover, "understand": s.Understand,
		"configure": s.Configure, "preview": s.Preview,
		"execute": s.Execute, "observe": s.Observe,
		"recover": s.Recover, "verify": s.Verify,
		"automate": s.Automate,
	}
}

type CapabilityContract struct {
	Purpose               string                   `json:"purpose"`
	Tool                  CanonicalTool            `json:"tool"`
	Classification        CapabilityClassification `json:"classification"`
	ReleaseBlocking       bool                     `json:"release_blocking"`
	ConsoleRoute          string                   `json:"console_route"`
	NavigationEntrypoints []string                 `json:"navigation_entrypoints"`
	PermissionAuthority   string                   `json:"permission_authority"`
	Edition               string                   `json:"edition"`
	Dependencies          []string                 `json:"dependencies"`
	SideEffects           string                   `json:"side_effects"`
	SecretDataHandling    string                   `json:"secret_data_handling"`
	Maturity              Maturity                 `json:"maturity"`
	Stages                StageSet                 `json:"stages"`
	Owner                 string                   `json:"owner"`
	TargetCheckpoint      string                   `json:"target_checkpoint"`
	CandidateSHA          string                   `json:"candidate_sha"`
	Freshness             string                   `json:"freshness"`
}

var exactCandidateSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func ComputeMaturity(stages StageSet) Maturity {
	cells := stages.Cells()
	complete := 0
	hasGap := false
	intentionalAPI := 0
	for _, cell := range cells {
		switch cell.Status {
		case StageComplete:
			complete++
		case StageNotApplicable:
			// An explained non-applicable stage is not a product gap.
		case StageIntentionalAPIOnly:
			intentionalAPI++
			hasGap = true
		case StageMissing, StageBlocked, "":
			hasGap = true
		default:
			hasGap = true
		}
	}
	if complete == 0 {
		return MaturityAbsent
	}
	if !hasGap {
		return MaturityCompleteVerticalSlice
	}
	if stages.Automate.Status == StageComplete && intentionalAPI > 0 &&
		stages.Discover.Status != StageComplete && stages.Understand.Status != StageComplete &&
		stages.Configure.Status != StageComplete && stages.Preview.Status != StageComplete &&
		stages.Execute.Status != StageComplete && stages.Observe.Status != StageComplete &&
		stages.Recover.Status != StageComplete && stages.Verify.Status != StageComplete {
		return MaturityAPICLIOnly
	}
	if stages.Discover.Status == StageComplete && stages.Understand.Status == StageComplete &&
		stages.Observe.Status == StageComplete && stages.Configure.Status != StageComplete &&
		stages.Execute.Status != StageComplete {
		return MaturityObserveOnly
	}
	return MaturityPartialWorkflow
}

func ValidateCatalog(catalog Catalog) error {
	if catalog.SchemaVersion != 3 {
		return fmt.Errorf("schema_version=%d, want 3", catalog.SchemaVersion)
	}
	wantTools := []CanonicalTool{ToolDiscover, ToolCertificates, ToolWorkloadsMachines, ToolSecrets, ToolSoftwareTrust, ToolOperations, ToolPlatformIntegrations}
	if !slices.Equal(catalog.CanonicalTools, wantTools) {
		return fmt.Errorf("canonical_tools=%q, want %q", catalog.CanonicalTools, wantTools)
	}
	wantMaturity := []Maturity{MaturityAbsent, MaturityAPICLIOnly, MaturityObserveOnly, MaturityPartialWorkflow, MaturityCompleteVerticalSlice}
	if !slices.Equal(catalog.MaturityValues, wantMaturity) {
		return fmt.Errorf("maturity_values=%q, want %q", catalog.MaturityValues, wantMaturity)
	}
	wantStageStatus := []StageStatus{StageComplete, StageNotApplicable, StageIntentionalAPIOnly, StageBlocked, StageMissing}
	if !slices.Equal(catalog.StageStatusValues, wantStageStatus) {
		return fmt.Errorf("stage_status_values=%q, want %q", catalog.StageStatusValues, wantStageStatus)
	}
	seen := make(map[string]bool, len(catalog.Items))
	for _, item := range catalog.Items {
		if seen[item.FeatureID] {
			return fmt.Errorf("duplicate feature_id %q", item.FeatureID)
		}
		seen[item.FeatureID] = true
		if err := ValidateCapabilityContract(item); err != nil {
			return fmt.Errorf("%s (%s): %w", item.FeatureID, item.Feature, err)
		}
	}
	return nil
}

func ValidateCapabilityContract(item Item) error {
	c := item.Contract
	if strings.TrimSpace(c.Purpose) == "" {
		return fmt.Errorf("purpose is empty")
	}
	if !validTool(c.Tool) {
		return fmt.Errorf("invalid canonical tool %q", c.Tool)
	}
	if c.Classification != CapabilityPrimary && c.Classification != CapabilitySupporting {
		return fmt.Errorf("invalid classification %q", c.Classification)
	}
	if !strings.HasPrefix(c.ConsoleRoute, "/") {
		return fmt.Errorf("console_route %q is not an absolute product route", c.ConsoleRoute)
	}
	if len(nonBlankCopy(c.NavigationEntrypoints)) == 0 {
		return fmt.Errorf("navigation_entrypoints are empty")
	}
	for field, value := range map[string]string{
		"permission_authority": c.PermissionAuthority,
		"edition":              c.Edition,
		"side_effects":         c.SideEffects,
		"secret_data_handling": c.SecretDataHandling,
		"owner":                c.Owner,
		"target_checkpoint":    c.TargetCheckpoint,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is empty", field)
		}
	}
	if c.SideEffects != "read_only" && c.SideEffects != "mutating" && c.SideEffects != "mixed" {
		return fmt.Errorf("invalid side_effects %q", c.SideEffects)
	}
	if !exactCandidateSHA.MatchString(c.CandidateSHA) {
		return fmt.Errorf("candidate_sha %q is not an exact 40-character lowercase SHA", c.CandidateSHA)
	}
	if _, err := time.Parse("2006-01-02", c.Freshness); err != nil {
		return fmt.Errorf("freshness %q is not YYYY-MM-DD", c.Freshness)
	}

	validStatus := map[StageStatus]bool{
		StageComplete: true, StageNotApplicable: true, StageIntentionalAPIOnly: true,
		StageBlocked: true, StageMissing: true,
	}
	for name, stage := range c.Stages.Cells() {
		if !validStatus[stage.Status] {
			return fmt.Errorf("invalid stage status %q for %s", stage.Status, name)
		}
		if stage.Status == StageComplete {
			if len(nonBlankCopy(stage.Evidence)) == 0 {
				return fmt.Errorf("complete stage %s has no evidence", name)
			}
			if isOperationalStage(name) && onlyNavigationEvidence(stage.Evidence) {
				return fmt.Errorf("complete operational stage %s relies only on the route registry instead of workflow evidence", name)
			}
			if strings.TrimSpace(stage.Reason) != "" {
				return fmt.Errorf("complete stage %s also declares a reason", name)
			}
		} else {
			if strings.TrimSpace(stage.Reason) == "" {
				return fmt.Errorf("stage %s status %s has no reason", name, stage.Status)
			}
			if len(nonBlankCopy(stage.Evidence)) > 0 {
				return fmt.Errorf("incomplete stage %s also claims completion evidence", name)
			}
		}
	}
	if c.Classification == CapabilityPrimary {
		for _, name := range []string{"discover", "understand", "configure", "preview", "execute", "observe", "recover", "verify"} {
			if c.Stages.Cells()[name].Status == StageIntentionalAPIOnly {
				return fmt.Errorf("primary stage %s cannot be intentional_api_only", name)
			}
		}
	}
	computed := ComputeMaturity(c.Stages)
	if c.Maturity != computed {
		return fmt.Errorf("maturity %q contradicts computed maturity %q", c.Maturity, computed)
	}
	wantReleaseBlocking := c.Classification == CapabilityPrimary && computed != MaturityCompleteVerticalSlice
	if c.ReleaseBlocking != wantReleaseBlocking {
		return fmt.Errorf("release_blocking=%t contradicts classification=%q maturity=%q", c.ReleaseBlocking, c.Classification, computed)
	}
	return nil
}

func isOperationalStage(name string) bool {
	switch name {
	case "configure", "preview", "execute", "recover", "verify", "automate":
		return true
	default:
		return false
	}
}

func onlyNavigationEvidence(evidence []string) bool {
	nonBlank := nonBlankCopy(evidence)
	if len(nonBlank) == 0 {
		return false
	}
	for _, value := range nonBlank {
		if value != "web/src/lib/navigation.ts" {
			return false
		}
	}
	return true
}

func validTool(tool CanonicalTool) bool {
	switch tool {
	case ToolDiscover, ToolCertificates, ToolWorkloadsMachines, ToolSecrets,
		ToolSoftwareTrust, ToolOperations, ToolPlatformIntegrations:
		return true
	default:
		return false
	}
}

func nonBlankCopy(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
