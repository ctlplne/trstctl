// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	featureClaimsPath = "internal/featureparity/feature-map-backlog.json"
	readmeClaimsPath  = "README.md"
	hsmClaimsPath     = "docs/limitations.md"
)

type featureClaimsLedger struct {
	Items []featureClaim `json:"items"`
}

type featureClaim struct {
	FeatureID       string            `json:"feature_id"`
	Feature         string            `json:"feature"`
	ServedState     string            `json:"served_state"`
	DoDCapabilities []string          `json:"dod_capabilities,omitempty"`
	DoDResiduals    map[string]string `json:"dod_residuals,omitempty"`
}

type claimFailureSet struct {
	items []string
}

func (f *claimFailureSet) add(format string, args ...any) {
	f.items = append(f.items, fmt.Sprintf(format, args...))
}

func (f *claimFailureSet) err() error {
	if len(f.items) == 0 {
		return nil
	}
	sort.Strings(f.items)
	return fmt.Errorf("%s", strings.Join(f.items, "; "))
}

// validateClaimsForSelection is intentionally a no-op for an exact focused
// census. Such a report marks every unselected row UNKNOWN, so using it as a
// product-wide denominator would manufacture false disclosure failures. The
// mandatory unfocused make dod-gate path always reaches the full validator.
func validateClaimsForSelection(repo string, manifest Manifest, report Report, sel selection) error {
	if sel.Capability != "" || sel.CardID != "" {
		return nil
	}
	return validateFreshProductClaims(repo, manifest, report)
}

func validateFreshProductClaims(repo string, manifest Manifest, report Report) error {
	ledgerBytes, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(featureClaimsPath)))
	if err != nil {
		return fmt.Errorf("read feature claims ledger: %w", err)
	}
	var ledger featureClaimsLedger
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		return fmt.Errorf("parse feature claims ledger: %w", err)
	}
	if len(ledger.Items) == 0 {
		return fmt.Errorf("feature claims ledger has no items")
	}
	readme, err := os.ReadFile(filepath.Join(repo, readmeClaimsPath))
	if err != nil {
		return fmt.Errorf("read README capability claims: %w", err)
	}
	limitations, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(hsmClaimsPath)))
	if err != nil {
		return fmt.Errorf("read managed-key limitations claims: %w", err)
	}
	return validateProductClaims(manifest, report, ledger, string(readme), string(limitations))
}

// validateProductClaims is the pure honesty lock used by the full wiring
// census. Its report argument is the evaluator's fresh in-memory result, not a
// previously generated wiring-census.json file.
func validateProductClaims(manifest Manifest, report Report, ledger featureClaimsLedger, readme, limitations string) error {
	failures := &claimFailureSet{}
	manifestCapabilities := map[string][]string{}

	if len(report.Entries) != len(manifest.Entries) {
		failures.add("fresh DoD census entries=%d, manifest entries=%d", len(report.Entries), len(manifest.Entries))
	}
	for _, entry := range manifest.Entries {
		manifestCapabilities[entry.Capability] = append(manifestCapabilities[entry.Capability], entry.ID)
		got, ok := report.Entries[entry.ID]
		if !ok {
			failures.add("fresh DoD census is missing manifest entry %s", entry.ID)
			continue
		}
		if got.Capability != entry.Capability {
			failures.add("fresh DoD census entry %s capability=%q, manifest=%q", entry.ID, got.Capability, entry.Capability)
		}
		if got.Enforcement != entry.Enforcement {
			failures.add("fresh DoD census entry %s enforcement=%q, manifest=%q", entry.ID, got.Enforcement, entry.Enforcement)
		}
	}

	mappedCapabilities := map[string]bool{}
	for _, item := range ledger.Items {
		for _, capability := range item.DoDCapabilities {
			entryIDs, known := manifestCapabilities[capability]
			if !known {
				failures.add("%s maps unknown DoD capability %q", item.FeatureID, capability)
				continue
			}
			mappedCapabilities[capability] = true
			capabilityServed := len(entryIDs) > 0
			for _, id := range entryIDs {
				entry, ok := report.Entries[id]
				if !ok || !claimableCensusEntry(entry) {
					capabilityServed = false
					if item.ServedState == "served" {
						failures.add("%s (%s) claims served while fresh DoD census entry %s is status=%s enforcement=%s", item.FeatureID, item.Feature, id, entry.Status, entry.Enforcement)
					}
				}
			}
			residual := strings.TrimSpace(item.DoDResiduals[capability])
			if !capabilityServed && len(strings.Fields(residual)) < 8 {
				failures.add("%s (%s) must explain the non-served %s census residual, got %q", item.FeatureID, item.Feature, capability, residual)
			}
			if capabilityServed && item.ServedState == "library" {
				failures.add("%s (%s) is still library-only after every %s census entry became served", item.FeatureID, item.Feature, capability)
			}
			if capabilityServed && residual != "" {
				failures.add("%s (%s) keeps stale %s census residual after every entry became served: %q", item.FeatureID, item.Feature, capability, residual)
			}
		}
	}
	for capability := range manifestCapabilities {
		if !mappedCapabilities[capability] {
			failures.add("DoD capability %q has no feature-map row, so its census state cannot constrain product claims", capability)
		}
	}

	validateReadmeCensusClaims(failures, manifest, report, readme)
	validateHSMCensusClaims(failures, manifest, report, limitations)
	return failures.err()
}

func claimableCensusEntry(entry entryResult) bool {
	return entry.Status == statusServed && entry.Enforcement == enforcementRequired
}

func validateReadmeCensusClaims(failures *claimFailureSet, manifest Manifest, report Report, readme string) {
	wantInventory := map[string]int{
		"connector":      24,
		"external_ca":    14,
		"dynamic_secret": 8,
		"secret_sync":    10,
		"hsm_kms":        6,
	}
	labels := map[string]string{
		"connector":      "Deployment connectors",
		"external_ca":    "CA integrations",
		"dynamic_secret": "Dynamic-secret backends",
		"secret_sync":    "Secret-sync targets",
		"hsm_kms":        "HSM/KMS backends",
	}
	type count struct{ inventory, served int }
	counts := map[string]count{}
	for _, entry := range manifest.Entries {
		if entry.Inventory == nil || !*entry.Inventory {
			continue
		}
		capability := advertisedInventoryCapability(entry)
		current := counts[capability]
		current.inventory++
		if claimableCensusEntry(report.Entries[entry.ID]) {
			current.served++
		}
		counts[capability] = current
	}
	capabilities := make([]string, 0, len(wantInventory))
	for capability := range wantInventory {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	for _, capability := range capabilities {
		want := wantInventory[capability]
		got := counts[capability]
		if got.inventory != want {
			failures.add("DoD manifest %s inventory=%d, code-backed advertised inventory=%d", capability, got.inventory, want)
		}
		marker := labels[capability] + ": **" + strconv.Itoa(want) + " inventory / " + strconv.Itoa(got.served) + " served in the shipped binary**"
		if !strings.Contains(readme, marker) {
			failures.add("README capabilities must show the fresh inventory/runtime split %q", marker)
		}
	}
	for _, stale := range []string{"**7** dynamic-secret backends", "secret sync (**7** targets)"} {
		if strings.Contains(readme, stale) {
			failures.add("README keeps stale integration count %q; code and DoD manifest have 8", stale)
		}
	}
}

// advertisedInventoryCapability keeps public inventory counts tied to the one
// exact DoD row that proves each backend. The two sync backends completed by W2
// stay in the secrets_residuals family for card/family reporting, while still
// contributing to the advertised ten-target secret-sync inventory.
func advertisedInventoryCapability(entry Entry) string {
	switch entry.ID {
	case "secrets_residuals.terraform_opentofu_native_sync", "secrets_residuals.vault_kv_outbound_sync":
		return "secret_sync"
	default:
		return entry.Capability
	}
}

func validateHSMCensusClaims(failures *claimFailureSet, manifest Manifest, report Report, limitations string) {
	inventory, served := 0, 0
	for _, entry := range manifest.Entries {
		if entry.Capability != "hsm_kms" || entry.Inventory == nil || !*entry.Inventory {
			continue
		}
		inventory++
		if claimableCensusEntry(report.Entries[entry.ID]) {
			served++
		}
	}
	if inventory != 6 {
		failures.add("HSM/KMS census inventory=%d, want six advertised backends", inventory)
		return
	}
	low := strings.ToLower(strings.Join(strings.Fields(limitations), " "))
	if served < inventory {
		for _, marker := range []string{"/api/v1/managed-keys", "zero of six", "control-plane process constructs", "not production-assembled", "m-of-n"} {
			if !strings.Contains(low, marker) {
				failures.add("limitations.md must disclose the non-served HSM/KMS custody residual (missing %q)", marker)
			}
		}
		if strings.Contains(low, "hsm/kms-resident ca private keys are supported") {
			failures.add("limitations.md claims served HSM/KMS custody while the exact backend census is red")
		}
		return
	}
	if strings.Contains(low, "zero of six") {
		failures.add("limitations.md keeps stale zero-served HSM/KMS wording after every backend became served")
	}
	for _, marker := range []string{
		"six of six backends served",
		"control-plane process does not construct a provider",
		"postgresql outbox",
		"fsync-backed journal",
		"high-fidelity protocol emulation",
	} {
		if !strings.Contains(low, marker) {
			failures.add("limitations.md must describe the served HSM/KMS custody spine (missing %q)", marker)
		}
	}
}
