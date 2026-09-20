// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryClaimsMatchRequiredManifestShape(t *testing.T) {
	repo := filepath.Clean(filepath.Join("..", ".."))
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatalf("load repository manifest: %v", err)
	}
	report := Report{Entries: make(map[string]entryResult, len(manifest.Entries))}
	for _, entry := range manifest.Entries {
		status := statusUnknown
		if entry.Enforcement == enforcementRequired {
			status = statusServed
		}
		report.Entries[entry.ID] = entryResult{
			Capability: entry.Capability, Inventory: entry.Inventory != nil && *entry.Inventory,
			Enforcement: entry.Enforcement, Status: status,
		}
	}
	if err := validateFreshProductClaims(repo, manifest, report); err != nil {
		t.Fatalf("repository claims do not match the required/pending manifest shape: %v", err)
	}
}

func TestValidateProductClaimsAcceptsMatchingFreshCensus(t *testing.T) {
	manifest, report, ledger, readme, limitations := validProductClaimsFixture()
	if err := validateProductClaims(manifest, report, ledger, readme, limitations); err != nil {
		t.Fatalf("matching product claims rejected: %v", err)
	}
}

func TestValidateProductClaimsRejectsServedOverclaim(t *testing.T) {
	manifest, report, ledger, readme, limitations := validProductClaimsFixture()
	entry := report.Entries["connector.backend_01"]
	entry.Status = statusStub
	report.Entries["connector.backend_01"] = entry
	ledger.Items[0].ServedState = "served"

	err := validateProductClaims(manifest, report, ledger, readme, limitations)
	if err == nil || !strings.Contains(err.Error(), "claims served while fresh DoD census entry connector.backend_01 is status=stub enforcement=required") {
		t.Fatalf("served overclaim was not rejected by exact live row: %v", err)
	}
}

func TestValidateProductClaimsRejectsStaleResidual(t *testing.T) {
	manifest, report, ledger, readme, limitations := validProductClaimsFixture()
	ledger.Items[0].DoDResiduals = map[string]string{
		"connector": "This old residual has more than eight words but every exact row is now served.",
	}

	err := validateProductClaims(manifest, report, ledger, readme, limitations)
	if err == nil || !strings.Contains(err.Error(), "keeps stale connector census residual") {
		t.Fatalf("stale residual was not rejected: %v", err)
	}
}

func TestValidateProductClaimsRejectsReadmeCountMismatch(t *testing.T) {
	manifest, report, ledger, readme, limitations := validProductClaimsFixture()
	readme = strings.ReplaceAll(readme, "Deployment connectors: **24 inventory / 24 served through the production-assembled handler**", "Deployment connectors: **24 inventory / 23 served through the production-assembled handler**")

	err := validateProductClaims(manifest, report, ledger, readme, limitations)
	if err == nil || !strings.Contains(err.Error(), "README capabilities must show the fresh inventory/runtime split") {
		t.Fatalf("README live denominator mismatch was not rejected: %v", err)
	}
}

func TestValidateProductClaimsRejectsHSMDisclosureMismatch(t *testing.T) {
	manifest, report, ledger, readme, limitations := validProductClaimsFixture()
	limitations = strings.ReplaceAll(limitations, "fsync-backed journal", "memory-only state")

	err := validateProductClaims(manifest, report, ledger, readme, limitations)
	if err == nil || !strings.Contains(err.Error(), `served HSM/KMS custody spine (missing "fsync-backed journal")`) {
		t.Fatalf("HSM disclosure mismatch was not rejected: %v", err)
	}
}

func TestFocusedCensusDoesNotApplyFullDenominatorClaims(t *testing.T) {
	missingRepo := t.TempDir()
	for _, sel := range []selection{{Capability: "connector.nginx"}, {CardID: "WIRE-CONN-101"}} {
		if err := validateClaimsForSelection(missingRepo, Manifest{}, Report{}, sel); err != nil {
			t.Fatalf("focused selection %+v tried to load full-denominator claims: %v", sel, err)
		}
	}
	if err := validateClaimsForSelection(missingRepo, Manifest{}, Report{}, selection{}); err == nil || !strings.Contains(err.Error(), "read feature claims ledger") {
		t.Fatalf("unfocused census did not fail closed through the full claims validator: %v", err)
	}
}

func TestClaimsFailureStillWritesReceiptAndReturnsGateFailure(t *testing.T) {
	out := filepath.Join(t.TempDir(), "wiring-census.json")
	report := Report{SchemaVersion: 1, Entries: map[string]entryResult{}}
	var stdout, stderr bytes.Buffer
	code := finishCLIReport(out, report, selection{}, fmt.Errorf("deliberate claims mismatch"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("claims mismatch exit=%d, want ordinary gate failure 1: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("claims mismatch did not preserve the fresh census receipt: %v", err)
	}
	if !strings.Contains(stderr.String(), "product claims do not match the fresh wiring census: deliberate claims mismatch") {
		t.Fatalf("claims mismatch diagnostic missing: %q", stderr.String())
	}
}

func validProductClaimsFixture() (Manifest, Report, featureClaimsLedger, string, string) {
	type inventorySpec struct {
		capability string
		label      string
		count      int
		mode       string
	}
	specs := []inventorySpec{
		{capability: "connector", label: "Deployment connectors", count: 24, mode: runtimeModeAssembledHandler},
		{capability: "dynamic_secret", label: "Dynamic-secret backends", count: 8, mode: runtimeModeAssembledHandler},
		{capability: "external_ca", label: "CA integrations", count: 14, mode: runtimeModeAssembledHandler},
		{capability: "hsm_kms", label: "HSM/KMS backends", count: 6, mode: runtimeModeLaunchedBinary},
		{capability: "secret_sync", label: "Secret-sync targets", count: 10, mode: runtimeModeAssembledHandler},
	}
	manifest := Manifest{}
	report := Report{Entries: map[string]entryResult{}}
	ledger := featureClaimsLedger{}
	var readme strings.Builder
	for index, spec := range specs {
		ledger.Items = append(ledger.Items, featureClaim{
			FeatureID:       fmt.Sprintf("F%d", index+1),
			Feature:         spec.label,
			ServedState:     "conditional",
			DoDCapabilities: []string{spec.capability},
		})
		launched, assembled := 0, spec.count
		if spec.mode == runtimeModeLaunchedBinary {
			launched, assembled = spec.count, 0
		}
		_, _ = fmt.Fprintf(&readme, "%s: **%d inventory / %d %s**\n", spec.label, spec.count, spec.count, servedProofPhrase(launched, assembled))
		for backend := 1; backend <= spec.count; backend++ {
			id := fmt.Sprintf("%s.backend_%02d", spec.capability, backend)
			manifest.Entries = append(manifest.Entries, Entry{
				ID: id, Capability: spec.capability, Inventory: boolPtr(true), Enforcement: enforcementRequired,
				Runtime: RuntimeProof{Mode: spec.mode},
			})
			report.Entries[id] = entryResult{
				Capability: spec.capability, Inventory: true, Enforcement: enforcementRequired, Status: statusServed,
			}
		}
	}
	limitations := strings.Join([]string{
		"six of six backends served",
		"control-plane process does not construct a provider",
		"PostgreSQL outbox",
		"fsync-backed journal",
		"high-fidelity protocol emulation",
	}, ". ")
	return manifest, report, ledger, readme.String(), limitations
}
