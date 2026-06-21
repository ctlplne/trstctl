package docs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDependencyFreshnessSLOHasReportAndOwnerQueue(t *testing.T) {
	var report struct {
		SchemaVersion int    `json:"schema_version"`
		ObservedAt    string `json:"observed_at"`
		MaxReportAge  int    `json:"max_report_age_days"`
		FreshnessSLOs []struct {
			Class      string `json:"class"`
			Owner      string `json:"owner"`
			MaxAgeDays int    `json:"max_age_days"`
		} `json:"freshness_slos"`
		TrackedUpgrades []struct {
			Ecosystem             string `json:"ecosystem"`
			Name                  string `json:"name"`
			CurrentVersion        string `json:"current_version"`
			LatestObservedVersion string `json:"latest_observed_version"`
			UpdateType            string `json:"update_type"`
			Owner                 string `json:"owner"`
			Status                string `json:"status"`
			NextReviewBy          string `json:"next_review_by"`
			DeferralUntil         string `json:"deferral_until"`
			Rationale             string `json:"rationale"`
		} `json:"tracked_upgrades"`
	}
	if err := json.Unmarshal([]byte(read(t, "../deploy/supply-chain/dependency-freshness.json")), &report); err != nil {
		t.Fatalf("parse dependency freshness report: %v", err)
	}
	if report.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", report.SchemaVersion)
	}
	if _, err := time.Parse(time.DateOnly, report.ObservedAt); err != nil {
		t.Fatalf("observed_at must be YYYY-MM-DD: %v", err)
	}
	if report.MaxReportAge <= 0 || report.MaxReportAge > 45 {
		t.Fatalf("max_report_age_days = %d, want a positive fail-closed age budget no larger than 45 days", report.MaxReportAge)
	}

	sloClasses := map[string]bool{}
	for _, slo := range report.FreshnessSLOs {
		if slo.Class == "" || slo.Owner == "" || slo.MaxAgeDays <= 0 {
			t.Fatalf("freshness SLO rows must carry class, owner, and positive max_age_days: %+v", slo)
		}
		sloClasses[slo.Class] = true
	}
	for _, want := range []string{"critical-go-runtime", "web-runtime", "developer-tooling", "release-infrastructure"} {
		if !sloClasses[want] {
			t.Errorf("dependency freshness report missing SLO class %q", want)
		}
	}

	tracked := map[string]bool{}
	for _, upgrade := range report.TrackedUpgrades {
		tracked[upgrade.Name] = true
		for field, value := range map[string]string{
			"ecosystem":               upgrade.Ecosystem,
			"current_version":         upgrade.CurrentVersion,
			"latest_observed_version": upgrade.LatestObservedVersion,
			"update_type":             upgrade.UpdateType,
			"owner":                   upgrade.Owner,
			"status":                  upgrade.Status,
			"next_review_by":          upgrade.NextReviewBy,
			"rationale":               upgrade.Rationale,
		} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("tracked upgrade %q has empty %s", upgrade.Name, field)
			}
		}
		if _, err := time.Parse(time.DateOnly, upgrade.NextReviewBy); err != nil {
			t.Fatalf("tracked upgrade %q next_review_by must be YYYY-MM-DD: %v", upgrade.Name, err)
		}
		if upgrade.Status == "accepted_deferral" {
			if _, err := time.Parse(time.DateOnly, upgrade.DeferralUntil); err != nil {
				t.Fatalf("tracked upgrade %q accepted_deferral must include deferral_until YYYY-MM-DD: %v", upgrade.Name, err)
			}
		}
	}
	for _, want := range []string{
		"github.com/fergusstrange/embedded-postgres",
		"github.com/nats-io/nats-server/v2",
		"github.com/open-policy-agent/opa",
		"github.com/tetratelabs/wazero",
		"github.com/jackc/pgx/v5",
		"google.golang.org/grpc",
		"react",
		"react-dom",
		"react-router-dom",
		"vite",
		"vitest",
		"tailwindcss",
		"typescript",
	} {
		if !tracked[want] {
			t.Errorf("dependency freshness report missing tracked upgrade %q", want)
		}
	}
}

func TestDependencyFreshnessGateIsWiredSeparatelyFromVulnerabilityScanning(t *testing.T) {
	makefile := read(t, "../Makefile")
	for _, want := range []string{
		"dependency-freshness:",
		"node scripts/ci/check-dependency-freshness.mjs",
		"supply-chain: sbom sca dependency-freshness",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile missing dependency freshness gate wiring %q", want)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"Dependency freshness SLO",
		"node scripts/ci/check-dependency-freshness.mjs",
		"Generate module SBOM",
		"Verify & scan the embedded-postgres binary",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing dependency freshness or separate SCA wiring %q", want)
		}
	}

	supplyChain := read(t, "../docs/supply-chain.md")
	for _, want := range []string{
		"Dependency freshness SLO",
		"deploy/supply-chain/dependency-freshness.json",
		"go list -m -u all",
		"npm outdated --json",
		"govulncheck",
		"npm audit",
	} {
		if !strings.Contains(supplyChain, want) {
			t.Errorf("docs/supply-chain.md missing dependency freshness evidence %q", want)
		}
	}
}
