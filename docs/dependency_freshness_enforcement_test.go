// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// CODE-109: the dependency freshness SLO has to be enforcement, not documentation.
//
// deploy/supply-chain/dependency-freshness.json declares a max_age_days per class.
// The checker used to shape-check that number and then discard it, so a dependency
// could sit arbitrarily far behind and stay "compliant" as long as next_review_by
// kept being rolled forward. These guards run the real
// scripts/ci/check-dependency-freshness.mjs against mutated copies of the committed
// report -- fed on stdin, so the tracked file is never written -- and prove that the
// budget actually fails a build, that the timestamp the budget needs cannot be
// dropped to escape it, and that neither an expired deferral nor a status relabel
// carries an over-budget row.

// runFreshnessChecker feeds report to the committed checker on stdin and reports its
// combined output and whether it exited non-zero.
func runFreshnessChecker(t *testing.T, report []byte) (string, bool) {
	t.Helper()
	cmd := exec.Command("node", "../scripts/ci/check-dependency-freshness.mjs", "-")
	cmd.Stdin = bytes.NewReader(report)
	out, err := cmd.CombinedOutput()
	return string(out), err != nil
}

// mutateFreshnessReport returns the committed report with exactly one tracked upgrade
// row rewritten by mutate. mutate returns true for the row it changed; requiring
// exactly one match keeps a renamed dependency from silently turning these guards into
// assertions about an unmodified report.
func mutateFreshnessReport(t *testing.T, mutate func(row map[string]any) bool) []byte {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(read(t, "../deploy/supply-chain/dependency-freshness.json")), &report); err != nil {
		t.Fatalf("CODE-109: parse dependency freshness report: %v", err)
	}
	rows, ok := report["tracked_upgrades"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatal("CODE-109: dependency freshness report has no tracked_upgrades")
	}
	changed := 0
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("CODE-109: tracked_upgrades row is not an object: %T", raw)
		}
		if mutate(row) {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("CODE-109: expected to rewrite exactly 1 tracked upgrade, rewrote %d", changed)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("CODE-109: re-encode dependency freshness report: %v", err)
	}
	return body
}

// TestDependencyFreshnessCheckerAcceptsTheCommittedReport is the control for the three
// negative guards below: it proves the stdin path and the committed report are healthy,
// so a later failure is caused by the mutation and not by the harness.
func TestDependencyFreshnessCheckerAcceptsTheCommittedReport(t *testing.T) {
	out, failed := runFreshnessChecker(t, []byte(read(t, "../deploy/supply-chain/dependency-freshness.json")))
	if failed {
		t.Fatalf("CODE-109: the committed dependency freshness report must pass its own checker:\n%s", out)
	}
}

// TestDependencyFreshnessFailsWhenBehindSinceExceedsTheClassBudget is the core CODE-109
// assertion: max_age_days must be able to fail a build. OPA is in critical-go-runtime,
// whose declared budget is 45 days, so a row 60 days behind has to be rejected.
func TestDependencyFreshnessFailsWhenBehindSinceExceedsTheClassBudget(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -60).Format(time.DateOnly)
	body := mutateFreshnessReport(t, func(row map[string]any) bool {
		if row["name"] != "github.com/open-policy-agent/opa" {
			return false
		}
		row["behind_since"] = stale
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-109: a critical-go-runtime dependency behind since %s (60 days against a 45-day budget) must fail the gate, got success:\n%s", stale, out)
	}
	if !strings.Contains(out, "45-day critical-go-runtime budget") {
		t.Errorf("CODE-109: the failure must name the class budget that was exceeded, got:\n%s", out)
	}
}

// TestDependencyFreshnessRejectsANonCurrentRowWithNoBehindSince closes the obvious
// evasion: if the age is measured from behind_since, then omitting behind_since must be
// a hard failure rather than an unmeasurable row that passes.
func TestDependencyFreshnessRejectsANonCurrentRowWithNoBehindSince(t *testing.T) {
	body := mutateFreshnessReport(t, func(row map[string]any) bool {
		if row["name"] != "github.com/open-policy-agent/opa" {
			return false
		}
		if row["status"] == "current" {
			t.Fatalf("CODE-109: this guard assumes the OPA row is not yet current, status=%v", row["status"])
		}
		delete(row, "behind_since")
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-109: omitting behind_since must not be a way past the age budget, got success:\n%s", out)
	}
	if !strings.Contains(out, "must record behind_since") {
		t.Errorf("CODE-109: the failure must name the missing behind_since field, got:\n%s", out)
	}
}

// TestDependencyFreshnessRejectsAnExpiredDeferralOnAnOverBudgetRow pins the one escape
// hatch shut: an accepted_deferral may carry a row past its budget only while its
// deferral_until still covers today.
func TestDependencyFreshnessRejectsAnExpiredDeferralOnAnOverBudgetRow(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -400).Format(time.DateOnly)
	expired := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	body := mutateFreshnessReport(t, func(row map[string]any) bool {
		if row["name"] != "react" {
			return false
		}
		row["status"] = "accepted_deferral"
		row["behind_since"] = stale
		row["deferral_until"] = expired
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-109: an expired deferral must not silently carry an over-budget dependency, got success:\n%s", out)
	}
	if !strings.Contains(out, "does not cover today") {
		t.Errorf("CODE-109: the failure must say the deferral no longer covers today, got:\n%s", out)
	}
}

// TestDependencyFreshnessCannotBeEvadedByRelabellingAnExpiredDeferral covers the other
// half of that escape hatch: relabelling an over-budget row away from accepted_deferral
// removes the deferral check, so the age check has to catch it instead.
func TestDependencyFreshnessCannotBeEvadedByRelabellingAnExpiredDeferral(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -400).Format(time.DateOnly)
	body := mutateFreshnessReport(t, func(row map[string]any) bool {
		if row["name"] != "react" {
			return false
		}
		row["status"] = "planned"
		row["behind_since"] = stale
		row["deferral_until"] = ""
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-109: relabelling an over-budget deferral as planned must still fail, got success:\n%s", out)
	}
	if !strings.Contains(out, "record status accepted_deferral with a dated deferral_until") {
		t.Errorf("CODE-109: the failure must point at the dated-deferral escape hatch, got:\n%s", out)
	}
}
