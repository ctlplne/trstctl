// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// CODE-111: the dependency freshness SLO has to be enforcement, not documentation.
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
		t.Fatalf("CODE-111: parse dependency freshness report: %v", err)
	}
	rows, ok := report["tracked_upgrades"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatal("CODE-111: dependency freshness report has no tracked_upgrades")
	}
	changed := 0
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("CODE-111: tracked_upgrades row is not an object: %T", raw)
		}
		if mutate(row) {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("CODE-111: expected to rewrite exactly 1 tracked upgrade, rewrote %d", changed)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("CODE-111: re-encode dependency freshness report: %v", err)
	}
	return body
}

// TestDependencyFreshnessCheckerAcceptsTheCommittedReport is the control for the three
// negative guards below: it proves the stdin path and the committed report are healthy,
// so a later failure is caused by the mutation and not by the harness.
func TestDependencyFreshnessCheckerAcceptsTheCommittedReport(t *testing.T) {
	out, failed := runFreshnessChecker(t, []byte(read(t, "../deploy/supply-chain/dependency-freshness.json")))
	if failed {
		t.Fatalf("CODE-111: the committed dependency freshness report must pass its own checker:\n%s", out)
	}
}

// TestDependencyFreshnessFailsWhenBehindSinceExceedsTheClassBudget is the core CODE-111
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
		t.Fatalf("CODE-111: a critical-go-runtime dependency behind since %s (60 days against a 45-day budget) must fail the gate, got success:\n%s", stale, out)
	}
	if !strings.Contains(out, "45-day critical-go-runtime budget") {
		t.Errorf("CODE-111: the failure must name the class budget that was exceeded, got:\n%s", out)
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
			t.Fatalf("CODE-111: this guard assumes the OPA row is not yet current, status=%v", row["status"])
		}
		delete(row, "behind_since")
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-111: omitting behind_since must not be a way past the age budget, got success:\n%s", out)
	}
	if !strings.Contains(out, "must record behind_since") {
		t.Errorf("CODE-111: the failure must name the missing behind_since field, got:\n%s", out)
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
		t.Fatalf("CODE-111: an expired deferral must not silently carry an over-budget dependency, got success:\n%s", out)
	}
	if !strings.Contains(out, "does not cover today") {
		t.Errorf("CODE-111: the failure must say the deferral no longer covers today, got:\n%s", out)
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
		t.Fatalf("CODE-111: relabelling an over-budget deferral as planned must still fail, got success:\n%s", out)
	}
	if !strings.Contains(out, "record status accepted_deferral with a dated deferral_until") {
		t.Errorf("CODE-111: the failure must point at the dated-deferral escape hatch, got:\n%s", out)
	}
}

// CODE-111: an age budget and a major-version gap are different debts, and the checker
// only measured the first. A row can sit well inside its class age budget and still be
// two majors behind -- exactly where the typescript row was, 5.9.3 against a published
// 7.0.2 in the 90-day developer-tooling class, while `make dependency-freshness` printed
// OK. These guards pin the gap cap: more than one major behind is allowed only while an
// accepted_deferral is live, so a multi-major pin stays a dated, argued decision.
//
// They assert on the checker's own failure text, which lives on single source lines in
// scripts/ci/check-dependency-freshness.mjs, rather than on prose in
// docs/security/dependency-freshness.md. No guarded phrase depends on how that Markdown
// happens to wrap.

// freshnessRow returns the committed report's tracked_upgrades row for name, so the
// guards below assert against the versions actually recorded instead of hard-coded
// strings that rot the moment the report is re-observed.
func freshnessRow(t *testing.T, name string) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(read(t, "../deploy/supply-chain/dependency-freshness.json")), &report); err != nil {
		t.Fatalf("CODE-111: parse dependency freshness report: %v", err)
	}
	rows, ok := report["tracked_upgrades"].([]any)
	if !ok {
		t.Fatal("CODE-111: dependency freshness report has no tracked_upgrades array")
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if ok && row["name"] == name {
			return row
		}
	}
	t.Fatalf("CODE-111: dependency freshness report has no %q row", name)
	return nil
}

// freshnessMajor parses the leading integer of a version field the same way the checker
// does, so these guards measure the gap rather than assume it.
func freshnessMajor(t *testing.T, row map[string]any, field string) int {
	t.Helper()
	value, _ := row[field].(string)
	head, _, ok := strings.Cut(strings.TrimPrefix(value, "v"), ".")
	if !ok {
		t.Fatalf("CODE-111: %s.%s = %q has no dotted major version", row["name"], field, value)
	}
	major, err := strconv.Atoi(head)
	if err != nil {
		t.Fatalf("CODE-111: %s.%s = %q has a non-numeric major version: %v", row["name"], field, value, err)
	}
	return major
}

// TestDependencyFreshnessTypescriptRowIsMoreThanOneMajorBehind is the premise the two
// guards below stand on. If TypeScript ever catches up this fails loudly rather than
// letting the gap-cap guards go quietly vacuous against a row with no gap left.
func TestDependencyFreshnessTypescriptRowIsMoreThanOneMajorBehind(t *testing.T) {
	row := freshnessRow(t, "typescript")
	gap := freshnessMajor(t, row, "latest_observed_version") - freshnessMajor(t, row, "current_version")
	if gap <= 1 {
		t.Fatalf("CODE-111: the typescript row is %d majors behind; the gap-cap guards below need a row more than one major behind -- re-point them at another row", gap)
	}
	if row["status"] != "accepted_deferral" {
		t.Fatalf("CODE-111: a row more than one major behind must carry status accepted_deferral, got %v", row["status"])
	}
	deferral, _ := row["deferral_until"].(string)
	until, err := time.Parse(time.DateOnly, deferral)
	if err != nil {
		t.Fatalf("CODE-111: the typescript deferral_until must be YYYY-MM-DD, got %q: %v", deferral, err)
	}
	today, err := time.Parse(time.DateOnly, time.Now().UTC().Format(time.DateOnly))
	if err != nil {
		t.Fatalf("CODE-111: parse today: %v", err)
	}
	if until.Before(today) {
		t.Fatalf("CODE-111: the typescript deferral_until %s no longer covers today; re-argue the multi-major pin in the row rationale or take the upgrade", deferral)
	}
	if !strings.Contains(fmt.Sprint(row["rationale"]), "6.0.3") {
		t.Errorf("CODE-111: a deferred multi-major row must name its intermediate hop in the rationale, got: %v", row["rationale"])
	}
}

// TestDependencyFreshnessFailsAMajorGapWithNoLiveDeferral is the core CODE-111 assertion.
// The age budget cannot catch this row -- typescript is developer-tooling, a 90-day
// class, and it is well inside that -- so only the gap cap can.
func TestDependencyFreshnessFailsAMajorGapWithNoLiveDeferral(t *testing.T) {
	row := freshnessRow(t, "typescript")
	gap := freshnessMajor(t, row, "latest_observed_version") - freshnessMajor(t, row, "current_version")
	body := mutateFreshnessReport(t, func(candidate map[string]any) bool {
		if candidate["name"] != "typescript" {
			return false
		}
		candidate["status"] = "planned"
		candidate["deferral_until"] = ""
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-111: a dependency %d majors behind with no live deferral must fail the gate, got success:\n%s", gap, out)
	}
	want := fmt.Sprintf("tracked upgrade typescript is %d majors behind (%v against %v), over the 1-major gap cap", gap, row["current_version"], row["latest_observed_version"])
	if !strings.Contains(out, want) {
		t.Errorf("CODE-111: the failure must name the major gap, both versions and the cap; want %q, got:\n%s", want, out)
	}
}

// TestDependencyFreshnessRejectsAnExpiredDeferralOnAMajorGap closes the same escape hatch
// the age budget already has shut: a deferral carries a multi-major pin only while it is
// live, so the pin has to be re-argued on a date rather than inherited forever.
func TestDependencyFreshnessRejectsAnExpiredDeferralOnAMajorGap(t *testing.T) {
	expired := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	row := freshnessRow(t, "typescript")
	gap := freshnessMajor(t, row, "latest_observed_version") - freshnessMajor(t, row, "current_version")
	body := mutateFreshnessReport(t, func(candidate map[string]any) bool {
		if candidate["name"] != "typescript" {
			return false
		}
		candidate["status"] = "accepted_deferral"
		candidate["deferral_until"] = expired
		return true
	})
	out, failed := runFreshnessChecker(t, body)
	if !failed {
		t.Fatalf("CODE-111: an expired deferral must not carry a %d-major gap, got success:\n%s", gap, out)
	}
	want := fmt.Sprintf("over the 1-major gap cap, and its deferral_until %s does not cover today", expired)
	if !strings.Contains(out, want) {
		t.Errorf("CODE-111: the failure must say the deferral no longer covers the major gap; want %q, got:\n%s", want, out)
	}
}
