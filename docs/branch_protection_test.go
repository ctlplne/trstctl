package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// branchProtection mirrors the fields of .github/branch-protection.json this test
// asserts on (TEST-006). Only the fields under test are modeled.
type branchProtection struct {
	RequiredStatusChecks struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
	} `json:"required_status_checks"`
	EnforceAdmins              bool `json:"enforce_admins"`
	RequiredPullRequestReviews struct {
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	} `json:"required_pull_request_reviews"`
	RequiredLinearHistory bool `json:"required_linear_history"`
	AllowForcePushes      bool `json:"allow_force_pushes"`
	AllowDeletions        bool `json:"allow_deletions"`
}

// jobNameRe extracts the `name:` of each workflow job. We read names rather than job
// keys because GitHub reports the `name:` as the status-check context.
var jobNameRe = regexp.MustCompile(`(?m)^    name:\s*(.+?)\s*$`)

// workflowJobNames returns the set of job `name:` values declared in a workflow file
// that have a fixed (non-matrix-templated) name. A name containing `${{` is a
// build-matrix template (e.g. CodeQL's `analyze (${{ matrix.language }})`) whose
// real check name is only known at runtime; those are excluded from the required
// set by design, so this helper skips them.
func workflowJobNames(t *testing.T, rel string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	out := map[string]bool{}
	for _, m := range jobNameRe.FindAllStringSubmatch(string(b), -1) {
		name := strings.Trim(m[1], `"'`)
		if strings.Contains(name, "${{") {
			continue // matrix-templated name; not pinned by literal
		}
		out[name] = true
	}
	return out
}

// branchProtectionExemptCIJobs names fixed CI/security jobs that intentionally do
// not block pull-request merges. Every exemption needs a reason so a new job cannot
// silently become "runs but does not protect main" by omission.
var branchProtectionExemptCIJobs = map[string]string{
	"branch protection / live policy drift": "scheduled/manual-only drift verifier; it audits the live GitHub branch-protection settings outside the PR path",
	"captured soak / leak gate":             "scheduled/manual-only endurance verifier; it publishes captured soak trend evidence outside the PR path and cannot be required on pull_request",
	"spine burst / replay-outbox gate":      "scheduled/manual-only event-spine capacity verifier; it boots embedded datastores, publishes replay/outbox trend evidence, and cannot be required on pull_request",
}

// TestBranchProtectionMatchesCIJobs is the TEST-006 reality-test for the codified
// branch protection: .github/branch-protection.json exists, sets the safety flags
// the policy promises (enforce-admins, code-owner reviews, linear history, no
// force-push/delete, strict + ≥1 review), and — critically — every required status
// check it lists corresponds to a REAL CI/security job name. This binds the required
// set to the workflows so a renamed or removed job cannot silently fall out of the
// "blocks merge" gate (turning a real check into theater), and a typo in the list
// cannot pin a check that never runs (which GitHub would treat as forever-pending).
// It also checks the other direction: every fixed-name CI/security job must either
// be required or have an explicit exemption with a reason.
func TestBranchProtectionMatchesCIJobs(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("../.github/branch-protection.json"))
	if err != nil {
		t.Fatalf("a codified branch-protection policy must exist at .github/branch-protection.json (TEST-006): %v", err)
	}
	var bp branchProtection
	if err := json.Unmarshal(raw, &bp); err != nil {
		t.Fatalf(".github/branch-protection.json is not valid JSON: %v", err)
	}

	// (1) The safety flags the policy doc promises must actually be set.
	if !bp.EnforceAdmins {
		t.Error("branch-protection.json must set enforce_admins (maintainers are bound by the gate too)")
	}
	if !bp.RequiredPullRequestReviews.RequireCodeOwnerReviews {
		t.Error("branch-protection.json must require code-owner reviews (so the root of trust gets a security review)")
	}
	if bp.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1 {
		t.Error("branch-protection.json must require at least one approving review")
	}
	if !bp.RequiredLinearHistory {
		t.Error("branch-protection.json must require linear history")
	}
	if bp.AllowForcePushes {
		t.Error("branch-protection.json must NOT allow force-pushes (history cannot be rewritten under protection)")
	}
	if bp.AllowDeletions {
		t.Error("branch-protection.json must NOT allow branch deletion")
	}
	if !bp.RequiredStatusChecks.Strict {
		t.Error("branch-protection.json should require branches to be up to date (strict)")
	}
	if len(bp.RequiredStatusChecks.Contexts) == 0 {
		t.Fatal("branch-protection.json lists no required status checks")
	}

	// (2) Every required check must be a real, fixed-name CI/security job, and
	// every fixed-name CI/security job must either be required or explicitly
	// exempted with a reason.
	known := map[string]string{}
	for _, wf := range []string{"../.github/workflows/ci.yml", "../.github/workflows/security.yml"} {
		for name := range workflowJobNames(t, wf) {
			known[name] = wf
		}
	}
	seenRequired := map[string]bool{}
	for _, ctx := range bp.RequiredStatusChecks.Contexts {
		seenRequired[ctx] = true
		if known[ctx] == "" {
			t.Errorf("required check %q in branch-protection.json matches no CI/security job name — a renamed/removed job, or a typo, would make the gate ineffective (TEST-006)", ctx)
		}
	}
	for name, wf := range known {
		if seenRequired[name] {
			continue
		}
		if reason := strings.TrimSpace(branchProtectionExemptCIJobs[name]); reason != "" {
			continue
		}
		t.Errorf("CI/security job %q from %s is neither required in branch-protection.json nor explicitly exempted — a real gate would run without blocking merge (TEST-004)", name, wf)
	}
	for name, reason := range branchProtectionExemptCIJobs {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("branch-protection exemption for %q must include a reason", name)
		}
		if known[name] == "" {
			t.Errorf("branch-protection exemption %q matches no fixed CI/security job name", name)
		}
	}

	docBody := read(t, "branch-protection.md")
	for _, ctx := range bp.RequiredStatusChecks.Contexts {
		if !strings.Contains(docBody, "`"+ctx+"`") {
			t.Errorf("branch-protection.md must document required check %q so the human policy stays in sync with branch-protection.json", ctx)
		}
	}

	// (3) The headline CI gate (build/test/lint, which runs make test + the
	// architecture linter), chaos, fuzz, and FIPS gates MUST be required — they
	// are the floor the audit rests on for normal regression, resilience
	// regression, parser hardening, and FIPS-capable builds.
	requiredGates := map[string]string{
		"build / test / lint":                 "make test + trstctllint must block merge",
		"chaos (fault injection)":             "make chaos must block merge (RESIL-003)",
		"fuzz (smoke per-PR, deeper nightly)": "fuzz smoke/nightly parser safety net must block merge (FUZZ-003)",
		"fips-capable build (GOFIPS140)":      "FIPS-capable build must block merge (PKIGOV-007)",
	}
	for gate, why := range requiredGates {
		if !seenRequired[gate] {
			t.Errorf("branch-protection.json must require the %q check (%s)", gate, why)
		}
	}
}

// TestChaosGateExecutesFaultMatrix is the RESIL-003 reality test: the required
// GitHub Actions check must literally run `make chaos`, the make target must run
// the chaos-tagged tests, and the committed fault matrix must still name the fault
// directions the audit required. That means deleting a chaos scenario or removing
// the CI step fails locally, before branch protection becomes theater.
func TestChaosGateExecutesFaultMatrix(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{"name: chaos (fault injection)", "run: make chaos"} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml must contain %q for the RESIL-003 chaos gate", want)
		}
	}

	makefile := read(t, "../Makefile")
	for _, want := range []string{"chaos:", "-tags=chaos", "-run '^TestChaos'", "./internal/orchestrator/...", "./internal/signing/..."} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("Makefile chaos target must contain %q (RESIL-003)", want)
		}
	}

	matrix := read(t, "../internal/orchestrator/chaos_test.go") + "\n" + read(t, "../internal/signing/chaos_test.go")
	for _, want := range []string{
		"signer-sigkill-mid-issue",
		"nats-restart-partition",
		"postgres-failover-mid-transaction",
		"disk-full-store",
		"restore-interruption",
		"memory-pressure",
	} {
		if !strings.Contains(matrix, want) {
			t.Fatalf("chaos fault matrix no longer names %q (RESIL-003)", want)
		}
	}
}

// TestBranchProtectionDocExistsAndLinked keeps the human-readable policy present and
// discoverable: docs/branch-protection.md exists, documents the codified gate, and
// is linked from the supply-chain page so a reviewer finds it.
func TestBranchProtectionDocExistsAndLinked(t *testing.T) {
	body := read(t, "branch-protection.md")
	low := strings.ToLower(body)
	for _, want := range []string{"required status checks", "enforce_admins", "codeowners", "branch-protection.json", "code-owner"} {
		if !strings.Contains(low, strings.ToLower(want)) {
			t.Errorf("branch-protection.md should document %q", want)
		}
	}
	// It cites the TEST-006 finding so the doc is traceable to why it exists.
	if !strings.Contains(body, "TEST-006") {
		t.Error("branch-protection.md should cite TEST-006 (the finding it closes)")
	}
	// Discoverable from supply-chain.md (the related process page).
	if !strings.Contains(read(t, "supply-chain.md"), "branch-protection.md") {
		t.Error("supply-chain.md should link to the branch-protection policy so it is discoverable")
	}
}

func TestReleaseRequiresRequiredCheckPreflight(t *testing.T) {
	release := read(t, "../.github/workflows/release.yml")
	for _, want := range []string{
		"required-checks:",
		"name: required checks / live CI preflight",
		"checks: read",
		"statuses: read",
		"TRSTCTL_REQUIRED_CHECKS_ATTEMPTS",
		"run: scripts/ci/verify-required-checks.sh",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release.yml must contain %q so TEST-003 release publishing checks the full required CI/security surface", want)
		}
	}

	for _, job := range []string{"image:", "agent-windows:", "helm-chart:"} {
		start := strings.Index(release, "\n  "+job)
		if start < 0 {
			t.Fatalf("release.yml is missing publishing job %s", job)
		}
		body := release[start+1:]
		if next := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:`).FindAllStringIndex(body, 2); len(next) == 2 {
			body = body[:next[1][0]]
		}
		if !strings.Contains(body, "needs: [test, required-checks]") {
			t.Errorf("publishing job %s must need both release-local tests and required-checks preflight (TEST-003)", job)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	if !strings.Contains(ci, "bash scripts/ci/verify-required-checks_selftest.sh") {
		t.Error("ci.yml must self-test the required-check verifier so the release preflight cannot silently weaken")
	}
}

func TestBranchProtectionDriftCheckIsScheduled(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"workflow_dispatch:",
		"branch-protection-drift:",
		"name: branch protection / live policy drift",
		"if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
		"secrets.TRSTCTL_BRANCH_PROTECTION_READ_TOKEN || github.token",
		"run: scripts/ci/verify-branch-protection.sh",
		"bash scripts/ci/verify-branch-protection_selftest.sh",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml must contain %q so TEST-001 live branch protection drift is watched", want)
		}
	}

	body := read(t, "branch-protection.md")
	for _, want := range []string{
		"branch protection / live policy drift",
		"scripts/ci/verify-branch-protection.sh",
		"TRSTCTL_BRANCH_PROTECTION_READ_TOKEN",
		"TEST-001",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("branch-protection.md must document %q for TEST-001 live enforcement evidence", want)
		}
	}
}
