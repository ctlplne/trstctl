// SPDX-License-Identifier: BUSL-1.1

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
	RequiredPullRequestReviews *struct {
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
	"perf live / served hot-path load gate": "scheduled/manual-only served-load verifier; too load-sensitive for shared per-PR runners. Promoted to required by the per-PR 'scheduled gates / nightly freshness' check",
	"web storybook (workbench build)":       "advisory component-workbench build (S-C8): it verifies the stories compile against real tokens, and stays non-blocking while story coverage matures so a workbench regression cannot hold product merges",
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
	// Review requirements are conditional on there being someone to review.
	//
	// trstctl has one maintainer, and GitHub does not let an author approve their
	// own pull request, so requiring an approving review made main unmergeable by
	// the only person who can merge to it. The original policy also named a
	// @ctlplne/security TEAM that does not exist, so require_code_owner_reviews
	// could not have resolved even with a second person.
	//
	// This guard therefore does not demand reviews unconditionally — a requirement
	// nobody can satisfy is not a control, it is a gate that gets routed around.
	// It demands that ONE of the two coherent states holds, so the file can never
	// drift into "reviews disabled and nothing replacing them":
	//
	//   (a) reviews are required, with a code-owner review and >= 1 approval; or
	//   (b) reviews are explicitly null AND the compensating controls are real —
	//       enforce_admins binds the owner to every required check, and the
	//       required-context set is non-empty, so CI is the review.
	//
	// Restore (a) the day a second maintainer exists.
	if bp.RequiredPullRequestReviews == nil {
		if !bp.EnforceAdmins {
			t.Error("branch-protection.json waives pull-request reviews but does not set enforce_admins; " +
				"with neither, nothing binds the maintainer to the gate at all")
		}
		if len(bp.RequiredStatusChecks.Contexts) == 0 {
			t.Error("branch-protection.json waives pull-request reviews but requires no status checks; " +
				"CI is the compensating control for a single maintainer, so it cannot also be empty")
		}
	} else {
		if !bp.RequiredPullRequestReviews.RequireCodeOwnerReviews {
			t.Error("branch-protection.json requires reviews but not code-owner reviews (so the root of trust gets a security review)")
		}
		if bp.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1 {
			t.Error("branch-protection.json requires reviews but sets no approving-review count")
		}
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
		"definition of done / wiring census":  "compiled + assembled + non-sentinel served capabilities must block merge (DOD-GATE-001)",
		"chaos (fault injection)":             "make chaos must block merge (RESIL-003)",
		"fuzz (smoke per-PR, deeper nightly)": "fuzz smoke/nightly parser safety net must block merge (FUZZ-003)",
		"fips-capable build (GOFIPS140)":      "FIPS-capable build must block merge (PKIGOV-007)",
		"web e2e (three-browser live routes)": "the supported-browser route matrix must block merge (S-C4)",
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

// TestScheduledAndReleaseGatePromotionsAreRequired is the OPS-CI-101..107
// acceptance: core decommission integration and conformance remain in the
// required build/test/lint job (OPS-CI-103/104), reproducible-check gates
// every PR as its own required job (OPS-CI-102), perf-live runs on the nightly
// schedule (OPS-CI-101), and the scheduled-only verifiers (captured soak, spine
// burst, live branch-protection drift, perf live) are promoted to REQUIRED via
// the per-PR "scheduled gates / nightly freshness" check, which fails closed
// when the latest scheduled run is missing, stale, red, or silently skipped a
// promoted job (OPS-CI-105/106/107).
func TestScheduledAndReleaseGatePromotionsAreRequired(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"go test -tags integration ./internal/decommission/intwire/... -count=1 -timeout=10m",
		"go test -tags integration ./internal/decommission/conformance/... -count=1 -timeout=12m",
		"name: reproducible build (byte-identical rebuild)",
		"run: make reproducible-check",
		"name: perf live / served hot-path load gate",
		"run: make perf-live",
		"name: scheduled gates / nightly freshness",
		"run: scripts/ci/verify-scheduled-gates.sh",
		"bash scripts/ci/verify-scheduled-gates_selftest.sh",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml must contain %q (OPS-CI-101..107 gate promotion)", want)
		}
	}
	policy := read(t, "../.github/branch-protection.json")
	for _, want := range []string{
		`"reproducible build (byte-identical rebuild)"`,
		`"scheduled gates / nightly freshness"`,
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("branch-protection.json must require %s (OPS-CI-101..107)", want)
		}
	}
	freshness := read(t, "../scripts/ci/verify-scheduled-gates.sh")
	for _, want := range []string{
		"captured soak / leak gate",
		"spine burst / replay-outbox gate",
		"branch protection / live policy drift",
		"perf live / served hot-path load gate",
		"TRSTCTL_SCHEDULED_GATES_MAX_AGE_HOURS",
	} {
		if !strings.Contains(freshness, want) {
			t.Fatalf("verify-scheduled-gates.sh must enforce %q (OPS-CI-105/106/107)", want)
		}
	}
}

func TestSPIREContainerE2EGateIsRequired(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"name: spire container e2e",
		"TRSTCTL_RUN_SPIRE_E2E: \"1\"",
		"go test -tags e2e -count=1 -v ./test/e2e/spire/...",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml must contain %q so ENGHEALTH-001 cannot regress to a documented-but-unrun SPIRE container proof", want)
		}
	}

	requiredPolicy := read(t, "../.github/branch-protection.json")
	if !strings.Contains(requiredPolicy, `"spire container e2e"`) {
		t.Fatal("branch-protection.json must require the spire container e2e check (ENGHEALTH-001)")
	}
	if !strings.Contains(read(t, "branch-protection.md"), "`spire container e2e`") {
		t.Fatal("branch-protection.md must document the spire container e2e required check (ENGHEALTH-001)")
	}
}

// TestPQCDodproofGateIsRequired locks A0.3f: the PQC census proofs (pure
// ML-DSA-65 EST enrollment with stock OpenSSL, the two-entry hybrid SVID
// response, and the CBOM→migration TLS rollout) run in CI on every push and
// stay in the required-check set, so "PQC issuance is proven" can never
// regress to a locally-invoked build tag nobody runs.
func TestPQCDodproofGateIsRequired(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"name: pqc e2e (dodproof)",
		"pqc_end_to_end.pure_mldsa_leaf_stock_clients",
		"pqc_end_to_end.multikey_spiffe_hybrid_svid",
		"pqc_end_to_end.automated_rollout_tls_findings",
		`DOD_CAPABILITY="${capability_id}"`,
		"ML-DSA-65",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml must contain %q so the PQC census proofs cannot regress to a documented-but-unrun claim (A0.3f)", want)
		}
	}
	if strings.Contains(ci, "go test -tags trstctl_dodproof") {
		t.Fatal("ci.yml bypasses the parent DoD gate and runs a proof test without its signed expectation envelope")
	}

	requiredPolicy := read(t, "../.github/branch-protection.json")
	if !strings.Contains(requiredPolicy, `"pqc e2e (dodproof)"`) {
		t.Fatal("branch-protection.json must require the pqc e2e (dodproof) check (A0.3f)")
	}
	if !strings.Contains(read(t, "branch-protection.md"), "`pqc e2e (dodproof)`") {
		t.Fatal("branch-protection.md must document the pqc e2e (dodproof) required check (A0.3f)")
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
		if !strings.Contains(body, "needs: [test, required-checks, release-evidence]") {
			t.Errorf("publishing job %s must need release-local tests, required-checks preflight, and chaos release evidence (TEST-003/RUNOPS-007)", job)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	if !strings.Contains(ci, "bash scripts/ci/verify-required-checks_selftest.sh") {
		t.Error("ci.yml must self-test the required-check verifier so the release preflight cannot silently weaken")
	}
}

func TestReleasePublishesChaosEvidence(t *testing.T) {
	release := read(t, "../.github/workflows/release.yml")
	for _, want := range []string{
		"release-evidence:",
		"name: release evidence / chaos",
		"needs: [test, required-checks]",
		"command=make vuln",
		"command=bash scripts/ci/npm-audit-dependency-surfaces.sh",
		"command=make chaos",
		"make chaos 2>&1 | tee -a \"$evidence\"",
		"name: release-chaos-evidence",
		"path: dist/release-evidence/trstctl-chaos-evidence.txt",
		"name: release-npm-audit-evidence",
		"path: dist/release-evidence/npm-audit-dependency-surfaces.json",
		"if-no-files-found: error",
		"gh release upload \"$GITHUB_REF_NAME\" dist/release-evidence/trstctl-chaos-evidence.txt --clobber",
		"gh release upload \"$GITHUB_REF_NAME\" dist/release-evidence/npm-audit-dependency-surfaces.json --clobber",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release.yml must contain %q so RUNOPS-007 chaos output is published with each GA candidate", want)
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
		if !strings.Contains(body, "needs: [test, required-checks, release-evidence]") {
			t.Errorf("publishing job %s must wait for release-local chaos evidence before emitting GA candidate artifacts (RUNOPS-007)", job)
		}
	}

	doc := read(t, "branch-protection.md")
	for _, want := range []string{
		"`release-evidence` runs `make chaos`",
		"`release-chaos-evidence`",
		"`trstctl-chaos-evidence.txt`",
		"`npm-audit-dependency-surfaces.json`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("branch-protection.md must document %q for RUNOPS-007 release evidence", want)
		}
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
		"TRSTCTL_BRANCH_PROTECTION_RECEIPT: ${{ runner.temp }}/branch-protection-drift-receipt.json",
		"run: scripts/ci/verify-branch-protection.sh",
		"name: Upload live branch-protection drift receipt",
		"name: branch-protection-live-drift-receipt",
		"path: ${{ runner.temp }}/branch-protection-drift-receipt.json",
		"if-no-files-found: error",
		"bash scripts/ci/verify-branch-protection_selftest.sh",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml must contain %q so TEST-001 live branch protection drift is watched", want)
		}
	}

	body := read(t, "branch-protection.md")
	for _, want := range []string{
		"branch protection / live policy drift",
		"branch-protection-live-drift-receipt",
		"branch-protection-drift-receipt.json",
		"scripts/ci/verify-branch-protection.sh",
		"TRSTCTL_BRANCH_PROTECTION_READ_TOKEN",
		"TEST-001",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("branch-protection.md must document %q for TEST-001 live enforcement evidence", want)
		}
	}
}
