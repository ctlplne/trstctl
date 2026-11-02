// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// makeTestLanes is the order `make test` runs its lanes in. CI runs the first four
// as parallel jobs (owner decision 2026-11-02: split the Go test jobs); the
// required umbrella check then runs the self-tests, the merged coverage floors and
// the live SLO report, in this order.
var makeTestLanes = []string{"test-selftests", "test-packages", "test-server", "test-extra", "coverage-gate", "test-live-slo"}

// ciUmbrellaCheck is the required check that the Go test lanes, and the gates
// split out of the old single job, block merge through; dodUmbrellaCheck is the
// one the Definition-of-Done census shards and self-tests block merge through.
const (
	ciUmbrellaCheck   = "build / test / lint"
	dodUmbrellaCheck  = "definition of done / wiring census"
	fuzzUmbrellaCheck = "fuzz (smoke per-PR, deeper nightly)"
)

var makeTestRecipeRe = regexp.MustCompile(`(?m)^test: ## Run all tests[^\n]*\n((?:\t[^\n]*\n)+)`)

func readCIWorkflow(t *testing.T) ciWorkflow {
	t.Helper()
	var wf ciWorkflow
	if err := yaml.Unmarshal([]byte(read(t, "../.github/workflows/ci.yml")), &wf); err != nil {
		t.Fatalf("parse .github/workflows/ci.yml: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("parsed no jobs out of ci.yml; the workflow shape changed, so revisit this guard")
	}
	return wf
}

// ciJobByName returns the job whose `name:` (its status-check context) is name.
func ciJobByName(wf ciWorkflow, name string) (string, ciJob, bool) {
	ids := make([]string, 0, len(wf.Jobs))
	for id := range wf.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if wf.Jobs[id].Name == name {
			return id, wf.Jobs[id], true
		}
	}
	return "", ciJob{}, false
}

// ciUmbrellaGatesOnNeeds reports whether step fails unless every job the umbrella
// needs succeeded: a failed, cancelled or skipped lane fails the required check.
func ciUmbrellaGatesOnNeeds(step ciStep) bool {
	return strings.TrimSpace(step.Env["RESULTS"]) == "${{ toJSON(needs) }}" &&
		strings.Contains(step.Run, `v["result"] != "success"`) &&
		strings.Contains(step.Run, "sys.exit(1 if bad else 0)")
}

// ciUmbrellaGate reports whether the umbrella has a needs gate that always runs:
// its first step, or a later step marked if: always() (so a failure earlier in
// the umbrella cannot skip it).
func ciUmbrellaGate(job ciJob) bool {
	for i, step := range job.Steps {
		if ciUmbrellaGatesOnNeeds(step) && (i == 0 || strings.TrimSpace(step.If) == "always()") {
			return true
		}
	}
	return false
}

// ciMatrixSize returns N when the job's matrix key is exactly [0, 1, ..., N-1].
func ciMatrixSize(t *testing.T, job ciJob, key string) int {
	t.Helper()
	values, ok := job.Strategy.Matrix[key].([]any)
	if !ok || len(values) == 0 {
		t.Fatalf("job %q matrix %q is not a list", job.Name, key)
	}
	for i, v := range values {
		if n, ok := v.(int); !ok || n != i {
			t.Fatalf("job %q matrix %q = %v, want exactly 0..%d", job.Name, key, values, len(values)-1)
		}
	}
	return len(values)
}

func ciJobRuns(job ciJob) string {
	var runs []string
	for _, step := range job.Steps {
		runs = append(runs, step.Run)
	}
	return strings.Join(runs, "\n")
}

// ciJobUploadsCoverage reports whether the job uploads an artifact named coverage-*
// (what the umbrella downloads and merges).
func ciJobUploadsCoverage(job ciJob) bool {
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && strings.HasPrefix(fmt.Sprint(step.With["name"]), "coverage-") &&
			fmt.Sprint(step.With["if-no-files-found"]) == "error" {
			return true
		}
	}
	return false
}

// TestMakeTestRunsEveryLaneInOrder pins `make test` as the lanes CI runs: a
// recipe of sequential sub-makes (safe under -j), each lane a documented target.
func TestMakeTestRunsEveryLaneInOrder(t *testing.T) {
	mk := read(t, "../Makefile")
	m := makeTestRecipeRe.FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("Makefile test target must be a documented recipe that runs the lanes in order")
	}
	var lanes []string
	for _, line := range strings.Split(strings.TrimRight(m[1], "\n"), "\n") {
		lane, ok := strings.CutPrefix(strings.TrimSpace(line), "@$(MAKE) --no-print-directory ")
		if !ok || strings.ContainsAny(lane, " ;&|$") {
			t.Fatalf("make test recipe line %q is not exactly one lane", line)
		}
		lanes = append(lanes, lane)
	}
	if !slices.Equal(lanes, makeTestLanes) {
		t.Fatalf("make test lanes = %v, want %v", lanes, makeTestLanes)
	}
	for _, lane := range makeTestLanes {
		if !strings.Contains(mk, "\n.PHONY: "+lane+"\n"+lane+": ## ") {
			t.Errorf("lane %s must be a documented .PHONY target", lane)
		}
	}
	if !strings.Contains(mk, "[ -n \"$$units\" ] || { echo \"FAIL: package shard $(TEST_SHARD) of $(TEST_SHARDS) selected no packages\"; exit 1; }") {
		t.Error("an empty package shard must fail rather than let go test fall back to the current directory")
	}
	for _, want := range []string{
		"for i in $$(seq 0 $$(( $(TEST_SHARDS) - 1 ))); do profiles=\"$$profiles $(COVERPROFILE_MAIN).$$i\"; done",
		"for f in $$profiles; do head -n 1 \"$$f\" | grep -qx 'mode: atomic' || { echo \"FAIL: coverage lane profile $$f is missing or not atomic\"; exit 1; }; done",
		"python3 scripts/ci/go-test-shard.py --shard 0 --shards $(TEST_SHARDS) --weights scripts/ci/go-test-weights.json --max-unit-seconds $(TEST_MAX_UNIT_SECONDS) --selftest",
		"PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/go-test-units_selftest.py",
	} {
		if !strings.Contains(mk, want) {
			t.Errorf("coverage-gate must merge every package shard and refuse a missing one: missing %q", want)
		}
	}
}

// TestCIRunsEveryTestLaneAndGatesOnAll binds the parallel CI lanes to `make test`:
// every package shard and server slice runs, each uploads its coverage, and the
// required umbrella check fails unless every lane succeeded, then enforces the
// floors over exactly those shards and slices and reports the live SLO after them.
func TestCIRunsEveryTestLaneAndGatesOnAll(t *testing.T) {
	wf := readCIWorkflow(t)
	packages, okPackages := wf.Jobs["go-test-packages"]
	server, okServer := wf.Jobs["go-test-server"]
	_, okExtra := wf.Jobs["go-test-extra"]
	if !okPackages || !okServer || !okExtra {
		t.Fatal("ci.yml must run the go-test-packages, go-test-server and go-test-extra lanes")
	}
	shards := ciMatrixSize(t, packages, "shard")
	slicesN := ciMatrixSize(t, server, "slice")
	for job, want := range map[string]string{
		"go-test-packages": fmt.Sprintf("make test-packages TEST_SHARD=${{ matrix.shard }} TEST_SHARDS=%d", shards),
		"go-test-server":   fmt.Sprintf("make test-server SERVER_SLICE=${{ matrix.slice }} SERVER_SLICES=%d SERVER_TEST_BINARY=", slicesN),
		"go-test-extra":    "make test-extra",
	} {
		if !strings.Contains(ciJobRuns(wf.Jobs[job]), want) {
			t.Errorf("CI lane %s must run %q", job, want)
		}
		if !ciJobUploadsCoverage(wf.Jobs[job]) {
			t.Errorf("CI lane %s must upload its coverage as a coverage-* artifact, failing when a file is missing", job)
		}
	}

	// Every server slice runs the one test binary the build job compiled.
	build, okBuild := wf.Jobs["go-test-server-build"]
	if !okBuild || !strings.Contains(ciJobRuns(build), "make server-test-binary SERVER_TEST_BINARY_OUT=server.test") ||
		!slices.Contains(server.Needs, "go-test-server-build") {
		t.Error("the server slices must need go-test-server-build, which builds the shared test binary")
	}
	uploaded, downloaded := false, false
	for _, step := range build.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && fmt.Sprint(step.With["name"]) == "server-test-binary" &&
			fmt.Sprint(step.With["if-no-files-found"]) == "error" {
			uploaded = true
		}
	}
	for _, step := range server.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") && fmt.Sprint(step.With["name"]) == "server-test-binary" {
			downloaded = true
		}
	}
	if !uploaded || !downloaded {
		t.Error("the server test binary must be uploaded by the build job and downloaded by every slice")
	}

	_, umbrella, ok := ciJobByName(wf, ciUmbrellaCheck)
	if !ok {
		t.Fatalf("ci.yml has no %q job", ciUmbrellaCheck)
	}
	if strings.TrimSpace(umbrella.If) != "always()" {
		t.Errorf("%s must run with if: always(), so a failed or skipped lane fails it instead of skipping it", ciUmbrellaCheck)
	}
	for _, lane := range []string{"go-test-packages", "go-test-server-build", "go-test-server", "go-test-extra", "editions-gate-tests"} {
		if !slices.Contains(umbrella.Needs, lane) {
			t.Errorf("%s must need lane %s", ciUmbrellaCheck, lane)
		}
	}
	if len(umbrella.Steps) == 0 || !ciUmbrellaGatesOnNeeds(umbrella.Steps[0]) {
		t.Fatalf("the first step of %s must fail unless every needed job succeeded", ciUmbrellaCheck)
	}
	if !ciUmbrellaGate(umbrella) {
		t.Fatalf("%s has no needs gate that always runs", ciUmbrellaCheck)
	}
	downloads := false
	for _, step := range umbrella.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") && fmt.Sprint(step.With["pattern"]) == "coverage-*" && fmt.Sprint(step.With["merge-multiple"]) == "true" {
			downloads = true
		}
	}
	if !downloads {
		t.Errorf("%s must download every lane's coverage-* artifact", ciUmbrellaCheck)
	}
	runs, last := ciJobRuns(umbrella), -1
	for _, want := range []string{
		fmt.Sprintf("make test-selftests TEST_SHARDS=%d", shards),
		fmt.Sprintf("make coverage-gate TEST_SHARDS=%d SERVER_SLICES=%d", shards, slicesN),
		"make test-live-slo",
	} {
		i := strings.Index(runs, want)
		if i < 0 || i < last {
			t.Fatalf("%s must run, in order, the self-tests, the floors over exactly the lanes' shards and slices, then the live SLO report: %q is missing or out of order", ciUmbrellaCheck, want)
		}
		last = i
	}
}

// TestEditionsGateTestsRunInLanesThatCoverEveryPackage keeps the editions gate's
// trstctl_core test pass whole after it moved out of build-lint into parallel
// lanes: build-lint still proves the core-only build and its dependency graph,
// every lane runs one shard of the same pass with the ML-DSA OpenSSL the
// interoperability tests need, the lanes match the Makefile's shard count (which
// make test-selftests checks covers every non-ee package exactly once), and the
// umbrella check needs them.
func TestEditionsGateTestsRunInLanesThatCoverEveryPackage(t *testing.T) {
	wf := readCIWorkflow(t)
	lint, okLint := wf.Jobs["build-lint"]
	lanes, okLanes := wf.Jobs["editions-gate-tests"]
	if !okLint || !okLanes {
		t.Fatal("ci.yml must have the build-lint job and the editions-gate-tests lanes")
	}
	if runs := ciJobRuns(lint); !strings.Contains(runs, "make editions-gate-build") || strings.Contains(runs, "make editions-gate\n") {
		t.Error("build-lint must run make editions-gate-build (the core-only build and graph), leaving the test pass to the lanes")
	}
	shards := ciMatrixSize(t, lanes, "shard")
	if want := fmt.Sprintf("make editions-gate-tests EDITIONS_SHARD=${{ matrix.shard }} EDITIONS_SHARDS=%d", shards); !strings.Contains(ciJobRuns(lanes), want) {
		t.Errorf("the editions lanes must run %q", want)
	}
	if !strings.Contains(ciJobRuns(lanes), "scripts/ci/install-openssl-pqc.sh") {
		t.Error("the editions lanes must install the pinned ML-DSA OpenSSL: the core-only pass runs its interoperability tests")
	}
	makefile := read(t, "../Makefile")
	if !strings.Contains(makefile, fmt.Sprintf("EDITIONS_CI_SHARDS ?= %d\n", shards)) {
		t.Errorf("Makefile EDITIONS_CI_SHARDS must equal the %d editions lanes, so test-selftests checks the partition CI runs", shards)
	}
	for _, want := range []string{
		"editions-gate: editions-gate-build editions-gate-tests",
		"--shards $(EDITIONS_CI_SHARDS) --weights scripts/ci/go-test-weights.json --max-unit-seconds $(TEST_MAX_UNIT_SECONDS) --selftest",
		"--tags trstctl_core --no-race",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile must contain %q", want)
		}
	}
}

// TestFuzzSmokeRunsInLanesThatCoverEveryTarget keeps fuzz smoke whole after it
// split into lanes: each lane runs its shard of the same targets at the same
// per-target budget, the lanes match the Makefile's FUZZ_CI_SHARDS (which make
// test-selftests checks holds every target exactly once), shard 0 keeps the
// property and coverage guards, and the required check needs every lane.
func TestFuzzSmokeRunsInLanesThatCoverEveryTarget(t *testing.T) {
	wf := readCIWorkflow(t)
	lanes, okLanes := wf.Jobs["fuzz-shards"]
	umbrella, okUmbrella := wf.Jobs["fuzz"]
	if !okLanes || !okUmbrella {
		t.Fatal("ci.yml must have the fuzz-shards lanes and the fuzz umbrella")
	}
	shards := ciMatrixSize(t, lanes, "shard")
	want := fmt.Sprintf("make fuzz-smoke FUZZ_SMOKE_TIME=${{ github.event_name == 'schedule' && '120s' || '15s' }} FUZZ_SHARD=${{ matrix.shard }} FUZZ_SHARDS=%d", shards)
	if !strings.Contains(ciJobRuns(lanes), want) {
		t.Errorf("the fuzz lanes must run %q", want)
	}
	if !strings.Contains(read(t, "../Makefile"), fmt.Sprintf("FUZZ_CI_SHARDS ?= %d\n", shards)) {
		t.Errorf("Makefile FUZZ_CI_SHARDS must equal the %d fuzz lanes", shards)
	}
	if umbrella.Name != fuzzUmbrellaCheck || !slices.Contains(umbrella.Needs, "fuzz-shards") ||
		strings.TrimSpace(umbrella.If) != "always()" || len(umbrella.Steps) == 0 || !ciUmbrellaGatesOnNeeds(umbrella.Steps[0]) {
		t.Errorf("%q must need fuzz-shards, always run, and fail unless every lane succeeded", fuzzUmbrellaCheck)
	}
	guards := 0
	for _, step := range lanes.Steps {
		if strings.Contains(step.Run, "go test ./internal/crypto/ -run TestEvery") && strings.TrimSpace(step.If) == "matrix.shard == 0" {
			guards++
		}
	}
	if guards != 2 {
		t.Errorf("fuzz lane 0 must run the property and coverage guards, found %d", guards)
	}
}

// TestEverySetupGoStepRestoresItsCacheBeforeAToolchainSwitch keeps the fix for a
// cache restore that failed on every job: setup-go installs go.mod's `go`
// version, and with GOTOOLCHAIN=auto its own `go env` fetched the newer
// `toolchain` version into the module cache first, so restoring the cache
// collided with those files. release.yml is left out on purpose: tag builds
// compile from scratch, which a release does not mind.
func TestEverySetupGoStepRestoresItsCacheBeforeAToolchainSwitch(t *testing.T) {
	for _, name := range []string{"ci.yml", "security.yml", "codeql.yml", "trust-audit.yml", "github-action-conformance.yml"} {
		var wf ciWorkflow
		if err := yaml.Unmarshal([]byte(read(t, "../.github/workflows/"+name)), &wf); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		steps := 0
		for id, job := range wf.Jobs {
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
					continue
				}
				steps++
				if step.Env["GOTOOLCHAIN"] != "local" {
					t.Errorf("%s job %s: its setup-go step must set GOTOOLCHAIN: local so the cache restores before any toolchain download", name, id)
				}
			}
		}
		if steps == 0 {
			t.Errorf("%s has no setup-go step; revisit this guard", name)
		}
	}
}
