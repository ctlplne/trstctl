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
	ciUmbrellaCheck  = "build / test / lint"
	dodUmbrellaCheck = "definition of done / wiring census"
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
	if !strings.Contains(mk, "[ -n \"$$pkgs\" ] || { echo \"FAIL: package shard $(TEST_SHARD) of $(TEST_SHARDS) selected no packages\"; exit 1; }") {
		t.Error("an empty package shard must fail rather than let go test fall back to the current directory")
	}
	for _, want := range []string{
		"for i in $$(seq 0 $$(( $(TEST_SHARDS) - 1 ))); do profiles=\"$$profiles $(COVERPROFILE_MAIN).$$i\"; done",
		"for f in $$profiles; do head -n 1 \"$$f\" | grep -qx 'mode: atomic' || { echo \"FAIL: coverage lane profile $$f is missing or not atomic\"; exit 1; }; done",
		"python3 scripts/ci/go-test-shard.py --shard 0 --shards $(TEST_SHARDS) --weights scripts/ci/go-test-weights.json --selftest",
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
		"go-test-server":   fmt.Sprintf("make test-server SERVER_SLICE=${{ matrix.slice }} SERVER_SLICES=%d", slicesN),
		"go-test-extra":    "make test-extra",
	} {
		if !strings.Contains(ciJobRuns(wf.Jobs[job]), want) {
			t.Errorf("CI lane %s must run %q", job, want)
		}
		if !ciJobUploadsCoverage(wf.Jobs[job]) {
			t.Errorf("CI lane %s must upload its coverage as a coverage-* artifact, failing when a file is missing", job)
		}
	}

	_, umbrella, ok := ciJobByName(wf, ciUmbrellaCheck)
	if !ok {
		t.Fatalf("ci.yml has no %q job", ciUmbrellaCheck)
	}
	if strings.TrimSpace(umbrella.If) != "always()" {
		t.Errorf("%s must run with if: always(), so a failed or skipped lane fails it instead of skipping it", ciUmbrellaCheck)
	}
	for _, lane := range []string{"go-test-packages", "go-test-server", "go-test-extra"} {
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
