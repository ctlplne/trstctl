// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
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
	for _, lane := range []string{"go-test-packages", "go-test-server-build", "go-test-server", "go-test-extra"} {
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

// TestEditionsGateTestsThePackagesTheTagChanges keeps the editions gate the owner
// approved on 2026-11-02: build-lint builds the core-only binary and checks its
// graph (zero ee/, every core family), then runs the trstctl_core tests of exactly
// the packages with a file whose //go:build line mentions the tag, derived from the
// files (an empty list fails), and compiles every package and test under the tag
// with go vet. No separate core-pass lanes remain.
func TestEditionsGateTestsThePackagesTheTagChanges(t *testing.T) {
	wf := readCIWorkflow(t)
	lint, ok := wf.Jobs["build-lint"]
	if !ok {
		t.Fatal("ci.yml must have the build-lint job")
	}
	runs := ciJobRuns(lint)
	build, tests := strings.Index(runs, "make editions-gate-build"), strings.Index(runs, "make editions-gate-tests")
	if build < 0 || tests < build {
		t.Error("build-lint must run make editions-gate-build, then make editions-gate-tests")
	}
	if _, lanes := wf.Jobs["editions-gate-tests"]; lanes {
		t.Error("the editions gate's core-pass lanes were dropped (owner decision 2026-11-02); ci.yml still has them")
	}
	makefile := read(t, "../Makefile")
	for _, want := range []string{
		"editions-gate: editions-gate-build editions-gate-tests",
		"git ls-files -z '*.go' | xargs -0 grep -l -E '^//go:build .*trstctl_core'",
		"the editions gate tests nothing\"; exit 1;",
		"$(GO) test -tags trstctl_core -count=1 $$pkgs",
		"@$(GO) vet -tags trstctl_core ./...",
		"if $(GO) list -tags trstctl_core -deps ./cmd/trstctl | grep -E '^$(MODULE)/ee(/|$$)' >/dev/null; then",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile must contain %q", want)
		}
	}
}

// TestScheduledCIRunsHaveTheirOwnConcurrencyGroup keeps the owner decision of
// 2026-11-02: scheduled (nightly) runs have their own concurrency group, so a
// nightly and a push run never cancel each other, and a newer push still cancels
// an older push run.
func TestScheduledCIRunsHaveTheirOwnConcurrencyGroup(t *testing.T) {
	var wf struct {
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress string `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "../.github/workflows/ci.yml")), &wf); err != nil {
		t.Fatalf("parse .github/workflows/ci.yml: %v", err)
	}
	if want := "ci-${{ github.event_name == 'schedule' && 'schedule-' || '' }}${{ github.ref }}"; wf.Concurrency.Group != want {
		t.Errorf("ci.yml concurrency group is %q, want %q: scheduled runs need a group of their own", wf.Concurrency.Group, want)
	}
	if want := "${{ github.event_name != 'schedule' }}"; wf.Concurrency.CancelInProgress != want {
		t.Errorf("ci.yml cancel-in-progress is %q, want %q: pushes cancel older push runs, scheduled runs are never cancelled", wf.Concurrency.CancelInProgress, want)
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

// TestCIModuleDownloadsRetryTransientProxyFailures keeps every job's module
// download behind scripts/ci/go-mod-download.sh: a bare `go mod download` let one
// HTTP/2 stream reset from the module proxy fail a whole server lane before any
// test ran (CI 41451560632). The script retries twice and still fails a real error.
func TestCIModuleDownloadsRetryTransientProxyFailures(t *testing.T) {
	wf := readCIWorkflow(t)
	uses := 0
	for id, job := range wf.Jobs {
		for _, step := range job.Steps {
			for _, line := range strings.Split(step.Run, "\n") {
				switch strings.TrimSpace(line) {
				case "go mod download":
					t.Errorf("job %s runs a bare `go mod download`; use scripts/ci/go-mod-download.sh", id)
				case "scripts/ci/go-mod-download.sh":
					uses++
				}
			}
		}
	}
	if uses == 0 {
		t.Error("no CI job downloads modules through scripts/ci/go-mod-download.sh")
	}
	script := read(t, "../scripts/ci/go-mod-download.sh")
	for _, want := range []string{"for delay in 10 30; do", "go mod download && exit 0", "exit 1"} {
		if !strings.Contains(script, want) {
			t.Errorf("go-mod-download.sh lost %q", want)
		}
	}
}

// TestServerSliceWallEndsInsideItsJob keeps a hung server test diagnosable on
// CI: a slice's test wall is shorter than its job's timeout (with room for
// setup), so Go's timeout panic writes every goroutine's stack into the part
// log before GitHub cancels the job, and the part logs are uploaded whether the
// slice passed or not (slice 3 of CI run 41485378892 hung and left nothing).
func TestServerSliceWallEndsInsideItsJob(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			TimeoutMinutes any `yaml:"timeout-minutes"`
			Steps          []struct {
				Name string         `yaml:"name"`
				If   string         `yaml:"if"`
				With map[string]any `yaml:"with"`
				Run  string         `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "../.github/workflows/ci.yml")), &wf); err != nil {
		t.Fatalf("parse .github/workflows/ci.yml: %v", err)
	}
	job, ok := wf.Jobs["go-test-server"]
	if !ok {
		t.Fatal("ci.yml has no go-test-server job")
	}
	timeout, ok := job.TimeoutMinutes.(int)
	if !ok {
		t.Fatalf("go-test-server's timeout-minutes is %v, want a fixed number of minutes", job.TimeoutMinutes)
	}
	wall := regexp.MustCompile(`make test-server [^\n]*SERVER_COMPLEMENTARY_TIMEOUT=(\d+)m`)
	uploaded := false
	for _, step := range job.Steps {
		if m := wall.FindStringSubmatch(step.Run); m != nil {
			minutes, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("server slice wall %q: %v", m[1], err)
			}
			if minutes+5 > timeout {
				t.Errorf("the server slice wall (%d min) plus five minutes of setup exceeds the job's %d minutes", minutes, timeout)
			}
			uploaded = true
		}
		if step.Name == "Upload server slice coverage and census result" {
			if strings.TrimSpace(step.If) != "always()" || !strings.Contains(fmt.Sprint(step.With["path"]), ".shards/part-*.ndjson") {
				t.Error("the server slice upload must run always() and keep the part logs")
			}
		}
	}
	if !uploaded {
		t.Error("the server slice step must set SERVER_COMPLEMENTARY_TIMEOUT to a wall inside the job")
	}
}

// TestEveryPostgresArchiveRestoreSeedsTheBundledSource keeps the restored
// PostgreSQL archive in reach of the bundled server: the cache holds the
// embedded-postgres library's own cache, which the bundled server never reads,
// so jobs downloaded the archive anyway and parallel ones drew HTTP 429 (CI run
// 41479056374). Every restore is followed by the seed script, and the test
// lanes run its self-test.
func TestEveryPostgresArchiveRestoreSeedsTheBundledSource(t *testing.T) {
	wf := readCIWorkflow(t)
	restores := 0
	for id, job := range wf.Jobs {
		for i, step := range job.Steps {
			if step.Name != "Restore the pinned embedded PostgreSQL archive" {
				continue
			}
			restores++
			if i+1 == len(job.Steps) || strings.TrimSpace(job.Steps[i+1].Run) != "scripts/ci/seed-bundled-pg-archive.sh" {
				t.Errorf("job %s restores the PostgreSQL archive without seeding the bundled server's source next", id)
			}
		}
	}
	if restores == 0 {
		t.Error("no CI job restores the pinned PostgreSQL archive")
	}
	script := read(t, "../scripts/ci/seed-bundled-pg-archive.sh")
	for _, want := range []string{`src="${HOME}/.embedded-postgres-go"`, `dst="${TMPDIR:-/tmp}/trstctl-pg-bin"`, `install -m 600 "$archive"`, `! -L "$archive"`} {
		if !strings.Contains(script, want) {
			t.Errorf("seed-bundled-pg-archive.sh lost %q", want)
		}
	}
	if !strings.Contains(read(t, "../Makefile"), "@bash scripts/ci/seed-bundled-pg-archive_selftest.sh") {
		t.Error("make test-selftests must run the seed script's self-test")
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
