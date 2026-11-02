// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestDODGateIsARequiredEmittingCICheck(t *testing.T) {
	t.Parallel()
	makefile := read(t, "../Makefile")
	for _, want := range []string{
		"dod-gate:",
		"$(GO) test ./tools/dodcensus/...",
		"$(GO) run ./tools/dodcensus",
		"TestDODGateProductionAssemblyCanary",
		"tools/dodcensus/manifest.json",
		"wiring-census.json",
		// Persist the expensive package cache across reboots, while keeping the
		// explicit override that lets CI and isolated proofs choose their cache.
		"DOD_GOCACHE_DEFAULT := $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/trstctl/dodcensus-gocache",
		`cache="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}"`,
		`(umask 077; mkdir -p "$$cache")`,
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile must keep the repo-native DoD gate token %q", want)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"name: definition of done / wiring census",
		"run: make dod-selftests",
		"path: wiring-census.json",
		"if-no-files-found: error",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml must keep the dedicated DoD gate token %q", want)
		}
	}
	// The census runs as shards; the required check merges exactly the shards
	// the matrix ran, and that merge is the full census (claims included).
	for _, want := range []string{
		"dod-selftests: dod-cache ## ",
		"$(GO) test ./tools/dodcensus/... -count=1",
		"dod-census-shard: dod-cache ## ",
		"--shard $(DOD_SHARD) --shards $(DOD_SHARDS) --out wiring-census.part-$(DOD_SHARD).json",
		"dod-census-merge: dod-cache ## ",
		"for i in $$(seq 0 $$(( $(DOD_SHARDS) - 1 ))); do parts=\"$$parts wiring-census.part-$$i.json\"; done",
		"--merge --out \"$(DOD_CENSUS_OUT)\" $$parts",
		"@$(MAKE) --no-print-directory dod-selftests",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile must keep the sharded DoD census token %q", want)
		}
	}
	wf := readCIWorkflow(t)
	shards := ciMatrixSize(t, wf.Jobs["dod-census"], "shard")
	for job, want := range map[string]string{
		"dod-census": fmt.Sprintf("make dod-census-shard DOD_SHARD=${{ matrix.shard }} DOD_SHARDS=%d", shards),
		"dod-gate":   fmt.Sprintf("make dod-census-merge DOD_SHARDS=%d", shards),
	} {
		if !strings.Contains(ciJobRuns(wf.Jobs[job]), want) {
			t.Errorf("CI job %s must run %q, so the merge takes exactly the shards the matrix ran", job, want)
		}
	}
	if gate := wf.Jobs["dod-gate"]; gate.Name != dodUmbrellaCheck || strings.TrimSpace(gate.If) != "always()" ||
		!slices.Contains(gate.Needs, "dod-census") || !slices.Contains(gate.Needs, "dod-selftests") || !ciUmbrellaGate(gate) {
		t.Error("the required DoD check must need every shard and the self-tests, always run, and fail unless each succeeded")
	}
	if !strings.Contains(read(t, "../tools/dodcensus/shard.go"), "claimsErr := validateClaimsForSelection(repo, manifest, report, sel)") {
		t.Error("the merged census must validate product claims against its merged in-memory report")
	}

	policy := read(t, "../.github/branch-protection.json")
	if !strings.Contains(policy, `"definition of done / wiring census"`) {
		t.Error("branch protection must require the dedicated DoD census check")
	}
	branchDoc := read(t, "branch-protection.md")
	if !strings.Contains(branchDoc, "`definition of done / wiring census`") {
		t.Error("branch-protection.md must explain the required DoD census check")
	}
	if !strings.Contains(read(t, "../.gitignore"), "/wiring-census.json") {
		t.Error("the timestamped local census receipt must be ignored, not committed as stale truth")
	}

	evaluator := read(t, "../tools/dodcensus/main.go")
	if !strings.Contains(evaluator, "claimsErr := validateClaimsForSelection(repo, manifest, report, sel)") {
		t.Error("the full repo-native census must validate product claims against its fresh in-memory report")
	}
	for _, name := range []string{"feature_served_state_test.go", "trace_completeness_test.go"} {
		docsClaimsTests := read(t, name)
		for _, forbidden := range []string{"liveDoDCensus", "exec.Command(\"go\", \"run\", \"./tools/dodcensus\""} {
			if strings.Contains(docsClaimsTests, forbidden) {
				t.Errorf("%s must not recursively launch the heavyweight census (%q)", name, forbidden)
			}
		}
	}
}
