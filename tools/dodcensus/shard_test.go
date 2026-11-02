// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// proofRunner answers the census's commands as a passing shipped binary would:
// the dependency list for `go list`, and for each runtime `go test` an exact
// receipt per expectation it was given, then a pass for the test it ran.
type proofRunner struct {
	t     *testing.T
	deps  string
	tests []string
}

func (r *proofRunner) PrepareRuntime(_ context.Context, _ string, profile BuildProfile) (BuildProfile, error) {
	profile.RuntimeRunnerImage = "sha256:" + strings.Repeat("a", 64)
	return profile, nil
}

func (r *proofRunner) Run(_ context.Context, _ string, profile BuildProfile, _ string, args ...string) commandResult {
	if len(args) == 0 || args[0] != "test" {
		return commandResult{Stdout: r.deps}
	}
	test := ""
	for _, arg := range args {
		if strings.HasPrefix(arg, "^TestDOD") && strings.HasSuffix(arg, "$") {
			test = strings.TrimSuffix(strings.TrimPrefix(arg, "^"), "$")
		}
	}
	r.tests = append(r.tests, test)
	var expectations []runtimeExpectation
	if err := json.Unmarshal([]byte(profile.RuntimeEnv["TRSTCTL_DOD_EXPECTATIONS"]), &expectations); err != nil {
		r.t.Fatalf("decode runtime expectations: %v", err)
	}
	broker := profile.RuntimeBroker
	for _, expectation := range expectations {
		broker.mu.Lock()
		expected := broker.expect[expectation.ID]
		broker.mu.Unlock()
		candidate := receiptFor(expected)
		candidate.MAC = ""
		writeJSON(r.t, expected.EvidenceFile, candidate)
		broker.mu.Lock()
		broker.receipts[expected.ID] = append([]byte(nil), candidate.ExecutionReceipt...)
		broker.mu.Unlock()
	}
	return commandResult{Stdout: goTestPass(test)}
}

// writeTwoGroupFixture is the gate fixture plus a second connector whose proof
// is its own runtime group.
func writeTwoGroupFixture(t *testing.T, repo string) Manifest {
	t.Helper()
	writeGateFixture(t, repo, false)
	writeFile(t, repo, "internal/server/dod_apache_served_test.go", `//go:build trstctl_dodproof

package server
import (
    "net/http"
    "testing"
    "trstctl.com/trstctl/tools/dodcensus/proof"
)
func TestDODConnectorApacheServed(t *testing.T) {
    external := proof.StartCommand(t, "connector.apache")
    endpoint := external.Endpoint()
    _ = endpoint
    deps := buildRunDeps()
    srv, _ := Build(nil, deps)
    req, _ := http.NewRequest("POST", "/api/v1/connectors/apache", nil)
    session := proof.Start(t, "connector.apache", srv.Handler(), req)
    payload := []byte("external payload with readback")
    executionReceipt := external.StopAndReceipt()
    session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{Destination: []byte("apache/configuration/path"), Written: payload, ReadBack: payload, ExecutionReceipt: executionReceipt}))
}
`, 0o600)
	manifest := validManifest(t, repo, enforcementRequired)
	apache := manifest.Entries[0]
	apache.ID, apache.CardID = "connector.apache", "WIRE-CONN-102"
	apache.Runtime.Test, apache.Runtime.File = "TestDODConnectorApacheServed", "internal/server/dod_apache_served_test.go"
	apache.Runtime.Path = "/api/v1/connectors/apache"
	manifest.Entries = append(manifest.Entries, apache)
	return manifest
}

const twoGroupDeps = "trstctl.com/trstctl/internal/server\ntrstctl.com/trstctl/internal/connector/nginx\n"

// A shard runs whole runtime groups, longest first to the least loaded shard;
// an unmeasured group counts as the median, and every caller computes the same
// partition.
func TestShardOwnersKeepGroupsWholeAndBalanceByMeasuredSeconds(t *testing.T) {
	entry := func(id, test string) Entry {
		return Entry{ID: id, Runtime: RuntimeProof{Package: "./internal/server", Test: test}}
	}
	manifest := Manifest{DefaultBuildProfile: "static", BuildProfiles: map[string]BuildProfile{"static": testStaticProfile()}, Entries: []Entry{
		entry("a.1", "TestA"), entry("a.2", "TestA"), entry("a.3", "TestA"),
		entry("b.1", "TestB"), entry("c.1", "TestC"), entry("c.2", "TestC"), entry("d.1", "TestD"),
		{ID: "e.static"},
	}}
	weights := shardWeights{Seconds: map[string]float64{
		"static ./internal/server TestA": 300, "static ./internal/server TestB": 200, "static ./internal/server TestC": 100,
	}}
	owners, loads, err := shardOwners(manifest, weights, 2)
	if err != nil {
		t.Fatal(err)
	}
	// A→0 (300), B→1 (200), C→1 (300), D (median 200)→0 (500), e.static (200)→1 (500).
	want := map[string]int{"a.1": 0, "a.2": 0, "a.3": 0, "b.1": 1, "c.1": 1, "c.2": 1, "d.1": 0, "e.static": 1}
	if !reflect.DeepEqual(owners, want) || !reflect.DeepEqual(loads, []float64{500, 500}) {
		t.Fatalf("owners %v loads %v, want %v [500 500]", owners, loads, want)
	}
	again, _, _ := shardOwners(manifest, weights, 2)
	if !reflect.DeepEqual(again, owners) {
		t.Fatal("the partition is not deterministic")
	}
	one, _, _ := shardOwners(manifest, weights, 1)
	for id, shard := range one {
		if shard != 0 {
			t.Fatalf("one shard left %s on shard %d", id, shard)
		}
	}
	if _, _, err := shardOwners(manifest, weights, 0); err == nil {
		t.Fatal("zero shards was accepted")
	}
}

// Two shards each run only their own runtime group and mark the other row not
// evaluated; merging their receipts gives the receipt a whole run writes.
func TestShardedCensusMergesToTheWholeRunReceipt(t *testing.T) {
	repo := t.TempDir()
	manifest := writeTwoGroupFixture(t, repo)
	wholeRunner := &proofRunner{t: t, deps: twoGroupDeps}
	whole, err := evaluate(context.Background(), repo, manifest, wholeRunner, selection{})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Entries["connector.nginx"].Status != statusServed || whole.Entries["connector.apache"].Status != statusServed || len(wholeRunner.tests) != 2 {
		t.Fatalf("whole run: %+v, tests %v", whole.Entries, wholeRunner.tests)
	}

	owners, _, err := shardOwners(manifest, shardWeights{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if owners["connector.nginx"] == owners["connector.apache"] {
		t.Fatalf("two equal groups landed on one shard: %v", owners)
	}
	receipts := make([]string, 2)
	for shard := range 2 {
		runner := &proofRunner{t: t, deps: twoGroupDeps}
		report, err := evaluate(context.Background(), repo, manifest, runner, selection{Shard: shard, Shards: 2, Owners: owners})
		if err != nil {
			t.Fatal(err)
		}
		mine, other := "connector.nginx", "connector.apache"
		if owners[mine] != shard {
			mine, other = other, mine
		}
		if report.Shard == nil || !reflect.DeepEqual(report.Shard.Owned, []string{mine}) || len(report.Shard.RuntimeSeconds) != 1 {
			t.Fatalf("shard %d receipt %+v", shard, report.Shard)
		}
		if report.Entries[mine].Status != statusServed || len(runner.tests) != 1 || runner.tests[0] != manifest.Entries[indexOfEntry(manifest, mine)].Runtime.Test {
			t.Fatalf("shard %d ran %v and served %+v", shard, runner.tests, report.Entries[mine])
		}
		if got := report.Entries[other]; got.Status != statusUnknown || !strings.Contains(got.Evidence.Runtime.Detail, "not evaluated in shard") {
			t.Fatalf("shard %d evaluated a row another shard owns: %+v", shard, got)
		}
		if shardFailed(report) {
			t.Fatalf("shard %d failed on a row it does not own", shard)
		}
		receipts[shard] = filepath.Join(t.TempDir(), "part.json")
		if err := writeReport(receipts[shard], report); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := mergeShardReports(repo, manifest, shardWeights{}, []string{receipts[1], receipts[0]})
	if err != nil {
		t.Fatal(err)
	}
	if merged.Shard != nil || merged.Summary != whole.Summary || !reflect.DeepEqual(merged.Capabilities, whole.Capabilities) ||
		merged.Served != whole.Served || merged.Total != whole.Total || merged.ToolchainOK != whole.ToolchainOK {
		t.Fatalf("merged receipt differs from the whole run:\nmerged %+v\nwhole  %+v", merged.Summary, whole.Summary)
	}
	for id, result := range whole.Entries {
		if got := merged.Entries[id]; got.Status != result.Status || got.Evidence.Runtime.OK != result.Evidence.Runtime.OK {
			t.Fatalf("merged row %s = %+v, whole run %+v", id, got, result)
		}
	}
}

func indexOfEntry(manifest Manifest, id string) int {
	for i, entry := range manifest.Entries {
		if entry.ID == id {
			return i
		}
	}
	return -1
}

// The merge accepts only one complete set of shards cut from this manifest,
// each having evaluated exactly the rows the partition gives it.
func TestMergeRefusesAnIncompleteForeignOrMisownedShardSet(t *testing.T) {
	repo := t.TempDir()
	manifest := writeTwoGroupFixture(t, repo)
	owners, _, err := shardOwners(manifest, shardWeights{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	part := func(index int, mutate func(*Report)) string {
		report := Report{
			SchemaVersion: manifest.SchemaVersion, ManifestVersion: manifest.ManifestVersion, BinaryPackage: manifest.BinaryPackage,
			DefaultBuildProfile: manifest.DefaultBuildProfile, ToolchainOK: true, BuildProfiles: normalizedProfiles(manifest.BuildProfiles),
			Entries: map[string]entryResult{}, Shard: &reportShard{Index: index, Count: 2, RuntimeSeconds: map[string]float64{}},
		}
		for _, entry := range manifest.Entries {
			status := statusUnknown
			if owners[entry.ID] == index {
				status = statusServed
				report.Shard.Owned = append(report.Shard.Owned, entry.ID)
			}
			report.Entries[entry.ID] = entryResult{CardID: entry.CardID, Capability: entry.Capability, Inventory: true, Enforcement: entry.Enforcement, Status: status}
		}
		if mutate != nil {
			mutate(&report)
		}
		path := filepath.Join(t.TempDir(), "part.json")
		if err := writeReport(path, report); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if merged, err := mergeShardReports(repo, manifest, shardWeights{}, []string{part(0, nil), part(1, nil)}); err != nil || merged.Summary.Served != 2 {
		t.Fatalf("a complete shard set: %+v %v", merged.Summary, err)
	}
	full := filepath.Join(t.TempDir(), "full.json")
	if err := writeReport(full, Report{Entries: map[string]entryResult{}}); err != nil {
		t.Fatal(err)
	}
	for name, paths := range map[string][]string{
		"one of two shards":   {part(0, nil)},
		"a shard twice":       {part(0, nil), part(0, nil)},
		"another manifest":    {part(0, nil), part(1, func(r *Report) { r.ManifestVersion++ })},
		"another build":       {part(0, nil), part(1, func(r *Report) { r.BinaryPackage = "./cmd/other" })},
		"rows it doesn't own": {part(0, nil), part(1, func(r *Report) { r.Shard.Owned = append(r.Shard.Owned, "connector.zzz") })},
		"a missing row":       {part(0, nil), part(1, func(r *Report) { delete(r.Entries, r.Shard.Owned[0]) })},
		"a full receipt":      {part(0, nil), full},
		"no receipts":         {},
	} {
		if _, err := mergeShardReports(repo, manifest, shardWeights{}, paths); err == nil {
			t.Errorf("%s was merged", name)
		}
	}
}

// The CLI keeps shards and merges whole-manifest, and a shard's exit status is
// its own rows'.
func TestShardFlagsAreValidatedBeforeAnyCommand(t *testing.T) {
	repo := t.TempDir()
	manifest := writeTwoGroupFixture(t, repo)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, "manifest.json", string(raw), 0o600)
	writeFile(t, repo, shardWeightsPath, `{"source":"test","seconds":{}}`, 0o600)
	for name, args := range map[string][]string{
		"a shard past the count":         {"--shard", "2", "--shards", "2"},
		"a negative shard":               {"--shard", "-1", "--shards", "2"},
		"a shard without a count":        {"--shard", "1"},
		"a shard of one exact selection": {"--shards", "2", "--capability", "connector.nginx"},
		"a merge of one exact selection": {"--merge", "--card", "WIRE-CONN-101", "part.json"},
		"receipts without --merge":       {"--shards", "2", "part.json"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCLI(context.Background(), append([]string{"--repo", repo, "--manifest", "manifest.json"}, args...), &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, stderr.String())
		}
	}
	writeFile(t, repo, shardWeightsPath, `{"source":"test","seconds":{"static ./internal/server TestDODConnectorNginxServed":0}}`, 0o600)
	if _, err := loadShardWeights(repo); err == nil {
		t.Fatal("a non-positive weight was accepted")
	}
	if err := os.Remove(filepath.Join(repo, shardWeightsPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := shardSelection(repo, manifest, 0, 2, 0); err == nil {
		t.Fatal("sharding ran without the committed weights")
	}
}

// The committed weights name only real runtime groups of the shipped manifest.
func TestCommittedShardWeightsNameShippedRuntimeGroups(t *testing.T) {
	repo := filepath.Join("..", "..")
	weights, err := loadShardWeights(repo)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, shippedManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]bool{}
	for _, entry := range manifest.Entries {
		groups[shardGroupKey(manifest, entry)] = true
	}
	for key := range weights.Seconds {
		if !groups[key] {
			t.Errorf("shard weight %q names no runtime group of %s", key, shippedManifestPath)
		}
	}
	if strings.TrimSpace(weights.Source) == "" {
		t.Error("shard weights must say where their seconds come from")
	}
}
