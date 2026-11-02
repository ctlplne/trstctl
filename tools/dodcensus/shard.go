// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// The census can run as shards (owner decision 2026-11-02: split the Go test
// jobs, dod-gate included). Its cost is the runtime groups: each is one go test
// of a production-assembly proof that its entries share. A shard evaluates the
// groups it owns, whole, and marks every other row not evaluated. The merge
// recomputes ownership from the manifest and the weights, takes each row from
// the shard that owns it, and only then checks the product claims, so the
// merged receipt is the one a single full run writes.

// shardWeightsPath holds measured seconds per runtime group, from a CI run.
const shardWeightsPath = "tools/dodcensus/shard-weights.json"

type shardWeights struct {
	Source  string             `json:"source"`
	Seconds map[string]float64 `json:"seconds"`
}

// reportShard is a shard receipt's own part; a full or merged receipt has none.
type reportShard struct {
	Index          int                `json:"index"`
	Count          int                `json:"count"`
	Owned          []string           `json:"owned"`
	RuntimeSeconds map[string]float64 `json:"runtime_seconds"`
}

func loadShardWeights(repo string) (shardWeights, error) {
	raw, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(shardWeightsPath))) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil {
		return shardWeights{}, fmt.Errorf("read shard weights: %w", err)
	}
	var weights shardWeights
	if err := json.Unmarshal(raw, &weights); err != nil {
		return shardWeights{}, fmt.Errorf("parse shard weights: %w", err)
	}
	for key, seconds := range weights.Seconds {
		if seconds <= 0 {
			return shardWeights{}, fmt.Errorf("shard weight for %q must be positive", key)
		}
	}
	return weights, nil
}

// shardGroupKey names the unit a shard owns: an entry's runtime group, or the
// entry itself when it has no runtime proof.
func shardGroupKey(manifest Manifest, entry Entry) string {
	profileName, _ := resolvedProfile(manifest, entry)
	if runtimeConfigured(entry.Runtime) {
		return strings.Join([]string{profileName, entry.Runtime.Package, entry.Runtime.Test}, " ")
	}
	return "entry " + entry.ID
}

// shardOwners assigns every entry to one of shards: whole groups, longest
// first (a group with no measurement counts as the median), each to the least
// loaded shard, ties by key, so every shard and the merge compute the same map.
func shardOwners(manifest Manifest, weights shardWeights, shards int) (map[string]int, []float64, error) {
	if shards < 1 {
		return nil, nil, errors.New("the shard count must be at least 1")
	}
	members := map[string][]string{}
	for _, entry := range manifest.Entries {
		key := shardGroupKey(manifest, entry)
		members[key] = append(members[key], entry.ID)
	}
	keys := make([]string, 0, len(members))
	var known []float64
	for key := range members {
		keys = append(keys, key)
		if seconds, ok := weights.Seconds[key]; ok {
			known = append(known, seconds)
		}
	}
	median := 1.0
	if len(known) > 0 {
		sort.Float64s(known)
		median = known[len(known)/2]
		if len(known)%2 == 0 {
			median = (known[len(known)/2-1] + known[len(known)/2]) / 2
		}
	}
	weight := func(key string) float64 {
		if seconds, ok := weights.Seconds[key]; ok {
			return seconds
		}
		return median
	}
	sort.Slice(keys, func(i, j int) bool {
		if wi, wj := weight(keys[i]), weight(keys[j]); wi != wj {
			return wi > wj
		}
		return keys[i] < keys[j]
	})
	loads := make([]float64, shards)
	owners := map[string]int{}
	for _, key := range keys {
		target := 0
		for i := 1; i < shards; i++ {
			if loads[i] < loads[target] {
				target = i
			}
		}
		loads[target] += weight(key)
		for _, id := range members[key] {
			owners[id] = target
		}
	}
	return owners, loads, nil
}

func (s selection) sharded() bool { return s.Shards > 0 }

// owns reports whether this run evaluates the entry: always, unless sharded.
func (s selection) owns(id string) bool {
	if !s.sharded() {
		return true
	}
	owner, ok := s.Owners[id]
	return ok && owner == s.Shard
}

func notEvaluatedShardResult(entry Entry, profileName string, sel selection) entryResult {
	detail := fmt.Sprintf("not evaluated in shard %d of %d: shard %d owns this row's runtime group; no proof command ran here", sel.Shard, sel.Shards, sel.Owners[entry.ID])
	notEvaluated := checkEvidence{Detail: detail}
	return entryResult{
		CardID: entry.CardID, Capability: entry.Capability, Inventory: *entry.Inventory,
		Enforcement: entry.Enforcement, BuildProfile: profileName, Status: statusUnknown,
		Evidence: entryEvidence{Artifact: notEvaluated, Dependency: notEvaluated, Assembly: notEvaluated, Runtime: notEvaluated},
	}
}

// shardReceipt records what a shard ran: the rows it owns and each runtime
// group's measured seconds (the next weights).
func shardReceipt(manifest Manifest, sel selection, executions map[string]*runtimeTestExecution) *reportShard {
	shard := &reportShard{Index: sel.Shard, Count: sel.Shards, RuntimeSeconds: map[string]float64{}}
	for _, entry := range manifest.Entries {
		if sel.owns(entry.ID) {
			shard.Owned = append(shard.Owned, entry.ID)
		}
	}
	sort.Strings(shard.Owned)
	for key, execution := range executions {
		if execution != nil {
			shard.RuntimeSeconds[strings.ReplaceAll(key, "\x00", " ")] = execution.elapsed.Round(time.Second).Seconds()
		}
	}
	return shard
}

// shardFailed reports whether a required row this shard owns is not served.
func shardFailed(report Report) bool {
	for _, id := range report.Shard.Owned {
		if entry := report.Entries[id]; entry.Enforcement == enforcementRequired && entry.Status != statusServed {
			return true
		}
	}
	return false
}

func printShardReport(w io.Writer, report Report, outputPath string) {
	served := 0
	for _, id := range report.Shard.Owned {
		if report.Entries[id].Status == statusServed {
			served++
		}
	}
	_, _ = fmt.Fprintf(w, "wiring-census shard %d of %d: %d/%d owned entries SERVED; receipt=%s\n", report.Shard.Index, report.Shard.Count, served, len(report.Shard.Owned), outputPath)
	groups := make([]string, 0, len(report.Shard.RuntimeSeconds))
	for key := range report.Shard.RuntimeSeconds {
		groups = append(groups, key)
	}
	sort.Strings(groups)
	for _, key := range groups {
		_, _ = fmt.Fprintf(w, "  runtime group %-90s %6.0fs\n", key, report.Shard.RuntimeSeconds[key])
	}
	for _, id := range report.Shard.Owned {
		entry := report.Entries[id]
		_, _ = fmt.Fprintf(w, "  %-42s %-12s %-8s %s\n", id, entry.Status, entry.Enforcement, entry.Evidence.Runtime.Detail)
	}
}

func readShardReport(path string) (Report, error) {
	f, err := os.Open(path) // #nosec G304 -- developer tool reading the shard receipts it is pointed at (CWE-22)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if report.Shard == nil {
		return Report{}, fmt.Errorf("%s is not a shard receipt", path)
	}
	return report, nil
}

// mergeShardReports joins shard receipts into the full receipt. Each shard
// must be one of exactly 0..N-1, from this manifest, and have evaluated exactly
// the rows the recomputed partition gives it; every row comes from its owner.
func mergeShardReports(repo string, manifest Manifest, weights shardWeights, paths []string) (Report, error) {
	if len(paths) == 0 {
		return Report{}, errors.New("no shard receipts to merge")
	}
	parts := make([]Report, len(paths))
	for i, path := range paths {
		report, err := readShardReport(path)
		if err != nil {
			return Report{}, err
		}
		parts[i] = report
	}
	count := len(parts)
	owners, _, err := shardOwners(manifest, weights, count)
	if err != nil {
		return Report{}, err
	}
	owned := make([][]string, count)
	for _, entry := range manifest.Entries {
		owned[owners[entry.ID]] = append(owned[owners[entry.ID]], entry.ID)
	}
	byIndex := make([]*Report, count)
	profiles := normalizedProfiles(manifest.BuildProfiles)
	wantProfiles, err := json.Marshal(profiles)
	if err != nil {
		return Report{}, err
	}
	for i := range parts {
		part := &parts[i]
		switch {
		case part.Shard.Count != count:
			return Report{}, fmt.Errorf("shard %d was cut %d ways, but %d receipts were given", part.Shard.Index, part.Shard.Count, count)
		case part.Shard.Index < 0 || part.Shard.Index >= count || byIndex[part.Shard.Index] != nil:
			return Report{}, fmt.Errorf("shard receipts are not exactly shards 0..%d", count-1)
		case part.SchemaVersion != manifest.SchemaVersion || part.ManifestVersion != manifest.ManifestVersion ||
			part.BinaryPackage != manifest.BinaryPackage || part.DefaultBuildProfile != manifest.DefaultBuildProfile ||
			!sameJSON(part.BuildProfiles, wantProfiles):
			return Report{}, fmt.Errorf("shard %d was evaluated against a different manifest", part.Shard.Index)
		}
		want := append([]string(nil), owned[part.Shard.Index]...)
		sort.Strings(want)
		if !reflect.DeepEqual(part.Shard.Owned, want) {
			return Report{}, fmt.Errorf("shard %d evaluated %v, but the partition gives it %v", part.Shard.Index, part.Shard.Owned, want)
		}
		byIndex[part.Shard.Index] = part
	}
	absRepo, err := filepath.Abs(repo)
	if err != nil {
		return Report{}, err
	}
	merged := Report{
		SchemaVersion: manifest.SchemaVersion, ManifestVersion: manifest.ManifestVersion,
		GeneratedAt: byIndex[0].GeneratedAt, Repo: absRepo, BinaryPackage: manifest.BinaryPackage,
		DefaultBuildProfile: manifest.DefaultBuildProfile, ToolchainOK: true, BuildProfiles: profiles,
		Entries: map[string]entryResult{},
	}
	for _, part := range byIndex {
		merged.ToolchainOK = merged.ToolchainOK && part.ToolchainOK
		if part.GeneratedAt < merged.GeneratedAt {
			merged.GeneratedAt = part.GeneratedAt
		}
	}
	for _, entry := range manifest.Entries {
		result, ok := byIndex[owners[entry.ID]].Entries[entry.ID]
		if !ok {
			return Report{}, fmt.Errorf("shard %d has no row %s", owners[entry.ID], entry.ID)
		}
		merged.Entries[entry.ID] = result
		updateSummary(&merged.Summary, result)
	}
	merged.Capabilities = aggregateCapabilities(merged.Entries)
	for _, capability := range merged.Capabilities {
		if capability.Status == statusServed {
			merged.Served++
		}
	}
	merged.Total = len(merged.Capabilities)
	return merged, nil
}

// shardSelection resolves --shard/--shards into the rows this run owns.
func shardSelection(repo string, manifest Manifest, shard, shards, args int) (selection, error) {
	if args > 0 {
		return selection{}, errors.New("receipt arguments are only for --merge")
	}
	if shards < 1 || shard < 0 || shard >= shards {
		return selection{}, fmt.Errorf("--shard %d of --shards %d: the shard must be in [0, shards)", shard, shards)
	}
	weights, err := loadShardWeights(repo)
	if err != nil {
		return selection{}, err
	}
	owners, _, err := shardOwners(manifest, weights, shards)
	if err != nil {
		return selection{}, err
	}
	return selection{Shard: shard, Shards: shards, Owners: owners}, nil
}

// runMerge writes the full receipt from the shards' receipts and checks the
// product claims against it, as a whole run does.
func runMerge(repo string, manifest Manifest, outPath string, paths []string, stdout, stderr io.Writer) int {
	weights, err := loadShardWeights(repo)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: %v\n", err)
		return 2
	}
	report, err := mergeShardReports(repo, manifest, weights, paths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: merge: %v\n", err)
		return 2
	}
	sel := selection{}
	claimsErr := validateClaimsForSelection(repo, manifest, report, sel)
	return finishCLIReport(outPath, report, sel, claimsErr, stdout, stderr)
}

// sameJSON compares what a receipt carries: runtime-only profile fields are not
// serialized, so two profiles agree when their JSON does.
func sameJSON(value any, want []byte) bool {
	got, err := json.Marshal(value)
	return err == nil && string(got) == string(want)
}
