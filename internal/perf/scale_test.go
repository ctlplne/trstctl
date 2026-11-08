// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/switchkit"
)

// A266: the default fleet lifetime gives the wait before the storm and the
// storm itself the same budget, after the built-in CA's NotBefore backdate;
// an explicit lifetime is kept inside its floor and ceiling.
func TestScaleConfigSizesTheFleetLifetimeFromTheStormBudget(t *testing.T) {
	backdate := trstcrypto.IssuanceBackdateSkew()
	cases := []struct {
		name   string
		in     ScaleConfig
		budget time.Duration
	}{
		{"small storm gets the three minute floor", ScaleConfig{Renewals: 20}, 3 * time.Minute},
		{"budget grows 200 ms a renewal", ScaleConfig{Renewals: 10000}, 2000 * time.Second},
		{"explicit lifetime is kept", ScaleConfig{Renewals: 20, FleetLifetimeSeconds: 3600}, time.Hour*2/3 - backdate},
		{"explicit lifetime below a minute's storm is raised", ScaleConfig{FleetLifetimeSeconds: 60}, time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Normalized()
			if got.stormBudget() != tc.budget {
				t.Fatalf("storm budget = %s (lifetime %ds), want %s", got.stormBudget(), got.FleetLifetimeSeconds, tc.budget)
			}
			// The wait before the storm is the same span: the last fleet
			// certificate enters its renewal window two thirds of the way
			// through its signed lifetime, which starts a backdate early.
			if wait := got.fleetLifetime()*2/3 - backdate; wait != tc.budget {
				t.Fatalf("wait before the storm = %s, want %s", wait, tc.budget)
			}
		})
	}
	if got := (ScaleConfig{FleetLifetimeSeconds: 40 * 24 * 3600}).Normalized(); got.fleetLifetime() != scaleMaxFleetLifetime {
		t.Fatalf("a lifetime at or above the default leaf lifetime has no effect as a profile ceiling; got %s, want %s",
			got.fleetLifetime(), scaleMaxFleetLifetime)
	}
	got := ScaleConfig{Inventory: -1, Renewals: -1, Chunk: switchkit.MaxRows + 1}.Normalized()
	if got.Inventory != 0 || got.Renewals != 0 || got.Clients != 8 || got.Chunk != 25000 || got.Seed != 266 {
		t.Fatalf("normalized defaults = %+v", got)
	}
}

// A266: the inventory is another product's export, generated from the seed:
// the switching kit reads every row, a rerun is the same bytes, and chunks
// and seeds never collide.
func TestScaleExportIsAReproducibleSwitchingExport(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	first, err := scaleExport(266, 0, 500, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := scaleExport(266, 0, 500, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(again) {
		t.Fatal("the same seed rendered a different export")
	}
	rows, err := switchkit.Parse(first, nil)
	if err != nil {
		t.Fatalf("switching kit refused the export: %v", err)
	}
	report := switchkit.Map(rows, switchkit.ExistingOwners{}, now)
	if report.Rows != 500 || report.Counts[switchkit.OutcomeMapped]+report.Counts[switchkit.OutcomeMappedWithGaps] != 500 {
		t.Fatalf("switching kit mapped %d of %d rows: %v", report.Counts[switchkit.OutcomeMapped]+report.Counts[switchkit.OutcomeMappedWithGaps], report.Rows, report.Counts)
	}
	if len(report.Owners) != 20 || len(report.Applications) != 20 {
		t.Fatalf("export names %d owners in %d applications, want 20 in 20", len(report.Owners), len(report.Applications))
	}

	seen := map[string]bool{}
	collect := func(seed uint64, from, to int) {
		t.Helper()
		data, err := scaleExport(seed, from, to, now)
		if err != nil {
			t.Fatal(err)
		}
		var export struct {
			Certificates []struct {
				Fingerprint string `json:"fingerprint_sha256"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal(data, &export); err != nil {
			t.Fatal(err)
		}
		if len(export.Certificates) != to-from {
			t.Fatalf("rows [%d, %d) rendered %d rows", from, to, len(export.Certificates))
		}
		for _, row := range export.Certificates {
			if len(row.Fingerprint) != 64 || seen[row.Fingerprint] {
				t.Fatalf("fingerprint %q is malformed or repeats", row.Fingerprint)
			}
			seen[row.Fingerprint] = true
		}
	}
	collect(266, 0, 500)
	collect(266, 500, 1000)
	collect(267, 0, 500)
}

// A266: the client pool runs every item once, keeps each latency, and counts
// failures with the first one kept for the receipt.
func TestScaleParallelRunsEveryItemOnceAndKeepsTheFirstFailure(t *testing.T) {
	ran := make([]int, 100)
	boom := errors.New("refused")
	latencies, failed, first := scaleParallel(context.Background(), 7, len(ran), func(_ context.Context, i int) error {
		ran[i]++
		if i%10 == 3 {
			return boom
		}
		return nil
	})
	for i, n := range ran {
		if n != 1 {
			t.Fatalf("item %d ran %d times", i, n)
		}
	}
	if len(latencies) != len(ran) || failed != 10 || !errors.Is(first, boom) {
		t.Fatalf("latencies %d, failed %d, first %v", len(latencies), failed, first)
	}
	p := phase("fleet.request", 100, 2*time.Second, latencies, failed)
	if p.PerSecond != 50 || p.Latency == nil || p.Latency.Count != 100 || p.Errors != 10 {
		t.Fatalf("phase = %+v", p)
	}
}
