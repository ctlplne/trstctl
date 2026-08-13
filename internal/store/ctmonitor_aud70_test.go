// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// AUD-70: discovery.source.upserted is the watchlist authority. Replacing that
// event-projected configuration must switch the active polling set in the same
// PostgreSQL transaction while retaining the prior checkpoint as retired audit
// history. A second tenant's identically named source is a different authority.
func TestAUD70CTSourceReplacementReconcilesActiveWatchlistAndRetainsHistory(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const (
		sourceA = "70707070-0000-4000-8000-000000000001"
		sourceB = "70707070-0000-4000-8000-000000000002"
		oldRun  = "70707070-0000-4000-8000-000000000003"
		dead    = "https://dead.example.test/argon/"
		working = "https://working.example.test/argon/"
	)

	apply := func(tenantID, sourceID, config string, at time.Time) {
		t.Helper()
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: sourceID, TenantID: tenantID, Kind: "ct_log", Name: "public-ct-watch",
				Config: []byte(config), CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatalf("apply CT source for %s: %v", tenantID, err)
		}
	}

	apply(tenantA, sourceA, `{"logs":["`+dead+`"],"watched_domains":["old.example.test"]}`, now)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: oldRun, TenantID: tenantA, SourceID: sourceA, Status: "queued", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("project old CT run: %v", err)
	}
	if err := st.SaveCTLogCheckpoint(ctx, tenantA, dead, 17); err != nil {
		t.Fatalf("advance dead-log checkpoint: %v", err)
	}
	apply(tenantB, sourceB, `{"logs":["`+dead+`"],"watched_domains":["tenant-b.example.test"]}`, now)

	apply(tenantA, sourceA, `{"logs":["`+working+`"],"watched_domains":["new.example.test"]}`, now.Add(time.Minute))

	active, err := st.ListCTLogCheckpoints(ctx, tenantA)
	if err != nil {
		t.Fatalf("list active checkpoints: %v", err)
	}
	if len(active) != 1 || active[0].LogURL != working || active[0].NextIndex != 0 || !active[0].Active {
		t.Fatalf("tenant A active checkpoints = %+v, want only fresh working log", active)
	}
	history, err := st.ListCTLogCheckpointHistory(ctx, tenantA)
	if err != nil {
		t.Fatalf("list checkpoint history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("tenant A checkpoint history = %+v, want active and retired rows", history)
	}
	byURL := map[string]store.CTCheckpoint{}
	for _, checkpoint := range history {
		byURL[checkpoint.LogURL] = checkpoint
	}
	retired := byURL[dead]
	if retired.Active || retired.NextIndex != 17 || retired.RetiredAt == nil {
		t.Fatalf("retired dead-log audit row = %+v, want inactive index 17 with retirement time", retired)
	}
	wantReplacementTime := now.Add(time.Minute)
	if delta := retired.RetiredAt.Sub(wantReplacementTime); delta < -time.Millisecond || delta > time.Millisecond {
		t.Fatalf("retirement time = %s, want source event time %s", retired.RetiredAt, wantReplacementTime)
	}
	if current := byURL[working]; !current.Active || current.RetiredAt != nil {
		t.Fatalf("working-log audit row = %+v, want active and unretired", current)
	} else if delta := current.ActivatedAt.Sub(wantReplacementTime); delta < -time.Millisecond || delta > time.Millisecond {
		t.Fatalf("replacement activation time = %s, want source event time %s", current.ActivatedAt, wantReplacementTime)
	}
	if err := st.SaveCTLogCheckpoint(ctx, tenantA, dead, 99); !errors.Is(err, store.ErrCTLogNotActive) {
		t.Fatalf("late retired-log checkpoint write = %v, want ErrCTLogNotActive", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCTLogPollResultFromEventTx(
			ctx, tx, tenantA, oldRun, dead, 99, store.CTPollFailed,
			"late 404 from an in-flight retired poll", now.Add(2*time.Minute),
		)
	}); err != nil {
		t.Fatalf("project late immutable result for retired log: %v", err)
	}
	history, err = st.ListCTLogCheckpointHistory(ctx, tenantA)
	if err != nil {
		t.Fatalf("reload checkpoint history after late write: %v", err)
	}
	for _, checkpoint := range history {
		if checkpoint.LogURL == dead && (checkpoint.Active || checkpoint.NextIndex != 17 || checkpoint.LastPollStatus != store.CTPollSucceeded) {
			t.Fatalf("late direct/event poll changed retired checkpoint: %+v", checkpoint)
		}
	}
	domains, err := st.ListWatchedDomains(ctx, tenantA)
	if err != nil {
		t.Fatalf("list active domains: %v", err)
	}
	if len(domains) != 1 || domains[0] != "new.example.test" {
		t.Fatalf("tenant A active domains = %v, want exact replacement", domains)
	}
	foreign, err := st.ListCTLogCheckpoints(ctx, tenantB)
	if err != nil {
		t.Fatalf("list tenant B checkpoints: %v", err)
	}
	if len(foreign) != 1 || foreign[0].LogURL != dead || !foreign[0].Active {
		t.Fatalf("tenant B active checkpoints = %+v, want its independent dead URL", foreign)
	}
}
