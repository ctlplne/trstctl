// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A discovery.run.queued event is projected inline by the request and again by
// the durable event tail. When a run is queued in the same instant its source
// was declared (the partner-lab bootstrap burst), the two projectors race on
// the run row. The apply must converge, never surface a raw unique violation.
func TestDiscoveryRunProjectionConcurrentReplayConverges(t *testing.T) {
	st := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Microsecond)
	const (
		sourceID = "53535353-0000-4000-8000-000000000001"
		runID    = "53535353-0000-4000-8000-000000000002"
	)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "network", Name: "concurrent-run-replay",
			Config: []byte(`{"targets":["192.0.2.0/24"]}`), CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	run := store.DiscoveryRun{
		ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued",
		RequestedBy: "test", Execution: "relay", Segment: "concurrent", CreatedAt: now,
	}

	firstProjected := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(release)
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := st.ApplyDiscoveryRunQueuedTx(ctx, tx, run); err != nil {
				return err
			}
			close(firstProjected)
			select {
			case <-releaseFirst:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
	}()
	select {
	case <-firstProjected:
	case err := <-firstErr:
		t.Fatalf("first projection before lock setup: %v", err)
	case <-ctx.Done():
		t.Fatalf("first projection setup: %v", context.Cause(ctx))
	}

	secondErr := make(chan error, 1)
	go func() {
		secondErr <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyDiscoveryRunQueuedTx(ctx, tx, run)
		})
	}()

	// Hold the first transaction open until PostgreSQL confirms the competing
	// projector is blocked behind the first (on the run projection lock, or on
	// the unique-index lock before that lock existed): the exact inline/tail
	// interleaving, reproduced without timing sleeps.
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-secondErr:
			t.Fatalf("competing projection completed before reaching the unique-index lock: %v", err)
		default:
		}
		var waiting bool
		if err := st.SystemPool().QueryRow(ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_stat_activity
			      WHERE pid <> pg_backend_pid()
			        AND (query LIKE '%INSERT INTO discovery_runs%'
			             OR query LIKE '%pg_advisory_xact_lock%')
			        AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatalf("observe competing projection: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("competing run projection did not block behind the first")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release()

	if err := <-firstErr; err != nil {
		t.Fatalf("first projection: %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("concurrent run replay must converge, got: %v", err)
	}
}

// The lock-wait interleaving above lets the second projector find the first's
// in-progress row at the arbiter pre-check. The partner-lab bootstrap burst is
// tighter: both projectors pass the primary-key pre-check before either has
// inserted, both insert speculatively, and the loser trips the tenant+ID unique
// index, which ON CONFLICT does not arbitrate. Many simultaneous identical
// applies from one start barrier reproduce that window; every one must
// converge to the same row and none may surface a unique violation.
func TestDiscoveryRunProjectionSimultaneousReplayConverges(t *testing.T) {
	st := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Microsecond)
	const sourceID = "54545454-0000-4000-8000-000000000001"
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "network", Name: "simultaneous-run-replay",
			Config: []byte(`{"targets":["192.0.2.0/24"]}`), CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	const (
		rounds     = 40
		projectors = 12
	)
	for round := 0; round < rounds; round++ {
		runID := "54545454-0000-4000-8000-" + padHex(round+2)
		run := store.DiscoveryRun{
			ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued",
			RequestedBy: "test", Execution: "relay", Segment: "simultaneous", CreatedAt: now,
		}
		start := make(chan struct{})
		errs := make(chan error, projectors)
		var wg sync.WaitGroup
		for i := 0; i < projectors; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					return st.ApplyDiscoveryRunQueuedTx(ctx, tx, run)
				})
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: simultaneous run replay must converge, got: %v", round, err)
			}
		}
		var count int
		if err := st.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM discovery_runs WHERE id = $1::uuid`, runID).Scan(&count); err != nil {
			t.Fatalf("round %d: count run rows: %v", round, err)
		}
		if count != 1 {
			t.Fatalf("round %d: run rows = %d, want exactly one", round, count)
		}
	}
}

// padHex renders n as a 12-hex-digit suffix so each round gets a distinct
// well-formed UUID.
func padHex(n int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 12)
	for i := 11; i >= 0; i-- {
		out[i] = digits[n%16]
		n /= 16
	}
	return string(out)
}
