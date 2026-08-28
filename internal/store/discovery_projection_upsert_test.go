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

// The inline projector and the durable event-tail projector may apply the same
// immutable declaration at the same time. The global UUID primary key is the
// only conflict authority that covers that race; the redundant tenant+ID key
// is useful for tenant-scoped foreign keys, but it is not a safe arbiter for
// concurrent INSERTs that also collide on the primary key.
func TestDiscoverySourceProjectionConcurrentReplayUsesPrimaryKeyArbiter(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := store.DiscoverySource{
		ID: "51515151-0000-4000-8000-000000000001", TenantID: tenantA,
		Kind: "network", Name: "concurrent-replay", Config: []byte(`{"targets":["192.0.2.0/24"]}`),
		CreatedAt: now, UpdatedAt: now,
		ProjectionEventID: "51515151-0000-4000-8000-0000000000e1", ProjectionEventSequence: 51,
	}

	firstProjected := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := st.ApplyDiscoverySourceUpsertedTx(ctx, tx, source); err != nil {
				return err
			}
			close(firstProjected)
			<-releaseFirst
			return nil
		})
	}()
	<-firstProjected

	secondErr := make(chan error, 1)
	go func() {
		secondErr <- st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, source)
		})
	}()

	// Do not release the first transaction until PostgreSQL confirms that the
	// competing INSERT has reached the unique-index lock. This deterministically
	// reproduces the production inline/tail interleaving without timing sleeps.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := st.SystemPool().QueryRow(ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_stat_activity
			      WHERE pid <> pg_backend_pid()
			        AND query LIKE '%INSERT INTO discovery_sources%'
			        AND wait_event_type = 'Lock'
			)`).Scan(&waiting); err != nil {
			t.Fatalf("observe competing projection: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("competing source projection did not reach the unique-index lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(releaseFirst)

	if err := <-firstErr; err != nil {
		t.Fatalf("first projection: %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("concurrent immutable replay: %v", err)
	}
}

// UUID identity is global even though every read and write remains tenant
// scoped. A malicious or accidental cross-tenant UUID reuse must be rejected
// as a declaration conflict, never overwrite the foreign row and never escape
// as a raw PostgreSQL/RLS error.
func TestDiscoveryProjectionPrimaryKeyCollisionIsTenantSafe(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const (
		sharedSourceID   = "52525252-0000-4000-8000-000000000001"
		sharedScheduleID = "52525252-0000-4000-8000-000000000002"
		sharedRunID      = "52525252-0000-4000-8000-000000000003"
		tenantBSourceID  = "52525252-0000-4000-8000-000000000004"
	)

	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sharedSourceID, TenantID: tenantA, Kind: "network", Name: "tenant-a-source",
			Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := st.ApplyDiscoveryScheduleUpsertedTx(ctx, tx, store.DiscoverySchedule{
			ID: sharedScheduleID, TenantID: tenantA, SourceID: sharedSourceID, Name: "tenant-a-schedule",
			IntervalSeconds: 3600, Enabled: true, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return st.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: sharedRunID, TenantID: tenantA, SourceID: sharedSourceID, Status: "queued",
			RequestedBy: "test", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed tenant A projections: %v", err)
	}
	if err := st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: tenantBSourceID, TenantID: tenantB, Kind: "network", Name: "tenant-b-source",
			Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed tenant B source: %v", err)
	}

	tests := []struct {
		name  string
		apply func(pgx.Tx) error
	}{
		{
			name: "source",
			apply: func(tx pgx.Tx) error {
				return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
					ID: sharedSourceID, TenantID: tenantB, Kind: "network", Name: "foreign-source-id",
					Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
				})
			},
		},
		{
			name: "schedule",
			apply: func(tx pgx.Tx) error {
				return st.ApplyDiscoveryScheduleUpsertedTx(ctx, tx, store.DiscoverySchedule{
					ID: sharedScheduleID, TenantID: tenantB, SourceID: tenantBSourceID, Name: "foreign-schedule-id",
					IntervalSeconds: 3600, Enabled: true, CreatedAt: now, UpdatedAt: now,
				})
			},
		},
		{
			name: "run",
			apply: func(tx pgx.Tx) error {
				return st.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
					ID: sharedRunID, TenantID: tenantB, SourceID: tenantBSourceID, Status: "queued",
					RequestedBy: "test", CreatedAt: now,
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := st.WithTenant(ctx, tenantB, tc.apply)
			if !errors.Is(err, store.ErrDiscoveryDeclarationEventConflict) {
				t.Fatalf("cross-tenant %s UUID reuse = %v, want ErrDiscoveryDeclarationEventConflict", tc.name, err)
			}
		})
	}
}
