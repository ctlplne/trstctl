// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	discoveryConvergenceSegmentID = "10000000-0000-4000-8000-000000000301"
	discoveryConvergenceSourceID  = "10000000-0000-4000-8000-000000000302"
)

// TestTailWorkerDiscoveryDeclarationsConvergePastInlineProjection reproduces
// the served double-writer boundary exactly: JetStream already contains the
// immutable declarations, the inline projector has committed both rows, and
// the durable tail then reaches those same events before a later unrelated
// event. Exact replay must converge, advance the checkpoint, clear tail health,
// and rebuild to the same read model without a process restart.
func TestTailWorkerDiscoveryDeclarationsConvergePastInlineProjection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event events.Event
	}{
		{
			name: "segment primary key",
			event: events.Event{
				Type: projections.EventDiscoverySegmentUpserted, TenantID: tenantA,
				Data: mustDiscoveryConvergenceJSON(t, projections.DiscoverySegmentUpserted{
					ID: discoveryConvergenceSegmentID, Name: "qa-dmz",
					Ranges: []string{"10.42.0.0/24"}, StalenessHours: 24,
				}),
			},
		},
		{
			name: "source primary key",
			event: events.Event{
				Type: projections.EventDiscoverySourceUpserted, TenantID: tenantA,
				// PostgreSQL stores timestamptz at microsecond precision. A production
				// event may carry nanoseconds, so convergence must compare the exact
				// database-normalized instant rather than reject a correct fresh row.
				Time: time.Date(2026, time.August, 26, 19, 58, 50, 123456789, time.UTC),
				Data: mustDiscoveryConvergenceJSON(t, projections.DiscoverySourceUpserted{
					ID: discoveryConvergenceSourceID, Kind: "manual", Name: "qa-manual-source",
					Config: json.RawMessage(`{}`),
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			log := openLog(t)
			ctx := context.Background()
			proj := projections.New(s)

			mustAppend(t, log, events.Event{
				Type: projections.EventTenantRegistered, TenantID: tenantA,
				Data: tenantRegistered("Acme"),
			})
			if err := proj.ProjectCatchUp(ctx, log); err != nil {
				t.Fatalf("project tenant base: %v", err)
			}
			declaration := mustAppendDiscoveryConvergenceEvent(t, log, tc.event)
			later := mustAppendDiscoveryConvergenceEvent(t, log, events.Event{
				Type: projections.EventOwnerCreated, TenantID: tenantA,
				Data: ownerCreated("10000000-0000-4000-8000-000000000303", "after-discovery-declaration"),
			})

			rowInserted := make(chan struct{})
			releaseCommit := make(chan struct{})
			inlineDone := make(chan error, 1)
			go func() {
				inlineDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					if err := proj.ApplyTx(ctx, tx, declaration); err != nil {
						return err
					}
					close(rowInserted)
					<-releaseCommit
					return nil
				})
			}()
			select {
			case <-rowInserted:
			case err := <-inlineDone:
				t.Fatalf("inline declaration projection: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("inline declaration projection did not reach the commit fence")
			}

			tailCtx, cancelTail := context.WithCancel(ctx)
			tailDone := make(chan error, 1)
			worker := projections.NewTailWorker(log, proj, nil, time.Second)
			go func() { tailDone <- worker.Run(tailCtx) }()
			select {
			case err := <-tailDone:
				close(releaseCommit)
				cancelTail()
				t.Fatalf("tail returned before the inline uniqueness lock committed: %v", err)
			case <-time.After(100 * time.Millisecond):
				// The tail is deterministically waiting on the inline unique row.
			}
			close(releaseCommit)
			if err := <-inlineDone; err != nil {
				cancelTail()
				t.Fatalf("inline declaration commit: %v", err)
			}

			deadline := time.NewTimer(20 * time.Second)
			defer deadline.Stop()
			for {
				checkpoint, err := s.ProjectionCheckpoint(ctx)
				if err != nil {
					cancelTail()
					t.Fatalf("read convergence checkpoint: %v", err)
				}
				if checkpoint >= later.Sequence {
					break
				}
				select {
				case err := <-tailDone:
					cancelTail()
					t.Fatalf("tail stopped before later seq %d (checkpoint=%d): %v",
						later.Sequence, checkpoint, err)
				case <-deadline.C:
					cancelTail()
					t.Fatalf("tail did not converge through later seq %d (checkpoint=%d)", later.Sequence, checkpoint)
				case <-time.After(25 * time.Millisecond):
				}
			}
			cancelTail()
			select {
			case <-tailDone:
			case <-time.After(5 * time.Second):
				t.Fatal("tail worker did not stop after convergence cancellation")
			}

			health, err := s.ProjectionTailHealth(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if health.AppliedSequence < later.Sequence || health.FailedSequence != 0 || health.LastError != "" {
				t.Fatalf("projection tail health after convergence = %+v, want clean through seq %d", health, later.Sequence)
			}

			warmSegments, warmSources := discoveryDeclarationRows(t, s)
			if len(warmSegments)+len(warmSources) != 1 || ownerCount(t, s, tenantA) != 1 {
				t.Fatalf("warm declaration model = segments:%+v sources:%+v owners:%d, want one declaration and later owner",
					warmSegments, warmSources, ownerCount(t, s, tenantA))
			}
			if err := proj.Rebuild(ctx, log); err != nil {
				t.Fatalf("rebuild converged discovery declaration: %v", err)
			}
			rebuiltSegments, rebuiltSources := discoveryDeclarationRows(t, s)
			if !reflect.DeepEqual(rebuiltSegments, warmSegments) || !reflect.DeepEqual(rebuiltSources, warmSources) {
				t.Fatalf("rebuild changed discovery declaration:\n warm segments=%+v\n rebuilt segments=%+v\n warm sources=%+v\n rebuilt sources=%+v",
					warmSegments, rebuiltSegments, warmSources, rebuiltSources)
			}
		})
	}
}

// TestConcurrentDiscoverySourceFirstProjectionConverges reproduces the other
// served double-writer order: several projector paths reach a brand-new source
// before any row is visible. PostgreSQL may discover the tenant-scoped
// (tenant_id, id) uniqueness collision before the legacy global primary-key
// collision, so the projection SQL must name the tenant-scoped arbiter. Every
// contender is applying the same immutable event and must converge to one row.
func TestConcurrentDiscoverySourceFirstProjectionConverges(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	event := projectorEvent(t, projections.EventDiscoverySourceUpserted,
		projections.DiscoverySourceUpserted{
			ID: discoveryConvergenceSourceID, Kind: "drift", Name: "concurrent-first-source",
			Config: json.RawMessage(`{"watched":[]}`),
		})
	event.ID = "10000000-0000-4000-8000-000000000307"
	event.Sequence = 11

	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	for range writers {
		go func() {
			<-start
			errs <- projections.New(s).Apply(ctx, event)
		}()
	}
	close(start)
	for range writers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent exact-event projection did not converge: %v", err)
		}
	}

	_, sources := discoveryDeclarationRows(t, s)
	if len(sources) != 1 || sources[0].ID != discoveryConvergenceSourceID ||
		sources[0].Name != "concurrent-first-source" {
		t.Fatalf("concurrent source projection = %+v, want one exact source", sources)
	}
}

// TestDiscoverySegmentLegacyRowIsBoundToItsFirstEvent proves the online
// migration path: a pre-0199 row keeps its operator-visible name while its
// first immutable declaration replaces the random legacy ID with the stable
// event ID. From that point on, unversioned writes fail closed and a cold
// rebuild produces the exact same declaration.
func TestDiscoverySegmentLegacyRowIsBoundToItsFirstEvent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	proj := projections.New(s)

	mustAppend(t, log, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("Acme"),
	})
	if err := proj.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project tenant base: %v", err)
	}
	legacy, err := s.UpsertDiscoverySegment(ctx, tenantA, store.DiscoverySegment{
		Name: "legacy-dmz", Ranges: []string{"10.10.0.0/16"}, StalenessHours: 168,
	})
	if err != nil {
		t.Fatalf("seed pre-0199 segment: %v", err)
	}
	if legacy.ID == discoveryConvergenceSegmentID {
		t.Fatal("legacy fixture unexpectedly used the deterministic event ID")
	}

	declaration := mustAppendDiscoveryConvergenceEvent(t, log, events.Event{
		Type: projections.EventDiscoverySegmentUpserted, TenantID: tenantA,
		Data: mustDiscoveryConvergenceJSON(t, projections.DiscoverySegmentUpserted{
			ID: discoveryConvergenceSegmentID, Name: "legacy-dmz",
			Ranges: []string{"10.10.0.0/16", "10.11.0.0/16"}, StalenessHours: 24,
		}),
	})
	if err := proj.Apply(ctx, declaration); err != nil {
		t.Fatalf("bind legacy segment to first declaration event: %v", err)
	}
	warmSegments, _ := discoveryDeclarationRows(t, s)
	boundEventID, boundSequence := discoverySegmentProjectionBinding(t, s, "legacy-dmz")
	if len(warmSegments) != 1 || warmSegments[0].ID != discoveryConvergenceSegmentID ||
		boundEventID != declaration.ID || boundSequence != declaration.Sequence {
		t.Fatalf("legacy segment was not bound to its first event: %+v", warmSegments)
	}
	if _, err := s.UpsertDiscoverySegment(ctx, tenantA, store.DiscoverySegment{
		Name: "legacy-dmz", Ranges: []string{"0.0.0.0/0"}, StalenessHours: 1,
	}); !errors.Is(err, store.ErrDiscoveryDeclarationEventConflict) {
		t.Fatalf("unversioned overwrite after event binding error = %v, want declaration conflict", err)
	}

	if err := proj.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild adopted segment: %v", err)
	}
	rebuiltSegments, _ := discoveryDeclarationRows(t, s)
	if !reflect.DeepEqual(rebuiltSegments, warmSegments) {
		t.Fatalf("legacy adoption did not converge:\n warm=%+v\n rebuilt=%+v", warmSegments, rebuiltSegments)
	}
}

// TestDiscoveryDeclarationSameEventDivergenceFailsClosed proves idempotence is
// not a blanket last-writer-wins escape hatch. Replaying one immutable event ID
// and sequence with different declaration fields must return a stable domain
// conflict and leave the accepted state byte-for-field unchanged.
func TestDiscoveryDeclarationSameEventDivergenceFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		eventType  string
		original   any
		divergent  any
		assertSame func(*testing.T, *store.Store)
	}{
		{
			name:      "segment ranges",
			eventType: projections.EventDiscoverySegmentUpserted,
			original: projections.DiscoverySegmentUpserted{
				ID: discoveryConvergenceSegmentID, Name: "qa-dmz",
				Ranges: []string{"10.42.0.0/24"}, StalenessHours: 24,
			},
			divergent: projections.DiscoverySegmentUpserted{
				ID: discoveryConvergenceSegmentID, Name: "qa-dmz",
				Ranges: []string{"0.0.0.0/0"}, StalenessHours: 24,
			},
			assertSame: func(t *testing.T, s *store.Store) {
				got, err := s.GetDiscoverySegmentByName(context.Background(), tenantA, "qa-dmz")
				if err != nil || !reflect.DeepEqual(got.Ranges, []string{"10.42.0.0/24"}) {
					t.Fatalf("divergent replay changed segment: %+v err=%v", got, err)
				}
			},
		},
		{
			name:      "source config",
			eventType: projections.EventDiscoverySourceUpserted,
			original: projections.DiscoverySourceUpserted{
				ID: discoveryConvergenceSourceID, Kind: "network", Name: "qa-dmz-tls",
				Config: json.RawMessage(`{"segment":"qa-dmz","ports":[443]}`),
			},
			divergent: projections.DiscoverySourceUpserted{
				ID: discoveryConvergenceSourceID, Kind: "network", Name: "qa-dmz-tls",
				Config: json.RawMessage(`{"segment":"qa-dmz","ports":[22]}`),
			},
			assertSame: func(t *testing.T, s *store.Store) {
				got, err := s.GetDiscoverySource(context.Background(), tenantA, discoveryConvergenceSourceID)
				if err != nil || string(got.Config) != `{"ports": [443], "segment": "qa-dmz"}` {
					t.Fatalf("divergent replay changed source: %+v err=%v", got, err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
				t.Fatal(err)
			}
			original := projectorEvent(t, tc.eventType, tc.original)
			original.ID = "10000000-0000-4000-8000-000000000304"
			original.Sequence = 7
			if err := projections.New(s).Apply(ctx, original); err != nil {
				t.Fatalf("apply original declaration: %v", err)
			}
			divergent := original
			divergent.Data = mustDiscoveryConvergenceJSON(t, tc.divergent)
			err := projections.New(s).Apply(ctx, divergent)
			if err == nil || !strings.Contains(err.Error(), "discovery declaration event conflict") {
				t.Fatalf("divergent same-event replay error = %v, want stable discovery declaration event conflict", err)
			}
			tc.assertSame(t, s)
		})
	}
}

// TestDiscoverySourceGlobalIDCannotCrossTenant keeps the legacy global source
// primary key from becoming a cross-tenant overwrite when the conflict target
// is corrected. RLS and the projection's tenant binding must fail closed.
func TestDiscoverySourceGlobalIDCannotCrossTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant.id, Name: tenant.name}); err != nil {
			t.Fatal(err)
		}
	}
	base := projectorEventForTenant(t, tenantA, projections.EventDiscoverySourceUpserted,
		projections.DiscoverySourceUpserted{
			ID: discoveryConvergenceSourceID, Kind: "network", Name: "acme-source",
			Config: json.RawMessage(`{"segment":"acme"}`),
		})
	base.ID = "10000000-0000-4000-8000-000000000305"
	base.Sequence = 9
	if err := projections.New(s).Apply(ctx, base); err != nil {
		t.Fatalf("apply tenant A source: %v", err)
	}
	foreign := projectorEventForTenant(t, tenantB, projections.EventDiscoverySourceUpserted,
		projections.DiscoverySourceUpserted{
			ID: discoveryConvergenceSourceID, Kind: "network", Name: "beta-source",
			Config: json.RawMessage(`{"segment":"beta"}`),
		})
	foreign.ID = "10000000-0000-4000-8000-000000000306"
	foreign.Sequence = 10
	if err := projections.New(s).Apply(ctx, foreign); err == nil {
		t.Fatal("cross-tenant reuse of the global discovery source ID succeeded")
	}
	if sources, err := s.ListDiscoverySourcesPage(ctx, tenantB, store.ZeroUUID, 10); err != nil || len(sources) != 0 {
		t.Fatalf("tenant B sees source rows after rejected overwrite: %+v err=%v", sources, err)
	}
	got, err := s.GetDiscoverySource(ctx, tenantA, discoveryConvergenceSourceID)
	if err != nil || got.Name != "acme-source" {
		t.Fatalf("tenant A source changed after foreign overwrite: %+v err=%v", got, err)
	}
}

func mustDiscoveryConvergenceJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustAppendDiscoveryConvergenceEvent(t *testing.T, log *events.Log, event events.Event) events.Event {
	t.Helper()
	appended, err := log.Append(context.Background(), event)
	if err != nil {
		t.Fatalf("append %s: %v", event.Type, err)
	}
	return appended
}

func discoveryDeclarationRows(t *testing.T, s *store.Store) ([]store.DiscoverySegment, []store.DiscoverySource) {
	t.Helper()
	segments, err := s.ListDiscoverySegments(context.Background(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := s.ListDiscoverySourcesPage(context.Background(), tenantA, store.ZeroUUID, 10)
	if err != nil {
		t.Fatal(err)
	}
	return segments, sources
}

func discoverySegmentProjectionBinding(t *testing.T, s *store.Store, name string) (string, uint64) {
	t.Helper()
	var eventID string
	var sequence int64
	if err := s.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT COALESCE(projection_event_id, ''), projection_event_sequence
			   FROM discovery_segments
			  WHERE tenant_id = $1 AND name = $2`, tenantA, name).
			Scan(&eventID, &sequence)
	}); err != nil {
		t.Fatal(err)
	}
	return eventID, uint64(sequence) // #nosec G115 -- migration 0199 constrains the sequence to non-negative bigint values
}
