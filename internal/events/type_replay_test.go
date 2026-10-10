// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestReplayTenantTypesThroughUsesSubjectIndexAndRetainedCut(t *testing.T) {
	log := openEmbedded(t)
	ctx := t.Context()
	first, err := log.Append(ctx, events.Event{Type: "test.selected", TenantID: "tenant-a", Data: []byte(`{"n":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	for range 120 {
		if _, err := log.Append(ctx, events.Event{Type: "test.unrelated", TenantID: "tenant-b", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	second, err := log.Append(ctx, events.Event{Type: "test.other", TenantID: "tenant-a", Data: []byte(`{"n":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: "test.selected", TenantID: "tenant-b", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	third, err := log.Append(ctx, events.Event{Type: "test.selected", TenantID: "tenant-a", Data: []byte(`{"n":3}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	if err := log.ReplayTenantTypesThrough(ctx, "tenant-a", 1, second.Sequence,
		[]string{"test.selected", "test.other", "test.selected"}, func(ev events.Event) error {
			got = append(got, ev.Sequence)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint64{first.Sequence, second.Sequence}) {
		t.Fatalf("selected cut = %v, want first and second only (third=%d)", got, third.Sequence)
	}
	got = nil
	if err := log.ReplayTenantTypesThrough(ctx, "tenant-a", second.Sequence, third.Sequence,
		[]string{"test.selected", "test.other"}, func(ev events.Event) error {
			got = append(got, ev.Sequence)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint64{second.Sequence, third.Sequence}) {
		t.Fatalf("selected suffix = %v, want second and third", got)
	}
	stop := errors.New("stop")
	if err := log.ReplayTenantTypesThrough(ctx, "tenant-a", 1, third.Sequence,
		[]string{"test.selected"}, func(events.Event) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback cancellation = %v, want stop", err)
	}
	if err := log.ReplayTenantTypesThrough(context.Background(), "tenant-a", 1, third.Sequence,
		[]string{"test.*"}, func(events.Event) error { return nil }); err == nil {
		t.Fatal("wildcard event type was accepted")
	}
}

type replayLaneRouter struct{ lane string }

func (r replayLaneRouter) TargetsFor(context.Context, string) (tenancy.Targets, error) {
	return tenancy.Targets{JetStreamSubjectLane: r.lane}, nil
}

func (r replayLaneRouter) JetStreamSubjectLanes(context.Context) ([]string, error) {
	return []string{r.lane}, nil
}

func TestReplayTenantTypesThroughColdRestartFindsHistoricalLanes(t *testing.T) {
	tenancy.SetRouter(nil)
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendSelected := func() events.Event {
		t.Helper()
		event, err := log.Append(t.Context(), events.Event{Type: "test.selected", TenantID: "tenant-a", Data: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	pooled := appendSelected()
	tenancy.SetRouter(replayLaneRouter{lane: "lane-a"})
	silo := appendSelected()
	tenancy.SetRouter(replayLaneRouter{lane: "lane.multi"})
	legacyMultiTokenLane := appendSelected()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	tenancy.SetRouter(nil)
	log, err = events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	var got []uint64
	if err := log.ReplayTenantTypesThrough(t.Context(), "tenant-a", 1, legacyMultiTokenLane.Sequence,
		[]string{"test.selected"}, func(ev events.Event) error {
			got = append(got, ev.Sequence)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint64{pooled.Sequence, silo.Sequence, legacyMultiTokenLane.Sequence}) {
		t.Fatalf("cold typed replay = %v, want all historical lanes", got)
	}
}

func TestReplayTenantTypesThroughDoesNotDuplicateOverlappingTypeSuffixes(t *testing.T) {
	log := openEmbedded(t)
	for _, eventType := range []string{"test.selected", "selected"} {
		if _, err := log.Append(t.Context(), events.Event{Type: eventType, TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	if err := log.ReplayTenantTypesThrough(t.Context(), "tenant-a", 1, 2,
		[]string{"selected", "test.selected"}, func(ev events.Event) error {
			got = append(got, ev.Type)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"test.selected", "selected"}) {
		t.Fatalf("overlapping type suffixes = %v", got)
	}
}
