// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

func TestRetainedReplayAndLookupShareOneHistoryRead(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const count = 512
	for i := range count {
		_, err := log.Append(ctx, Event{ID: fmt.Sprintf("replay-lookup-%d", i), Type: "test.replay-lookup", TenantID: "tenant-replay-lookup", Data: []byte(`{"safe":true}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, floor := range []bool{false, true} {
		if floor {
			log.EnforceLegacySchedulerWriteFloor()
		}
		for _, id := range []string{"replay-lookup-0", "replay-lookup-511", "replay-lookup-missing"} {
			t.Run(fmt.Sprintf("floor=%t/%s", floor, id), func(t *testing.T) {
				if err := log.nc.Flush(); err != nil {
					t.Fatal(err)
				}
				before := log.nc.Stats().InMsgs
				var seen []uint64
				visit := func(e Event) error { seen = append(seen, e.Sequence); return nil }
				got, found, err := log.ReplayThroughAndLookup(ctx, 2, count, id, visit)
				if err != nil || found != (id != "replay-lookup-missing") || (found && got.ID != id) {
					t.Fatalf("lookup found=%t id=%q err=%v", found, got.ID, err)
				}
				if len(seen) != count-1 || seen[0] != 2 || seen[len(seen)-1] != count {
					t.Fatalf("replay did not preserve its complete requested prefix: %v", seen)
				}
				budget := uint64(count + 64)
				if floor {
					budget += count
				} // Keep the full privacy preflight.
				if replies := log.nc.Stats().InMsgs - before; replies > budget {
					t.Fatalf("recovery and lookup repeated source reads: replies=%d budget=%d", replies, budget)
				}
			})
		}
	}
}

func TestRetainedReplayLookupPreservesIdentityAndCallbackIsolation(t *testing.T) {
	for _, field := range []string{"exact", "payload", "actor", "tenant", "time", "schema", "type"} {
		t.Run(field, func(t *testing.T) {
			ctx := t.Context()
			log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			original, err := log.Append(ctx, Event{ID: "lookup-immutable", Type: "test.lookup", TenantID: "tenant-lookup", Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Data: []byte(`{"safe":true}`), Actor: &Actor{Subject: "operator", Roles: []string{"operator"}}})
			if err != nil {
				t.Fatal(err)
			}
			duplicate := storedEvent{ID: original.ID, Type: original.Type, TenantID: original.TenantID, Time: original.Time, SchemaVersion: original.SchemaVersion, Data: original.Data, Actor: original.Actor}
			switch field {
			case "payload":
				duplicate.Data = []byte(`{"safe":false}`)
			case "actor":
				duplicate.Actor = &Actor{Subject: "other", Roles: []string{"operator"}}
			case "tenant":
				duplicate.TenantID = "other-tenant"
			case "time":
				duplicate.Time = duplicate.Time.Add(time.Second)
			case "schema":
				duplicate.SchemaVersion++
			case "type":
				duplicate.Type = "test.other"
			}
			raw, err := json.Marshal(duplicate)
			if err != nil {
				t.Fatal(err)
			}
			// Preserve two actual broker positions without its finite message-ID
			// deduplication hiding the exact/conflicting retained-envelope case.
			ack, err := log.js.Publish(ctx, "events.tenant-lookup.test.lookup", raw)
			if err != nil {
				t.Fatal(err)
			}
			if ack.Sequence != 2 {
				t.Fatalf("duplicate sequence=%d", ack.Sequence)
			}
			got, found, err := log.ReplayThroughAndLookup(ctx, 1, 2, original.ID, func(e Event) error {
				e.Data[0] = '!'
				e.Actor.Subject = "callback mutation"
				e.Actor.Roles[0] = "changed"
				return nil
			})
			if field == "exact" {
				if err != nil || !found || !sameRetainedEvent(got, original) || got.Sequence != 1 {
					t.Fatalf("canonical lookup was changed: found=%t err=%v event=%+v", found, err, got)
				}
			} else if !errors.Is(err, ErrConflictingEventIdentity) || found || got.ID != "" {
				t.Fatalf("conflicting %s returned canonical result: found=%t err=%v", field, found, err)
			}
		})
	}
}

func TestRetainedReplayLookupKeepsPrivacyCutAndErrorBoundaries(t *testing.T) {
	ctx := t.Context()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	first, err := log.Append(ctx, Event{ID: "cut-safe", Type: "test.cut", TenantID: "tenant-cut", Data: []byte(`{"safe":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	unsafe, err := log.Append(ctx, Event{ID: "cut-unsafe", Type: schedulerhistory.EventType, TenantID: "tenant-cut", SchemaVersion: 1, Data: []byte(`{"schedule_id":"s","run_id":"r","status":"failed","error":"synthetic-private-detail"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got, found, err := log.ReplayThroughAndLookup(ctx, unsafe.Sequence+1, unsafe.Sequence, unsafe.ID, func(Event) error { return nil }); !errors.Is(err, schedulerhistory.ErrSanitationRequired) || found || got.ID != "" {
		t.Fatalf("unsafe selected envelope escaped without the global floor: found=%t err=%v", found, err)
	}
	log.EnforceLegacySchedulerWriteFloor()
	callbacks := 0
	visit := func(Event) error { callbacks++; return nil }
	got, found, err := log.ReplayThroughAndLookup(ctx, 1, unsafe.Sequence, first.ID, visit)
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) || found || got.ID != "" || callbacks != 0 {
		t.Fatalf("privacy preflight: callbacks=%d found=%t err=%v", callbacks, found, err)
	}
	got, found, err = log.ReplayThroughAndLookup(ctx, first.Sequence+1, first.Sequence, first.ID, visit)
	if err != nil || !found || got.ID != first.ID || callbacks != 0 {
		t.Fatalf("finite empty replay lost older lookup: callbacks=%d found=%t err=%v", callbacks, found, err)
	}
	want := errors.New("projection failed")
	got, found, err = log.ReplayThroughAndLookup(ctx, 1, first.Sequence, first.ID, func(Event) error { return want })
	if !errors.Is(err, want) || found || got.ID != "" {
		t.Fatalf("callback failure returned lookup: found=%t err=%v", found, err)
	}
	for _, name := range []string{"future-cut", "empty-id", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			readCtx := ctx
			cut := first.Sequence
			id := first.ID
			callbacks = 0
			switch name {
			case "future-cut":
				cut = unsafe.Sequence + 1
			case "empty-id":
				id = ""
			case "cancelled":
				var cancel context.CancelFunc
				readCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, found, err := log.ReplayThroughAndLookup(readCtx, 1, cut, id, visit)
			if err == nil || found || got.ID != "" || callbacks != 0 {
				t.Fatalf("%s crossed error boundary: callbacks=%d found=%t err=%v", name, callbacks, found, err)
			}
		})
	}
}
