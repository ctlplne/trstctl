// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

func countingSafetyStream(stream jetstream.Stream, reads *atomic.Int64) jetstream.Stream {
	return retainedReadTestStream{Stream: stream, get: func(ctx context.Context, sequence uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
		reads.Add(1)
		return stream.GetMsg(ctx, sequence, opts...)
	}}
}

func TestSchedulerSafetyIndexChecksOnlyNewTailAndRescansAfterDelete(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	const initial = 24
	for i := 0; i < initial; i++ {
		if _, err := log.Append(ctx, Event{Type: "test.scheduler-safe", TenantID: "tenant-a", Data: []byte(`{"safe":true}`)}); err != nil {
			t.Fatal(err)
		}
	}
	_, stream, head, err := log.resolveReplayStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != initial {
		t.Fatalf("fixture head = %d, want %d", head, initial)
	}
	var reads atomic.Int64
	if err := log.preflightSchedulerPrefix(ctx, countingSafetyStream(stream, &reads), head); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != initial {
		t.Fatalf("first scan read %d positions, want %d", got, head)
	}
	reads.Store(0)
	if err := log.preflightSchedulerPrefix(ctx, countingSafetyStream(stream, &reads), head); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 0 {
		t.Fatalf("unchanged prefix reread %d positions", got)
	}
	if _, err := log.Append(ctx, Event{Type: "test.scheduler-safe", TenantID: "tenant-a", Data: []byte(`{"tail":true}`)}); err != nil {
		t.Fatal(err)
	}
	_, stream, head, err = log.resolveReplayStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	if err := log.preflightSchedulerPrefix(ctx, countingSafetyStream(stream, &reads), head); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("append scanned %d positions, want only the new tail", got)
	}
	if err := log.Delete(ctx, 2); err != nil {
		t.Fatal(err)
	}
	_, stream, head, err = log.resolveReplayStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	if err := log.preflightSchedulerPrefix(ctx, countingSafetyStream(stream, &reads), head); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != initial+1 {
		t.Fatalf("deletion rescanned %d positions, want %d", got, head)
	}
}

func TestSchedulerSafetyIndexColdReopenAndUnsafeTail(t *testing.T) {
	ctx := context.Background()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append(ctx, Event{Type: "test.scheduler-safe", TenantID: "tenant-a", Data: []byte(`{"safe":true}`)}); err != nil {
			t.Fatal(err)
		}
	}
	log.EnforceLegacySchedulerWriteFloor()
	if _, err := log.CheckedHead(ctx); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Errorf("close reopened log: %v", err)
		}
	}()
	if log.legacySafetyPresent {
		t.Fatal("cold process inherited a verified prefix")
	}
	log.EnforceLegacySchedulerWriteFloor()
	if head, err := log.CheckedHead(ctx); err != nil || head != 3 {
		t.Fatalf("cold checked head = %d, %v", head, err)
	}
	unsafe := storedEvent{ID: NewID(), Type: schedulerhistory.EventType, TenantID: "tenant-a", Time: time.Now().UTC(), SchemaVersion: 1, Data: []byte(`{"schedule_id":"schedule-1","run_id":"r","status":"failed","error":"credential"}`)}
	// A raw broker ingress bypasses the normal append floor. The next checked
	// head must reject its tail before exposing any watermark to a caller.
	raw, err := json.Marshal(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, "events.scheduler.run", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := log.CheckedHead(ctx); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("unsafe tail checked head = %v, want sanitation refusal", err)
	}
}

func TestSchedulerSafetyIndexRejectsSameSizeGenerationReplacement(t *testing.T) {
	base := schedulerSafetyState{StreamSnapshot: StreamSnapshot{Name: "source", Generation: "legacy", FirstSequence: 1, LastSequence: 7, Messages: 7, Bytes: 700}, created: time.Unix(1, 0)}
	replaced := base
	replaced.created = time.Unix(2, 0)
	if appendOnlySince(base, replaced) {
		t.Fatal("same-size recreated stream retained stale safety index")
	}
}
