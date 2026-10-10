// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
)

func TestEventIDIndexColdReplayAndDeletionUseExactGeneration(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := log.Append(ctx, Event{ID: "indexed-first", Type: "test.index", TenantID: "tenant-a", Data: []byte(`{"one":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := log.Append(ctx, Event{ID: "indexed-second", Type: "test.index", TenantID: "tenant-a", Data: []byte(`{"two":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got, found, err := log.EventByID(ctx, first.ID); err != nil || !found || got.Sequence != first.Sequence {
		t.Fatalf("first indexed lookup = %+v, %t, %v", got, found, err)
	}
	before, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened log: %v", err)
		}
	}()
	index, epoch, err := reopened.eventIDIndexFor(ctx, before)
	if err != nil {
		t.Fatal(err)
	}
	if covered, _, err := readEventIDCursor(ctx, index, epoch); err != nil || covered != second.Sequence {
		t.Fatalf("cold cursor = %d, %v, want %d", covered, err, second.Sequence)
	}
	if err := reopened.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	messages := reopened.nc.Stats().InMsgs
	if got, found, err := reopened.EventByID(ctx, second.ID); err != nil || !found || got.Sequence != second.Sequence {
		t.Fatalf("cold indexed lookup = %+v, %t, %v", got, found, err)
	}
	if replies := reopened.nc.Stats().InMsgs - messages; replies > 32 {
		t.Fatalf("cold indexed lookup used %d broker responses, want a bounded exact read", replies)
	}
	const otherSourceIndex = eventIDIndexPrefix + "OTHER"
	if _, err := reopened.js.CreateStream(ctx, jetstream.StreamConfig{
		Name: otherSourceIndex, Subjects: []string{eventIDIndexSubject + ".OTHER.>"},
		Storage: jetstream.FileStorage, Replicas: 1,
		Metadata: map[string]string{"trstctl.source_name": "OTHER_SOURCE", "trstctl.source_epoch": "OTHER"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Delete(ctx, first.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.js.Stream(ctx, otherSourceIndex); err != nil {
		t.Fatalf("unrelated source index was removed: %v", err)
	}
	after, err := reopened.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if eventIDSourceEpoch(before) == eventIDSourceEpoch(after) {
		t.Fatal("deletion reused the old source identity index")
	}
	if _, err := reopened.js.Stream(ctx, eventIDIndexPrefix+eventIDSourceEpoch(before)); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("deleted generation left its identity projection behind: %v", err)
	}
	if got, found, err := reopened.EventByID(ctx, first.ID); err != nil || found || got.ID != "" {
		t.Fatalf("deleted identity survived generation change: %+v, %t, %v", got, found, err)
	}
	if got, found, err := reopened.EventByID(ctx, second.ID); err != nil || !found || got.Sequence != second.Sequence {
		t.Fatalf("retained identity after deletion = %+v, %t, %v", got, found, err)
	}
}

func TestEventIDIndexCrashBetweenEntryAndCursorReplaysWithoutConflict(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := log.Append(ctx, Event{ID: fmt.Sprintf("crash-index-%d", i), Type: "test.index-crash", TenantID: "tenant-a", Data: []byte(`{"safe":true}`)}); err != nil {
			t.Fatal(err)
		}
	}
	_, source, _, err := log.resolveReplayStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	index, epoch, err := log.eventIDIndexFor(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.indexEventID(ctx, source, index, epoch, first); err != nil {
		t.Fatal(err)
	}
	if covered, _, err := readEventIDCursor(ctx, index, epoch); err != nil || covered != 0 {
		t.Fatalf("pre-crash cursor = %d, %v, want zero", covered, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close recovered log: %v", err)
		}
	}()
	for i := 1; i <= 2; i++ {
		id := fmt.Sprintf("crash-index-%d", i)
		if got, found, err := reopened.EventByID(ctx, id); err != nil || !found || got.Sequence != uint64(i) { // #nosec G115 -- the fixture index is bounded to one or two.
			t.Fatalf("recovered %s = %+v, %t, %v", id, got, found, err)
		}
	}
	index, epoch, err = reopened.eventIDIndexFor(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if covered, _, err := readEventIDCursor(ctx, index, epoch); err != nil || covered != 2 {
		t.Fatalf("recovered cursor = %d, %v, want 2", covered, err)
	}
}

func TestEventIDIndexLargeLagFailsClosedAndAdvancesByBoundedPages(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	const count = 1030
	for i := 0; i < count; i++ {
		if _, err := log.Append(ctx, Event{ID: fmt.Sprintf("lag-%d", i), Type: "test.index-lag", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if got, found, err := log.EventByID(ctx, "lag-0"); !errors.Is(err, ErrEventIDIndexBehind) || found || got.ID != "" {
		t.Fatalf("lagged lookup = %+v, %t, %v; want bounded retry", got, found, err)
	}
	state, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	index, epoch, err := log.eventIDIndexFor(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if covered, _, err := readEventIDCursor(ctx, index, epoch); err != nil || covered != eventIDIndexReadLimit {
		t.Fatalf("bounded cursor = %d, %v, want %d", covered, err, eventIDIndexReadLimit)
	}
	if got, found, err := log.EventByID(ctx, "lag-0"); err != nil || !found || got.Sequence != 1 {
		t.Fatalf("resumed bounded lookup = %+v, %t, %v", got, found, err)
	}
}

func TestEventIDIndexDetectsCrossTenantIdentityConflict(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	first := Event{ID: "cross-tenant-index-id", Type: "test.identity", TenantID: "tenant-a", Time: time.Now().UTC(), Data: []byte(`{"safe":true}`)}
	if _, err := log.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	other := storedEvent{ID: first.ID, Type: first.Type, TenantID: "tenant-b", Time: first.Time, SchemaVersion: DefaultSchemaVersion, Data: first.Data}
	raw, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, "events.tenant-b.test.identity", raw); err != nil {
		t.Fatal(err)
	}
	got, found, err := log.EventByID(ctx, first.ID)
	if !found || got.TenantID != first.TenantID || !errors.Is(err, ErrConflictingEventIdentity) {
		t.Fatalf("cross-tenant collision = %+v, %t, %v", got, found, err)
	}
}

func TestEventIDIndexRefusesRetentionCapInsteadOfRepairingIt(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	if _, err := log.Append(ctx, Event{ID: "retention-index", Type: "test.index", TenantID: "tenant-a"}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventByID(ctx, "retention-index"); err != nil || !found {
		t.Fatalf("build index: found=%t err=%v", found, err)
	}
	state, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	index, _, err := log.eventIDIndexFor(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	config := index.CachedInfo().Config
	config.MaxMsgs = 1 // Would evict an ID while preserving a complete cursor.
	if _, err := log.js.UpdateStream(ctx, config); err != nil {
		t.Fatal(err)
	}
	if got, found, err := log.EventByID(ctx, "retention-index"); err == nil || found || got.ID != "" {
		t.Fatalf("retention-capped index returned a result: %+v, %t, %v", got, found, err)
	}
}
