// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A266: with the background indexer, a burst of appends that no lookup
// touched leaves the identity projection within one lookup's reach, so a
// keyed lookup right after an inventory import finds its event instead of
// refusing with ErrEventIDIndexBehind until enough lookups have caught the
// projection up. Close stops the indexer.
func TestBackgroundEventIDIndexerKeepsTheProjectionWithinALookupsReach(t *testing.T) {
	ctx := t.Context()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, WithBackgroundEventIDIndexer())
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = log.Close()
		}
	}()
	count := 3*int(eventIDIndexReadLimit) + 17
	for i := 0; i < count; i++ {
		if _, err := log.Append(ctx, Event{ID: fmt.Sprintf("burst-%d", i), Type: "test.index-burst", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Minute)
	for {
		covered, head, err := log.EventIDIndexCovered(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head == uint64(count) && head-covered < eventIDIndexReadLimit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background indexer left the identity projection at %d of %d", covered, head)
		}
		time.Sleep(25 * time.Millisecond)
	}
	for i, id := range []string{fmt.Sprintf("burst-%d", count-1), "burst-0"} {
		got, found, err := log.EventByID(ctx, id)
		if err != nil || !found || got.ID != id || (i == 1 && got.Sequence != 1) {
			t.Fatalf("lookup %s after the burst = %+v, %t, %v", id, got, found, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	select {
	case <-log.idIndexDone:
	default:
		t.Fatal("the background indexer is still running after Close")
	}
}

// The indexer leaves a projection less than its lag behind to the lookups,
// which catch it up themselves, and indexes one further behind to the head.
func TestBackgroundEventIDIndexerWorksOnlyPastItsLag(t *testing.T) {
	ctx := t.Context()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	appendN := func(from, n int) {
		t.Helper()
		for i := from; i < from+n; i++ {
			if _, err := log.Append(ctx, Event{ID: fmt.Sprintf("lag-%d", i), Type: "test.index-lag", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	appendN(0, int(eventIDIndexerLag)-1)
	if err := log.catchUpEventIDIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if covered, _, err := log.EventIDIndexCovered(ctx); err != nil || covered != 0 {
		t.Fatalf("a projection %d behind was indexed to %d (%v); the lookups catch that up", eventIDIndexerLag-1, covered, err)
	}
	appendN(int(eventIDIndexerLag)-1, 2)
	if err := log.catchUpEventIDIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if covered, head, err := log.EventIDIndexCovered(ctx); err != nil || covered != head {
		t.Fatalf("a projection past the lag was indexed to %d of %d (%v)", covered, head, err)
	}
}

// Without the option a log runs no background indexer: a lookup alone
// advances the projection, by its bounded step.
func TestEventIDIndexerIsOptIn(t *testing.T) {
	log, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if log.idIndexKick != nil || log.idIndexDone != nil {
		t.Fatal("a log opened without WithBackgroundEventIDIndexer runs the background indexer")
	}
}
