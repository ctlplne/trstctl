// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A266: with the background indexer, the identity projection reaches the head
// after a burst of appends that no lookup touched, so a keyed lookup right
// after an inventory import finds its event instead of refusing with
// ErrEventIDIndexBehind until enough lookups have caught the projection up.
// Close stops the indexer.
func TestBackgroundEventIDIndexerKeepsTheProjectionAtTheHead(t *testing.T) {
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
		state, err := log.schedulerSafetySnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		index, epoch, err := log.eventIDIndexFor(ctx, state)
		if err != nil {
			t.Fatal(err)
		}
		covered, _, err := readEventIDCursor(ctx, index, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if covered == state.LastSequence {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background indexer left the identity projection at %d of %d", covered, state.LastSequence)
		}
		time.Sleep(25 * time.Millisecond)
	}
	for i, id := range []string{"burst-0", fmt.Sprintf("burst-%d", count-1)} {
		got, found, err := log.EventByID(ctx, id)
		if err != nil || !found || got.ID != id || (i == 0 && got.Sequence != 1) {
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
