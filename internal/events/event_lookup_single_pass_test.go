// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Count real broker responses instead of asserting a machine-dependent runtime.
// Lookup must still inspect the whole retained cut, including when the ID is
// absent, but its internal privacy check must not double all stored-message I/O.
func TestEventLookupChecksRetainedHistoryWithoutDuplicateReads(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const count = 512
	ids := make([]string, count)
	for i := range ids {
		event, err := log.Append(ctx, Event{ID: fmt.Sprintf("lookup-budget-%d", i), Type: "test.lookup-budget", TenantID: "tenant-lookup-budget", Data: []byte(`{"safe":true}`)})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = event.ID
	}
	log.EnforceLegacySchedulerWriteFloor()
	for _, item := range []struct {
		name, id string
		found    bool
	}{
		{"first", ids[0], true}, {"last", ids[count-1], true}, {"absent", "missing-lookup-id", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := log.nc.Flush(); err != nil {
				t.Fatal(err)
			}
			before := log.nc.Stats().InMsgs
			got, found, err := log.EventByID(ctx, item.id)
			if err != nil || found != item.found || (found && got.ID != item.id) {
				t.Fatalf("lookup result found=%t id=%q err=%v", found, got.ID, err)
			}
			replies := log.nc.Stats().InMsgs - before
			t.Logf("retained events=%d broker responses=%d", count, replies)
			// Allow stream/generation metadata responses around the retained cut.
			if replies > count+32 {
				t.Fatalf("lookup read amplification: %d broker responses for %d retained events; at most one event pass plus metadata expected", replies, count)
			}
		})
	}
}
