// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

func TestEventLookupWithholdsMatchWhenLaterHistoryNeedsSanitation(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "later unsafe history"
		if duplicate {
			name = "unsafe history after duplicate conflict"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			const dedupe = 100 * time.Millisecond
			log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, WithDuplicateWindowForTesting(dedupe))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			event := Event{ID: "lookup-safe-before-unsafe", Type: "test.lookup.safe", TenantID: "tenant-lookup", Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Data: []byte(`{"safe":true}`)}
			if _, err := log.Append(ctx, event); err != nil {
				t.Fatal(err)
			}
			if duplicate {
				time.Sleep(4 * dedupe)
				event.Data = []byte(`{"changed":true}`)
				if _, err := log.Append(ctx, event); err != nil {
					t.Fatal(err)
				}
			}
			const privateDetail = "synthetic-lookup-provider-detail"
			if _, err := log.Append(ctx, Event{ID: "unrelated-unsafe-lookup", Type: schedulerhistory.EventType, TenantID: "tenant-lookup", SchemaVersion: 1, Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + privateDetail + `"}`)}); err != nil {
				t.Fatal(err)
			}
			log.EnforceLegacySchedulerWriteFloor()
			got, found, err := log.EventByID(ctx, event.ID)
			if !errors.Is(err, schedulerhistory.ErrSanitationRequired) || found || got.ID != "" || len(got.Data) != 0 {
				t.Fatalf("unsafe history returned a lookup result: found=%t id=%q err=%v", found, got.ID, err)
			}
			if strings.Contains(err.Error(), privateDetail) {
				t.Fatal("unsafe detail disclosed in error")
			}
		})
	}
}
