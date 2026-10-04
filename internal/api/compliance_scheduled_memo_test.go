// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestScheduledAuditSummaryMemoPinsHeadAndBoundsWindows(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	a := &API{log: log}
	const tenant = "11111111-1111-1111-1111-111111111111"
	due := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	schedule := store.ComplianceReportSchedule{ID: "22222222-2222-4222-8222-222222222222", NextRunAt: due, IntervalSeconds: 3600}
	read := func() scheduledAuditSummary {
		t.Helper()
		wire, err := a.buildScheduledAuditSummary(ctx, tenant, schedule)
		if err != nil {
			t.Fatal(err)
		}
		var out scheduledAuditSummary
		if err := json.Unmarshal(wire, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := read(); got.RecordCount != 0 || got.SourceHeadSequence != 0 {
		t.Fatalf("empty log summary = %+v", got)
	}
	for _, id := range []string{tenant, "33333333-3333-4333-8333-333333333333"} {
		if _, err := log.Append(ctx, events.Event{TenantID: id, Type: "policy.decision", Time: due.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	first := read()
	if first.RecordCount != 1 || first.SourceHeadSequence != 2 {
		t.Fatalf("tenant-window summary = %+v", first)
	}
	scanned := a.scheduledAuditMemo.scannedEvents.Load()
	if again := read(); again.RecordCount != first.RecordCount || a.scheduledAuditMemo.scannedEvents.Load() != scanned {
		t.Fatalf("unchanged head replayed instead of reusing summary: %+v", again)
	}
	if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: "policy.denied", Time: due.Add(-30 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.RecordCount != 2 || got.SourceHeadSequence != 3 {
		t.Fatalf("appended event did not invalidate signed source head: %+v", got)
	}
	for i := 0; i < 80; i++ {
		schedule.NextRunAt = due.Add(time.Duration(i+1) * time.Hour)
		read()
	}
	if got := len(a.scheduledAuditMemo.byTenant); got > 64 {
		t.Fatalf("scheduled-window memo grew to %d entries, want at most 64", got)
	}
}
