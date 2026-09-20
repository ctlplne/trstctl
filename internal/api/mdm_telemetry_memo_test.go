// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"testing"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestMDMTelemetryDoesNotReplayFromZeroPerRequest is the behavioural pin for
// AUD-201 follow-up F5/V21: mdmSCEPTelemetry runs on the GET policy read path
// and replayed the ENTIRE log from sequence zero on every request — the third
// such endpoint, left unmemoized when its two siblings were fixed. Its cost
// grew with mdm.intune_scep_challenge volume, the very traffic it reports on.
func TestMDMTelemetryDoesNotReplayFromZeroPerRequest(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open embedded log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	a := &API{log: log}
	const challenges = 30
	for i := 0; i < challenges; i++ {
		if _, err := log.Append(ctx, events.Event{
			Type: "mdm.intune_scep_challenge", TenantID: "tenant-a",
			Data: []byte(`{"decision":"allow","transaction_id":"tx"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := a.mdmSCEPTelemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if first.Allowed != challenges {
		t.Fatalf("telemetry counted %d allowed, want %d", first.Allowed, challenges)
	}

	// An unchanged log must cost ZERO additional scanned events.
	before := a.mdmTelemetryMemo.scannedEvents.Load()
	again, err := a.mdmSCEPTelemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if scanned := a.mdmTelemetryMemo.scannedEvents.Load() - before; scanned != 0 {
		t.Fatalf("a repeat telemetry read scanned %d events on an unchanged log; it replayed instead of serving the memo", scanned)
	}
	if again != first {
		t.Fatalf("memoized telemetry %+v disagrees with the first read %+v", again, first)
	}

	// New traffic catches up incrementally, not from zero.
	const extra = 4
	for i := 0; i < extra; i++ {
		if _, err := log.Append(ctx, events.Event{
			Type: "mdm.intune_scep_challenge.replay_rejected", TenantID: "tenant-a",
			Data: []byte(`{"reason":"replayed","transaction_id":"tx2"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	before = a.mdmTelemetryMemo.scannedEvents.Load()
	updated, err := a.mdmSCEPTelemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if scanned := a.mdmTelemetryMemo.scannedEvents.Load() - before; scanned > extra {
		t.Fatalf("catch-up scanned %d events after %d appends; it replayed from zero", scanned, extra)
	}
	if updated.ReplayRejected != extra || updated.Allowed != challenges {
		t.Fatalf("caught-up telemetry = %+v, want %d allowed and %d replay-rejected", updated, challenges, extra)
	}
}
