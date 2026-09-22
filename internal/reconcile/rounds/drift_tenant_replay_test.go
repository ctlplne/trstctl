// SPDX-License-Identifier: BUSL-1.1

package rounds_test

import (
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

func TestTenantDriftSnapshotRebuildsWithoutOtherTenantsState(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	events := []eventspec.Event{
		witnessRecordedEvent(t, 1, at, "tenant-a", "same-id", witness.ClassPresence, "authority-a"),
		witnessRecordedEvent(t, 2, at, "tenant-b", "same-id", witness.ClassPresence, "authority-b"),
		completionEvent(t, 3, at.Add(time.Minute), "tenant-a", "same-id"),
	}
	p := rounds.NewDriftProjection(time.Hour)
	if err := p.Replay(events); err != nil {
		t.Fatal(err)
	}
	a, b := p.SnapshotForTenant("tenant-a"), p.SnapshotForTenant("tenant-b")
	if a.OpenWitnesses != 0 || a.ReplayWatermark != 3 || len(a.CompletionDurations) != 1 {
		t.Fatalf("tenant-a resolution was lost: %+v", a)
	}
	if b.OpenWitnesses != 1 || b.ReplayWatermark != 2 || len(b.CompletionDurations) != 0 {
		t.Fatalf("tenant-a completion changed tenant-b: %+v", b)
	}
	if len(a.WitnessClassCounts) != 1 || a.WitnessClassCounts[0].TenantID != "tenant-a" ||
		len(b.WitnessClassCounts) != 1 || b.WitnessClassCounts[0].TenantID != "tenant-b" {
		t.Fatalf("tenant counts mixed: a=%+v b=%+v", a, b)
	}
	if p.ReplayWatermark() != 3 {
		t.Fatalf("global projector cursor changed: %d", p.ReplayWatermark())
	}
	for _, tenant := range []string{"", "tenant-empty"} {
		view := p.SnapshotForTenant(tenant)
		if view.OpenWitnesses != 0 || view.ReplayWatermark != 0 || len(view.WitnessClassCounts) != 0 || len(view.CompletionDurations) != 0 {
			t.Errorf("empty scope %q exposed state: %+v", tenant, view)
		}
	}
	p.Reset()
	if view := p.SnapshotForTenant("tenant-a"); view.ReplayWatermark != 0 || view.OpenWitnesses != 0 || len(view.WitnessClassCounts) != 0 {
		t.Fatalf("reset retained tenant state: %+v", view)
	}
	if err := p.Replay(events); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, p.SnapshotForTenant("tenant-a")) || !reflect.DeepEqual(b, p.SnapshotForTenant("tenant-b")) {
		t.Fatal("replay did not reconstruct the separate tenant snapshots")
	}
	// Callers may modify their copy without mutating the shared projection.
	a.WitnessClassCounts[0].Count = 999
	a.CompletionDurations[0].Seconds = 999
	if fresh := p.SnapshotForTenant("tenant-a"); fresh.WitnessClassCounts[0].Count != 1 || fresh.CompletionDurations[0].Seconds != 60 {
		t.Fatalf("snapshot aliases the projection: %+v", fresh)
	}
}
