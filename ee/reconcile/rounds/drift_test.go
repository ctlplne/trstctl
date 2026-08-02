// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds_test

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/eventspec"
)

// Drift metrics are a replayable projection (XREC-claim-12).
func TestDrift_ProjectionReconstructable(t *testing.T) {
	base := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	events := []eventspec.Event{
		witnessRecordedEvent(t, 1, base, "tenant-a", "witness-1", witness.ClassPresence, "vault", "kms"),
		completionEvent(t, 2, base.Add(10*time.Minute), "tenant-a", "witness-1"),
	}
	first := rounds.NewDriftProjection(time.Hour)
	second := rounds.NewDriftProjection(time.Hour)
	if err := first.Replay(events); err != nil {
		t.Fatalf("first replay: %v", err)
	}
	if err := second.Replay(events); err != nil {
		t.Fatalf("second replay: %v", err)
	}
	a := first.Snapshot()
	b := second.Snapshot()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("snapshots differ:\n%+v\n%+v", a, b)
	}
	if a.ReplayWatermark != 2 || a.OpenWitnesses != 0 || len(a.CompletionDurations) != 1 ||
		a.CompletionDurations[0].Seconds != int64((10*time.Minute).Seconds()) {
		t.Fatalf("snapshot = %+v, want deterministic completion duration and watermark", a)
	}
}

// Per-class drift counts rebuilt from the ledger (XREC-claim-12).
func TestDrift_CountsPerClassPerWindow(t *testing.T) {
	base := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	events := []eventspec.Event{
		witnessRecordedEvent(t, 1, base.Add(5*time.Minute), "tenant-a", "witness-1", witness.ClassPresence, "vault", "kms"),
		witnessRecordedEvent(t, 2, base.Add(20*time.Minute), "tenant-a", "witness-2", witness.ClassStaleness, "vault"),
		witnessRecordedEvent(t, 3, base.Add(time.Hour+5*time.Minute), "tenant-a", "witness-3", witness.ClassPresence, "kms"),
		completionEvent(t, 4, base.Add(35*time.Minute), "tenant-a", "witness-1"),
	}
	proj := rounds.NewDriftProjection(time.Hour)
	if err := proj.Replay(events); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	snap := proj.Snapshot()
	assertClassCount(t, snap, "tenant-a", "vault", witness.ClassPresence, base, 1)
	assertClassCount(t, snap, "tenant-a", "kms", witness.ClassPresence, base, 1)
	assertClassCount(t, snap, "tenant-a", "vault", witness.ClassStaleness, base, 1)
	assertClassCount(t, snap, "tenant-a", "kms", witness.ClassPresence, base.Add(time.Hour), 1)
	if snap.OpenWitnesses != 2 {
		t.Fatalf("open witnesses = %d, want 2", snap.OpenWitnesses)
	}
	if len(snap.CompletionDurations) != 1 || snap.CompletionDurations[0].Seconds != int64((30*time.Minute).Seconds()) {
		t.Fatalf("completion durations = %+v, want one 30m duration", snap.CompletionDurations)
	}
}

func witnessRecordedEvent(t *testing.T, seq uint64, at time.Time, tenantID, witnessID, class string, authorities ...string) eventspec.Event {
	t.Helper()
	entries := []witness.Entry{{
		RecordKey: canon.RecordKey{TenantID: tenantID, RecordType: canon.RecordTypeX509Certificate, StableID: witnessID + "-record"},
		Class:     class,
	}}
	body := witness.Body{
		WitnessID:   witnessID,
		RoundID:     "round-" + witnessID,
		TenantID:    tenantID,
		SpecVersion: canon.SpecVersionV1,
		Entries:     entries,
		GeneratedAt: at.Unix(),
	}
	payload := witness.WitnessRecorded{
		WitnessID:   witnessID,
		TenantID:    tenantID,
		RoundID:     body.RoundID,
		WitnessHash: hex.EncodeToString(body.WitnessHash()),
		Authorities: authorities,
		Evidence: witness.Evidence{
			Body: body,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal witness: %v", err)
	}
	return eventspec.Event{Type: witness.EventTypeWitnessRecorded, TenantID: tenantID, Time: at, Sequence: seq, SchemaVersion: eventspec.DefaultSchemaVersion, Data: data}
}

func completionEvent(t *testing.T, seq uint64, at time.Time, tenantID, witnessID string) eventspec.Event {
	t.Helper()
	payload := quarantine.Completed{
		CompletionID: "completion-" + witnessID,
		TenantID:     tenantID,
		WitnessID:    witnessID,
		WitnessHash:  "hash-" + witnessID,
		PlanID:       "plan-" + witnessID,
		PlanHash:     "plan-hash-" + witnessID,
		CompletedAt:  at.Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal completion: %v", err)
	}
	return eventspec.Event{Type: quarantine.EventTypeCompleted, TenantID: tenantID, Time: at, Sequence: seq, SchemaVersion: eventspec.DefaultSchemaVersion, Data: data}
}

func assertClassCount(t *testing.T, snap rounds.DriftSnapshot, tenantID, authorityID, class string, window time.Time, want int64) {
	t.Helper()
	for _, count := range snap.WitnessClassCounts {
		if count.TenantID == tenantID && count.AuthorityID == authorityID && count.Class == class && count.WindowStart.Equal(window) {
			if count.Count != want {
				t.Fatalf("count %+v = %d, want %d", count, count.Count, want)
			}
			return
		}
	}
	t.Fatalf("missing count tenant=%s authority=%s class=%s window=%s in %+v", tenantID, authorityID, class, window, snap.WitnessClassCounts)
}
