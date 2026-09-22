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

func TestDriftCompletionCannotResolveAnotherTenantsWitness(t *testing.T) {
	p := rounds.NewDriftProjection(time.Hour)
	at := time.Unix(100, 0).UTC()
	if err := p.Apply(witnessRecordedEvent(t, 1, at, "tenant-a", "shared-id", witness.ClassPresence, "authority-a")); err != nil {
		t.Fatal(err)
	}
	// Rejecting the foreign completion is also valid; it must not change A's state.
	_ = p.Apply(completionEvent(t, 2, at.Add(time.Minute), "tenant-b", "shared-id"))
	got := p.Snapshot()
	if got.OpenWitnesses != 1 || len(got.CompletionDurations) != 0 {
		t.Fatalf("foreign completion changed tenant A's witness: %+v", got)
	}
}

func TestDriftRejectsEventAndPayloadTenantMismatchWithoutChangingState(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	for _, kind := range []string{"witness", "completion"} {
		t.Run(kind, func(t *testing.T) {
			p := rounds.NewDriftProjection(time.Hour)
			if err := p.Apply(witnessRecordedEvent(t, 1, at, "tenant-a", "existing", witness.ClassPresence, "authority-a")); err != nil {
				t.Fatal(err)
			}
			before := p.Snapshot()
			var ev eventspec.Event
			if kind == "witness" {
				ev = witnessRecordedEvent(t, 2, at.Add(time.Minute), "tenant-a", "another", witness.ClassPresence, "authority-a")
			} else {
				ev = completionEvent(t, 2, at.Add(time.Minute), "tenant-a", "existing")
			}
			ev.TenantID = "tenant-b"
			if err := p.Apply(ev); err == nil {
				t.Error("event envelope and payload name different tenants but projection accepted the event")
			}
			if after := p.Snapshot(); !reflect.DeepEqual(before, after) {
				t.Errorf("mismatched tenant event changed projection: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestDriftOpenWitnessIdentityIncludesTenant(t *testing.T) {
	p := rounds.NewDriftProjection(time.Hour)
	at := time.Unix(100, 0).UTC()
	for i, tenant := range []string{"tenant-a", "tenant-b"} {
		if err := p.Apply(witnessRecordedEvent(t, uint64(i+1), at, tenant, "shared-id", witness.ClassPresence, "authority-"+tenant)); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.Snapshot(); got.OpenWitnesses != 2 {
		t.Fatalf("tenant-local witness IDs collided: %+v", got)
	}
}
