// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestTenantRegistrationCreationTimeComesFromRetainedEvent(t *testing.T) {
	for _, mode := range []string{"live-command", "legacy-apply", "full-rebuild"} {
		t.Run(mode, func(t *testing.T) {
			st, log := newStore(t), openLog(t)
			ctx := t.Context()
			projector := projections.New(st)
			var event events.Event
			if mode == "live-command" {
				svc := app.New(log, st, nil)
				defer svc.Close()
				if err := svc.RegisterTenant(ctx, tenantA, "Retained customer", "retained-registration-time"); err != nil {
					t.Fatal(err)
				}
				row, err := st.GetTenant(ctx, tenantA)
				if err != nil {
					t.Fatal(err)
				}
				var found bool
				event, found, err = log.EventAtSequence(ctx, row.EventSeq)
				if err != nil || !found {
					t.Fatalf("registration envelope missing: %v", err)
				}
			} else {
				var err error
				event, err = log.Append(ctx, events.Event{ID: "legacy-registration-time", Type: projections.EventTenantRegistered, TenantID: tenantA, Time: time.Date(2025, 4, 12, 9, 8, 7, 123456000, time.UTC), Data: tenantRegistered("Retained customer")})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "legacy-apply" {
					err = projector.Apply(ctx, event)
				} else {
					err = projector.Rebuild(ctx, log)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			check := func(label string) {
				t.Helper()
				row, err := st.GetTenant(ctx, tenantA)
				if err != nil || row.EventSeq != event.Sequence || !row.CreatedAt.Equal(event.Time.Truncate(time.Microsecond)) {
					t.Errorf("%s registration=%+v error=%v, want retained sequence=%d time=%s", label, row, err, event.Sequence, event.Time)
				}
			}
			check("initial")
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			check("rebuild")
		})
	}
}

func TestLegacyTenantRenamePreservesOriginalCreationTime(t *testing.T) {
	st, log := newStore(t), openLog(t)
	ctx := t.Context()
	projector := projections.New(st)
	firstTime := time.Date(2025, 4, 12, 9, 8, 7, 123456000, time.UTC)
	var last events.Event
	for i, name := range []string{"Original customer", "Renamed customer"} {
		var err error
		last, err = log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Time: firstTime.Add(time.Duration(i) * time.Hour), Data: tenantRegistered(name)})
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, last); err != nil {
			t.Fatal(err)
		}
	}
	check := func() {
		t.Helper()
		row, err := st.GetTenant(ctx, tenantA)
		if err != nil || row.Name != "Renamed customer" || row.EventSeq != last.Sequence || !row.CreatedAt.Equal(firstTime) {
			t.Fatalf("rename replaced original creation time: %+v %v", row, err)
		}
	}
	check()
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check()
}
