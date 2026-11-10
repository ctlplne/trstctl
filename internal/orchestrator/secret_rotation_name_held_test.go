// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// LS-1: a tenant's secret rotation schedules have distinct names. A second
// schedule under a held name is refused before its event is appended; it used
// to append the event and fail the projection on the (tenant, name) index,
// leaving an event a rebuild stopped at. A log that already holds one
// rebuilds, the schedule it named never existing, as live.
func TestSecretRotationScheduleUnderAHeldNameIsRefusedBeforeItsEventLS1(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx := t.Context()
	o := orchestrator.NewOrchestrator(log, s, nil)
	schedule := store.SecretRotationSchedule{Name: "orders-db nightly", Provider: "connector:orders-vault", Key: "orders/db",
		OldRef: "v1", IntervalSeconds: 3600, Enabled: true}
	first, err := o.UpsertSecretRotationSchedule(ctx, tenantA, schedule)
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	schedule.Name = " orders-db nightly "
	var held *store.TenantNameHeldError
	if _, err := o.UpsertSecretRotationSchedule(ctx, tenantA, schedule); !errors.As(err, &held) || held.Kind != "secret rotation schedule" {
		t.Fatalf("a second schedule under the first's name: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("the refused schedule appended: %d -> %d %v", head, after, err)
	}
	// The first schedule may keep its own name.
	schedule.ID, schedule.Name, schedule.IntervalSeconds = first.ID, "orders-db nightly", 7200
	if _, err := o.UpsertSecretRotationSchedule(ctx, tenantA, schedule); err != nil {
		t.Fatalf("the first schedule re-saved under its own name: %v", err)
	}

	poisoned, err := json.Marshal(projections.SecretRotationScheduleUpserted{ID: "16161616-1616-4616-8616-161616161616",
		Name: "orders-db nightly", Provider: "connector:orders-vault", Key: "orders/db", OldRef: "v1", IntervalSeconds: 3600, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventSecretRotationScheduleUpserted, TenantID: tenantA, Data: poisoned}); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	if _, err := s.GetSecretRotationSchedule(ctx, tenantA, "16161616-1616-4616-8616-161616161616"); !store.IsNotFound(err) {
		t.Fatalf("the duplicate projected a schedule: %v", err)
	}
	if got, err := s.GetSecretRotationSchedule(ctx, tenantA, first.ID); err != nil || got.Name != "orders-db nightly" || got.IntervalSeconds != 7200 {
		t.Fatalf("the first schedule after the rebuild: %+v %v", got, err)
	}
}
