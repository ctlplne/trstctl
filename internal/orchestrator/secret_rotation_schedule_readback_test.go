// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A create receipt is an operator-visible record. It must be the persisted
// projection, including PostgreSQL's microsecond timestamp precision, so a
// follow-up GET and an idempotent retry return the same bytes.
func TestSecretRotationScheduleCreateReceiptMatchesProjectedReadback(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	tenantEvent, err := log.Append(ctx, events.Event{
		ID: events.NewID(), Type: projections.EventTenantRegistered,
		TenantID: tenantA, Data: tenantRegisteredJSON("schedule-create-readback"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	const id = "25800000-0000-4000-8000-000000000003"
	due := time.Date(2026, 10, 11, 17, 0, 0, 123456789, time.UTC)
	created, err := orch.UpsertSecretRotationSchedule(ctx, tenantA, store.SecretRotationSchedule{
		ID: id, Name: "precision-readback", Provider: "connector:ci",
		Key: "qa/precision", OldRef: "version:1", IntervalSeconds: 3600,
		NextRunAt: due, Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := st.GetSecretRotationSchedule(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	createJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	getJSON, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if string(createJSON) != string(getJSON) {
		t.Fatalf("create receipt differs from projected GET: create=%s get=%s", createJSON, getJSON)
	}
}
