// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
)

// TestRebuildPastOutboxRetentionReRecordsAReclaimedManagedKeyCommandAsDeliveredA237L4L3:
// a managed-key command queues one provider command when first projected,
// and its operation keeps that row's id. The row is delivered and, a day
// later, reclaimed by the sweep. A full rebuild re-derives the operation; it
// queues no second provider command but re-records the reclaimed row as
// delivered, so the operation still holds an id the outbox names and nothing
// is dispatched again. A command appended but not yet projected when the
// rebuild starts is queued as before.
func TestRebuildPastOutboxRetentionReRecordsAReclaimedManagedKeyCommandAsDeliveredA237L4L3(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const (
		first = "a2374103-0000-4000-8000-000000000001"
		late  = "a2374103-0000-4000-8000-000000000002"
	)
	command := func(operationID string) {
		t.Helper()
		data, err := json.Marshal(projections.ManagedKeyCommand{OperationID: operationID, Provider: "local",
			Action: "generate", Algorithm: "ecdsa-p256", RequestBinding: "a237l4l3-binding-" + operationID})
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: projections.EventManagedKeyCommandRequested, TenantID: tenantA,
			Time: time.Now().UTC(), Data: data})
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("A237L4-L3")})
	command(first)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	type row struct {
		id     int64
		status string
	}
	rows := func(key string) []row {
		t.Helper()
		r, err := s.SystemPool().Query(ctx,
			`SELECT id, status FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id`, tenantA, key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var out []row
		for r.Next() {
			var x row
			if err := r.Scan(&x.id, &x.status); err != nil {
				t.Fatal(err)
			}
			out = append(out, x)
		}
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	operationOutbox := func(operationID string) int64 {
		t.Helper()
		var id int64
		if err := s.SystemPool().QueryRow(ctx,
			`SELECT outbox_id FROM managed_key_operations WHERE tenant_id = $1 AND operation_id = $2`, tenantA, operationID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if got := rows(first); len(got) != 1 || got[0].status != "pending" || operationOutbox(first) != got[0].id {
		t.Fatalf("first projection: rows %+v, operation outbox_id %d", got, operationOutbox(first))
	}
	if tag, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET status = 'delivered', delivered_at = now() - interval '25 hours'
		  WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, first); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("mark delivered: %v (%d rows)", err, tag.RowsAffected())
	}
	if _, err := outboxgc.New(s, outboxgc.DefaultRetention).Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rows(first); len(got) != 0 {
		t.Fatalf("after the sweep the command's rows = %+v", got)
	}
	command(late)
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	got := rows(first)
	if len(got) != 1 || got[0].status != "delivered" {
		t.Fatalf("after the rebuild the reclaimed command's rows = %+v, want one re-recorded as delivered (none pending)", got)
	}
	if id := operationOutbox(first); id != got[0].id {
		t.Fatalf("the rebuilt operation names outbox row %d, want the re-recorded %d", id, got[0].id)
	}
	if late := rows(late); len(late) != 1 || late[0].status != "pending" {
		t.Fatalf("the unprojected command's rows = %+v, want one pending", late)
	}
	t.Logf("A237L4L3_OK rerecorded=%d", got[0].id)
}
