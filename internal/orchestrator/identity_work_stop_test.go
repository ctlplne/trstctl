// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestTerminalIdentityWorkCancellationSurvivesReplay(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	ob := orchestrator.NewOutbox(st)
	o := orchestrator.NewOrchestrator(log, st, ob)
	p := projections.New(st)
	identities := map[string]string{}
	for _, tenant := range []string{tenantA, tenantB} {
		ev, err := log.Append(ctx, events.Event{TenantID: tenant, Type: projections.EventTenantRegistered, Data: []byte(`{"name":"work-stop QA"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Apply(ctx, ev); err != nil {
			t.Fatal(err)
		}
		owner, err := o.CreateOwner(ctx, tenant, "team", "mail", "mail@example.test")
		if err != nil {
			t.Fatal(err)
		}
		identities[tenant] = issuedIdentity(t, ctx, st, o, tenant, owner.ID, "mail.example.test").ID
	}
	id := identities[tenantA]
	for _, to := range []orchestrator.State{orchestrator.StateDeployed, orchestrator.StateRenewing} {
		if err := o.Transition(ctx, tenantA, id, to, "queue retained renewal"); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	var parent orchestrator.Record
	for _, job := range pending {
		if job.Destination == "ca.renew" {
			parent = job
		}
	}
	if parent.ID == 0 {
		t.Fatal("renewal parent missing")
	}
	runID := uuid.NewString()
	body, err := json.Marshal(projections.LifecycleRotationRecorded{ID: runID, IdentityID: id, OutboxID: &parent.ID, Status: "running", Trigger: "scheduler", IdempotencyKey: parent.IdempotencyKey})
	if err != nil {
		t.Fatal(err)
	}
	runEvent, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventLifecycleRotationRecorded, Data: body})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, runEvent); err != nil {
		t.Fatal(err)
	}
	// Model an already-completed handoff, with the actual subject command still
	// waiting on its host. This is queue-state fault setup, not native CA proof.
	childPayload, _ := json.Marshal(map[string]string{"identity_id": id, "rotation_run_id": runID})
	var childID int64
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, parent.ID); err != nil {
			return err
		}
		var err error
		childID, err = ob.Enqueue(ctx, tx, orchestrator.Entry{TenantID: tenantA, Destination: "endpoint.renew", IdempotencyKey: "host-stop-child", Payload: childPayload})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.Transition(ctx, tenantA, id, orchestrator.StateRevoked, "cessationOfOperation"); err != nil {
		t.Fatal(err)
	}
	assertState := func() {
		t.Helper()
		child, err := ob.Get(ctx, tenantA, childID)
		if err != nil || child.Status != "cancelled" || string(child.Payload) != string(childPayload) {
			t.Fatalf("child status=%s err=%v", child.Status, err)
		}
		retainedParent, err := ob.Get(ctx, tenantA, parent.ID)
		if err != nil || retainedParent.Status != "delivered" {
			t.Fatalf("completed handoff overwritten: status=%s err=%v", retainedParent.Status, err)
		}
		run, err := st.GetRotationRun(ctx, tenantA, runID)
		if err != nil || run.Status != "cancelled" || run.CompletedAt == nil {
			t.Fatalf("rotation status=%s err=%v", run.Status, err)
		}
		other, err := ob.Pending(ctx, tenantB)
		if err != nil || len(other) != 1 || other[0].Destination != "ca.issue" {
			t.Fatalf("other tenant queue changed: count=%d err=%v", len(other), err)
		}
		jobs, err := ob.Pending(ctx, tenantA)
		if err != nil {
			t.Fatal(err)
		}
		publish := false
		for _, job := range jobs {
			if job.Destination == "revocation.publish" {
				publish = true
			}
		}
		if !publish {
			t.Fatal("revocation publication was cancelled")
		}
	}
	assertState()
	// Reports already in flight can enter the event log after the stop. They
	// remain audit evidence without reopening a cancelled run or its queue.
	for _, status := range []string{"running", "failed"} {
		observation := projections.LifecycleRotationRecorded{ID: runID, IdentityID: id, OutboxID: &parent.ID, Status: status, Trigger: "scheduler", IdempotencyKey: parent.IdempotencyKey}
		if status == "failed" {
			observation.Error = "late executor failure"
		}
		data, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		late, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventLifecycleRotationRecorded, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Apply(ctx, late); err != nil {
			t.Fatal(err)
		}
		assertState()
	}
	if err := p.Apply(ctx, runEvent); err != nil {
		t.Fatal(err)
	}
	assertState()
	if _, err := o.ReconcileStoppedIdentityWork(ctx, tenantA, time.Now()); err != nil {
		t.Fatal(err)
	}
	assertState()
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReconcileOutbox(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertState()
	// No remote operation occurs in any replay or cancellation step.
}
