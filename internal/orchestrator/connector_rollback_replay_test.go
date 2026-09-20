// SPDX-License-Identifier: BUSL-1.1
package orchestrator_test

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A normal lagging tail applies earlier log facts over state already updated by
// inline command projection. The current production result command creates the
// old event in this test; the exact event is then replayed through Projector.Apply.
func TestRollbackPriorResultProjectionCannotCompleteRearmedReceipt(t *testing.T) {
	ctx := t.Context()
	s, log, projector := recordingSpine(t)
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, first, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered', claim_attempts=1, claim_completed_at=now(), delivered_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.RecordConnectorRollbackResult(ctx, tenantA, q.IdempotencyKey, 1, store.ConnectorDeliveryReceipt{
		OutboxID: &q.OutboxID, Destination: "connector.rollback", Connector: "f5", Target: request.Target,
		Fingerprint: "old-leaf", Status: "rolled_back",
	}); err != nil {
		t.Fatal(err)
	}
	var oldResult events.Event
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type != projections.EventConnectorDeliveryRecorded || ev.TenantID != tenantA {
			return nil
		}
		var p projections.ConnectorDeliveryRecorded
		if err := json.Unmarshal(ev.Data, &p); err != nil {
			return err
		}
		if p.Status == "rolled_back" && p.OutboxID != nil && *p.OutboxID == q.OutboxID {
			oldResult = ev
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if oldResult.ID == "" {
		t.Fatal("production result command did not append its result event")
	}
	_, second, err := requestRollbackReceipt(ctx, o, request, "second-restore")
	if err != nil || second.ID != first.ID || second.Status != "rollback_queued" {
		t.Fatalf("rearm fixture: %+v %v", second, err)
	}
	if err := projections.New(s).Apply(ctx, oldResult); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID).Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	read, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if read.Status != "rollback_queued" || read.IdempotencyKey != "second-restore" {
		t.Fatalf("accepted old event crossed the new execution boundary: old_event_seq=%d outbox=%s receipt=%s attempts=%d key=%s", oldResult.Sequence, status, read.Status, read.Attempts, read.IdempotencyKey)
	}
	// Full rebuild must derive the same current queue from the unchanged history,
	// and the old event must remain inert when the tail resumes afterwards.
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, oldResult); err != nil {
		t.Fatal(err)
	}
	read, err = s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil || read.Status != "rollback_queued" || read.IdempotencyKey != "second-restore" {
		t.Fatalf("rebuild lost current queue: %+v %v", read, err)
	}

	// A current snapshot must preserve the sequence cursor as well as the status.
	if n, err := projector.Snapshot(ctx); err != nil || n == 0 {
		t.Fatalf("snapshot: %d %v", n, err)
	}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.ResetProjectionCheckpointTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if restored, err := projections.New(s).RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("snapshot restore: %t %v", restored, err)
	}
	if err := projections.New(s).Apply(ctx, oldResult); err != nil {
		t.Fatal(err)
	}
	read, err = s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil || read.Status != "rollback_queued" || read.IdempotencyKey != "second-restore" {
		t.Fatalf("snapshot lost current queue: %+v %v", read, err)
	}

}
