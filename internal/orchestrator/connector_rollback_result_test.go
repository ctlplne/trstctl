// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// This helper follows the served result recorder. The SQL fixture below controls
// the retirement/re-arm boundary; it does not synthesize a projected receipt.
func recordRollbackResult(ctx context.Context, o *orchestrator.Orchestrator, q orchestrator.ConnectorRollbackQueued, attempt int, status string) error {
	err := o.RecordConnectorRollbackResult(ctx, tenantA, q.IdempotencyKey, attempt, store.ConnectorDeliveryReceipt{
		OutboxID: &q.OutboxID, Destination: "connector.rollback", Connector: "f5", Target: "execution-route",
		Fingerprint: "old-leaf", Status: status, Attempts: attempt,
		IdempotencyKey: q.IdempotencyKey + ":rollback-result",
	})
	return err
}

func TestRollbackResultCannotOverwriteRearmedCommand(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, first, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	setJob := func(status string, attempt int) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET status=$3, claim_attempts=$4,
    delivered_at=CASE WHEN $3='delivered' THEN now() ELSE NULL END,
    claim_completed_at=CASE WHEN $3='delivered' THEN now() ELSE NULL END
    WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID, status, attempt)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertQueued := func() {
		t.Helper()
		got, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, first.ID)
		if err != nil || got.Status != "rollback_queued" || got.IdempotencyKey != "second-restore" {
			t.Fatalf("prior execution changed the second request: %+v %v", got, err)
		}
	}
	// Match the actual served ordering: retirement first, public callback later.
	setJob("delivered", 1)
	_, second, err := requestRollbackReceipt(ctx, o, request, "second-restore")
	if err != nil || second.ID != first.ID {
		t.Fatalf("rearm: %+v %v", second, err)
	}
	// The old callback must be inert both before and after the next claim.
	for _, state := range []struct {
		status  string
		attempt int
	}{{"pending", 1}, {"pending", 2}, {"delivered", 2}} {
		setJob(state.status, state.attempt)
		if err := recordRollbackResult(ctx, o, q, 1, "rolled_back"); err != nil {
			t.Fatal(err)
		}
		assertQueued()
	}
	if err := recordRollbackResult(ctx, o, q, 2, "rolled_back"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil || got.Status != "rolled_back" || got.Attempts != 2 {
		t.Fatalf("current result: %+v %v", got, err)
	}
	// A late failed callback from attempt one cannot replace attempt two either.
	if err := recordRollbackResult(ctx, o, q, 1, "rollback_failed"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil || got.Status != "rolled_back" || got.Attempts != 2 {
		t.Fatalf("late failure changed current result: %+v %v", got, err)
	}
}

func TestRollbackPendingRepeatPreservesRecordedFailure(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, first, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	// A retryable report releases the holder, retains its generation and records
	// the failure reason. The next claim has not begun yet.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET claim_attempts=1, attempts=1, last_error='connector_rollback_target_unreachable' WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := recordRollbackResult(ctx, o, q, 1, "rollback_failed"); err != nil {
		t.Fatal(err)
	}
	_, second, err := requestRollbackReceipt(ctx, o, request, "second-restore")
	if err != nil || second.ID != first.ID || second.Status != "rollback_failed" || second.Attempts != 1 {
		t.Fatalf("repeat reset the existing attempt result: %+v %v", second, err)
	}
	// A failed release is never evidence of successful restoration.
	if err := recordRollbackResult(ctx, o, q, 1, "rolled_back"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, first.ID)
	if err != nil || got.Status != "rollback_failed" {
		t.Fatalf("unretired attempt became successful: %+v %v", got, err)
	}
}

func TestRollbackResultHoldsJobLockThroughReceiptProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, receipt, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered', claim_attempts=1, delivered_at=now(), claim_completed_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	lock, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	var locker int
	if err := lock.QueryRow(ctx, `SELECT pg_backend_pid() FROM connector_delivery_receipts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantA, receipt.ID).Scan(&locker); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- recordRollbackResult(ctx, o, q, 1, "rolled_back") }()
	for {
		var waiting bool
		if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, locker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("result did not wait for receipt: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Re-arm takes this same job lock. It cannot pass the result writer while
	// that writer is still waiting to project its terminal receipt.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var id int64
		return tx.QueryRow(ctx, `SELECT id FROM outbox WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT`, tenantA, q.OutboxID).Scan(&id)
	})
	var lockErr *pgconn.PgError
	if !errors.As(err, &lockErr) || lockErr.Code != "55P03" {
		t.Fatalf("result projection did not retain job lock: %v", err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, next, err := requestRollbackReceipt(ctx, o, request, "second-restore")
	if err != nil || next.Status != "rollback_queued" || next.IdempotencyKey != "second-restore" {
		t.Fatalf("serialized rearm: %+v %v", next, err)
	}
}
