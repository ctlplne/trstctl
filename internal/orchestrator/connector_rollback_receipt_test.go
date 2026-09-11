// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Use the same atomic command as the served rollback route.
func seedRollbackPredecessor(t *testing.T, o *orchestrator.Orchestrator) {
	t.Helper()
	if _, err := o.CreateOwner(t.Context(), tenantA, "service", "rollback fixture", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(t.Context(), tenantA, store.Certificate{Fingerprint: "old-leaf", Serial: "01", Source: "import"}); err != nil {
		t.Fatal(err)
	}
}

func requestRollbackReceipt(ctx context.Context, o *orchestrator.Orchestrator, request orchestrator.ConnectorRollbackRequest, key string) (orchestrator.ConnectorRollbackQueued, store.ConnectorDeliveryReceipt, error) {
	return o.RequestConnectorRollbackWithReceipt(ctx, tenantA, request, store.ConnectorDeliveryReceipt{
		Target: "Display name", IdempotencyKey: key,
	})
}

func TestRollbackRequestReturnsReadableCanonicalReceiptOnRepeat(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	mustRegisterTenant(t, s, tenantB)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, first, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.RecordConnectorDelivery(ctx, tenantA, store.ConnectorDeliveryReceipt{
		OutboxID: &q.OutboxID, Destination: "connector.rollback", Connector: "f5", Target: request.Target,
		Fingerprint: "old-leaf", Status: "rolled_back", IdempotencyKey: q.IdempotencyKey + ":rollback-result",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered', delivered_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	q2, second, err := requestRollbackReceipt(ctx, o, request, "second-restore")
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
	if err != nil {
		t.Fatalf("returned repeated-command receipt %s is not readable: %v", second.ID, err)
	}
	if q2.OutboxID != q.OutboxID || second.ID != first.ID || read.Status != "rollback_queued" || read.IdempotencyKey != "second-restore" {
		t.Fatalf("repeat lost the canonical pending command: first=%+v second=%+v read=%+v", first, second, read)
	}
	if _, err := s.GetConnectorDeliveryReceipt(ctx, tenantB, second.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("another tenant read the receipt: %v", err)
	}
}

func TestRollbackRequestCannotBecomeClaimableBeforeItsQueuedReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	q, first, err := requestRollbackReceipt(ctx, o, request, "first-restore")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered', delivered_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Block receipt projection, then observe whether the new outbox state is
	// already visible. This uses real PostgreSQL locks and the real NATS log.
	lock, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	var locker int
	if err := lock.QueryRow(ctx, `SELECT pg_backend_pid() FROM connector_delivery_receipts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantA, first.ID).Scan(&locker); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := requestRollbackReceipt(ctx, o, request, "second-restore"); done <- err }()
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
			t.Fatalf("request did not wait for receipt projection: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var visible string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID).Scan(&visible)
	}); err != nil {
		t.Fatal(err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if visible != "delivered" {
		t.Fatalf("outbox became %q while the queued receipt was still blocked", visible)
	}
	final, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, first.ID)
	if err != nil || final.Status != "rollback_queued" || final.IdempotencyKey != "second-restore" {
		t.Fatalf("committed request has no matching queued receipt: %+v %v", final, err)
	}
}
