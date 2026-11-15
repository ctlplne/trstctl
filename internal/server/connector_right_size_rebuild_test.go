// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
)

// TestRebuildPastOutboxRetentionReRunsNoRightSizeA237L4L4 (served dispatcher
// harness, PostgreSQL and the embedded log): a connector right-size operation
// is delivered to its receiver and succeeds; its command row is delivered and,
// a day later, reclaimed by the sweep. A full rebuild then re-derives the run
// and its receipt from the log: it queues no second command (no right-size row
// is pending), the run and its receipt name the original command id their
// events carry, and the receiver is not called again. Before, the rebuild
// queued a new command row and then stopped at the run's terminal event,
// which names the original id.
func TestRebuildPastOutboxRetentionReRunsNoRightSizeA237L4L4(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)
	mutator := &durableRightSizeMutator{}
	h.handler.connectorRightSize = mutator
	message := seedDurableRightSizeOperation(t, h, "a237l4l4-right-size")
	if err := h.handler.handleConnectorRightSize(ctx, message); err != nil {
		t.Fatalf("deliver the right-size command: %v", err)
	}
	run, receipt := assertDurableRightSizeState(t, h, message, "succeeded", "delivered")
	if run.OutboxID == nil || *run.OutboxID != message.ID || receipt.OutboxID == nil || *receipt.OutboxID != message.ID {
		t.Fatalf("before the rebuild the run names %v and the receipt %v, want %d", run.OutboxID, receipt.OutboxID, message.ID)
	}
	calls := mutator.calls
	// The projection tail catches up past the operation's events, as it does
	// in a running deployment, so the rebuild knows they were projected.
	if err := projections.New(h.store).ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatalf("catch up: %v", err)
	}

	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE outbox SET status = 'delivered', delivered_at = now() - interval '25 hours'
			WHERE tenant_id = $1 AND id = $2`, h.tenant, message.ID)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("mark the command delivered: %d rows", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := outboxgc.New(h.store, outboxgc.DefaultRetention).Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	pending := func() int {
		t.Helper()
		var n int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
				h.tenant, message.IdempotencyKey).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := pending(); n != 0 {
		t.Fatalf("after the sweep %d command rows remain", n)
	}

	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if n := pending(); n != 0 {
		t.Fatalf("the rebuild queued %d right-size command rows again", n)
	}
	run, receipt = assertDurableRightSizeState(t, h, message, "succeeded", "delivered")
	if run.OutboxID == nil || *run.OutboxID != message.ID || receipt.OutboxID == nil || *receipt.OutboxID != message.ID {
		t.Fatalf("after the rebuild the run names %v and the receipt %v, want the original %d", run.OutboxID, receipt.OutboxID, message.ID)
	}
	if mutator.calls != calls {
		t.Fatalf("the receiver was called %d more times", mutator.calls-calls)
	}
	t.Logf("A237L4L4_RIGHT_SIZE_OK outbox=%d", message.ID)
}
