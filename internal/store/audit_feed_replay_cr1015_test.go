// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func cr1015Feed(t *testing.T, s *store.Store, feedID string) store.AuditFeed {
	t.Helper()
	at := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	feed := store.AuditFeed{ID: feedID, TenantID: tenantA, Name: "replay-siem", Provider: "splunk-hec",
		EndpointURL: "https://collector.example.test/services/collector", TokenRef: "env:TEST_AUDIT_FEED_TOKEN",
		IntervalSeconds: 60, BatchSize: 100, Enabled: true, ConfigEventSequence: 1,
		NextRunAt: at, UpdatedAt: at}
	mustTx(t, t.Context(), s, func(tx pgx.Tx) error { return s.ApplyAuditFeedConfiguredTx(t.Context(), tx, feed) })
	return feed
}

func cr1015Batch(number int, feedID string, at time.Time) store.AuditFeedBatch {
	start := uint64(number*10 - 9)
	end := uint64(number * 10)
	return store.AuditFeedBatch{BatchID: uuid(tenantA, 800+number), TenantID: tenantA,
		DestinationID: feedID, Provider: "splunk-hec", StartSequence: start, EndSequence: end,
		RecordCount: 10, ChainHead: "sha256:fixture", OutboxIdempotencyKey: "audit-feed:replay:" + uuid(tenantA, 800+number),
		QueuedAt: at.Add(time.Duration(number) * time.Minute), Status: "queued"}
}

func cr1015Apply(t *testing.T, s *store.Store, fn func(context.Context, pgx.Tx) error) error {
	t.Helper()
	ctx := t.Context()
	return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return fn(ctx, tx) })
}

func cr1015Delivered(batch store.AuditFeedBatch) store.AuditFeedBatch {
	batch.Status = "delivered"
	at := batch.QueuedAt.Add(time.Second)
	batch.AcceptedAt = &at
	batch.CollectorRequestID = "accepted-" + batch.BatchID
	return batch
}

func TestCR1015OlderAuditFeedBatchReplayPreservesNewerDelivery(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 800)
	feed := cr1015Feed(t, s, feedID)
	first := cr1015Batch(1, feedID, feed.NextRunAt)
	second := cr1015Batch(2, feedID, feed.NextRunAt)
	for _, batch := range []store.AuditFeedBatch{first, second} {
		if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
			return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
		}); err != nil {
			t.Fatal(err)
		}
		delivered := cr1015Delivered(batch)
		if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
			return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, delivered)
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertNewest := func() {
		t.Helper()
		current, found, err := s.GetAuditFeed(t.Context(), tenantA, feedID)
		if err != nil || !found || current.LastBatchID != second.BatchID ||
			current.LastDeliveredSequence != second.EndSequence || current.LastStatus != "delivered" ||
			current.LastOutboxKey != second.OutboxIdempotencyKey {
			t.Errorf("older replay changed newer feed cursor: found=%v err=%v current=%+v", found, err, current)
		}
	}
	assertNewest()
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, first, feed.IntervalSeconds)
	}); err != nil {
		t.Errorf("older queued event refused instead of replaying as no-op: %v", err)
	}
	assertNewest()
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, cr1015Delivered(first))
	}); err != nil {
		t.Errorf("older delivered event refused instead of replaying as no-op: %v", err)
	}
	assertNewest()
}

func TestCR1015DeliveredReceiptSupersedesPriorFailure(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 810)
	feed := cr1015Feed(t, s, feedID)
	batch := cr1015Batch(1, feedID, feed.NextRunAt)
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	failed := batch
	failed.Status = "failed"
	failed.ErrorCode = "collector_unreachable"
	at := batch.QueuedAt.Add(time.Second)
	failed.AcceptedAt = &at
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, cr1015Delivered(batch))
	}); err != nil {
		t.Fatalf("later exact collector receipt could not supersede failure: %v", err)
	}
	current, found, err := s.GetAuditFeed(t.Context(), tenantA, feedID)
	if err != nil || !found || current.LastStatus != "delivered" || current.LastDeliveredSequence != batch.EndSequence {
		t.Fatalf("delivered receipt did not win: found=%v err=%v current=%+v", found, err, current)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Errorf("replayed failure refused instead of preserving delivery: %v", err)
	}
	current, found, err = s.GetAuditFeed(t.Context(), tenantA, feedID)
	if err != nil || !found || current.LastStatus != "delivered" || current.LastDeliveredSequence != batch.EndSequence {
		t.Errorf("replayed failure downgraded delivery: found=%v err=%v current=%+v", found, err, current)
	}
}

func TestCR1015QueuedReplayCannotReopenFailedBatch(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 815)
	feed := cr1015Feed(t, s, feedID)
	batch := cr1015Batch(1, feedID, feed.NextRunAt)
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	failed := batch
	failed.Status = "failed"
	failed.ErrorCode = "collector_unreachable"
	at := batch.QueuedAt.Add(time.Second)
	failed.AcceptedAt = &at
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
	}); err != nil {
		t.Errorf("same queued event refused after failure: %v", err)
	}
	current, found, err := s.GetAuditFeed(t.Context(), tenantA, feedID)
	if err != nil || !found || current.LastStatus != "failed" || current.LastErrorCode != failed.ErrorCode {
		t.Errorf("queued replay reopened failed batch: found=%v err=%v current=%+v", found, err, current)
	}
}

func TestCR1015OlderFailedAuditFeedBatchCannotDowngradeNewerDelivery(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 820)
	feed := cr1015Feed(t, s, feedID)
	first := cr1015Batch(1, feedID, feed.NextRunAt)
	second := cr1015Batch(2, feedID, feed.NextRunAt)
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, first, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	failed := first
	failed.Status = "failed"
	failed.ErrorCode = "collector_unreachable"
	at := first.QueuedAt.Add(time.Second)
	failed.AcceptedAt = &at
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, second, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, cr1015Delivered(second))
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Errorf("older failed event refused instead of replaying as no-op: %v", err)
	}
	current, found, err := s.GetAuditFeed(t.Context(), tenantA, feedID)
	if err != nil || !found || current.LastBatchID != second.BatchID ||
		current.LastDeliveredSequence != second.EndSequence || current.LastStatus != "delivered" {
		t.Errorf("older failure downgraded newer delivery: found=%v err=%v current=%+v", found, err, current)
	}
}

func TestCR1015ReplayRejectsMismatchedBatchAuthority(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 825)
	feed := cr1015Feed(t, s, feedID)
	batch := cr1015Batch(1, feedID, feed.NextRunAt)
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	badQueued := batch
	badQueued.ChainHead = "sha256:other"
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, badQueued, feed.IntervalSeconds)
	}); !errors.Is(err, store.ErrAuditFeedBatchConflict) {
		t.Errorf("changed chain head should conflict, got %v", err)
	}
	delivered := cr1015Delivered(batch)
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, delivered)
	}); err != nil {
		t.Fatal(err)
	}
	badReceipt := delivered
	badReceipt.CollectorRequestID = "forged-receipt"
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, badReceipt)
	}); !errors.Is(err, store.ErrAuditFeedBatchConflict) {
		t.Errorf("changed collector receipt should conflict, got %v", err)
	}
	badFailure := batch
	badFailure.ErrorCode = "collector_unreachable"
	badFailure.OutboxIdempotencyKey = "audit-feed:forged"
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, badFailure)
	}); !errors.Is(err, store.ErrAuditFeedBatchConflict) {
		t.Errorf("changed outbox key should conflict, got %v", err)
	}
}

func TestCR1015LateReceiptAfterSameRangeRetryQueueDoesNotStall(t *testing.T) {
	s := newStore(t)
	feedID := uuid(tenantA, 830)
	feed := cr1015Feed(t, s, feedID)
	first := cr1015Batch(1, feedID, feed.NextRunAt)
	second := cr1015Batch(2, feedID, feed.NextRunAt)
	second.StartSequence, second.EndSequence = first.StartSequence, first.EndSequence
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, first, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	failed := first
	failed.Status, failed.ErrorCode = "failed", "collector_unreachable"
	at := first.QueuedAt.Add(time.Second)
	failed.AcceptedAt = &at
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, second, feed.IntervalSeconds)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, cr1015Delivered(first))
	}); err != nil {
		t.Fatalf("late exact receipt stalled behind same-range retry: %v", err)
	}
	current, found, err := s.GetAuditFeed(t.Context(), tenantA, feedID)
	if err != nil || !found || current.LastBatchID != second.BatchID ||
		current.LastQueuedSequence != second.EndSequence || current.LastStatus != "queued" {
		t.Fatalf("late receipt displaced newer intent: found=%v err=%v current=%+v", found, err, current)
	}
	if err := cr1015Apply(t, s, func(ctx context.Context, tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchDeliveredTx(ctx, tx, cr1015Delivered(second))
	}); err != nil {
		t.Fatalf("newer batch could not finish: %v", err)
	}
}
