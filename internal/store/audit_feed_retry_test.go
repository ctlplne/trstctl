// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestFailedAuditFeedIsRetriedNotWedged is the regression guard for the audit
// feed that stops forever.
//
// AuditFeedsDue excluded both 'queued' and 'failed'. Excluding 'queued' is
// right — a batch is in flight and re-queueing would duplicate it. Excluding
// 'failed' is a different thing entirely: a failed batch is not in flight,
// nothing anywhere clears the status, and no operator resume exists. One
// transient delivery error therefore stopped a tenant's SIEM feed permanently
// and silently, which is the worst way for compliance evidence to stop.
func TestFailedAuditFeedIsRetriedNotWedged(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	feedID := uuid(tenantA, 731)
	at := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

	feed := store.AuditFeed{
		ID: feedID, TenantID: tenantA, Name: "siem", Provider: "splunk-hec",
		EndpointURL: "https://collector.example.test/services/collector",
		TokenRef:    "env:TOKEN", IntervalSeconds: 60, BatchSize: 100, Enabled: true,
		ConfigEventSequence: 1, NextRunAt: at, UpdatedAt: at,
	}
	mustTx(t, ctx, s, func(tx pgx.Tx) error { return s.ApplyAuditFeedConfiguredTx(ctx, tx, feed) })

	due, err := s.AuditFeedsDue(ctx, tenantA, at.Add(time.Second), 10)
	if err != nil {
		t.Fatalf("AuditFeedsDue: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("a freshly configured, enabled, due feed was not returned (got %d); the fixture is broken", len(due))
	}

	// Queue a batch, then fail it — exactly what one unreachable collector does.
	batch := store.AuditFeedBatch{
		BatchID: uuid(tenantA, 732), TenantID: tenantA, DestinationID: feedID,
		Provider: "splunk-hec", StartSequence: 1, EndSequence: 9, RecordCount: 9,
		ChainHead: "deadbeef", OutboxIdempotencyKey: "audit-feed:731:1",
		QueuedAt: at, Status: "queued",
	}
	mustTx(t, ctx, s, func(tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, feed.IntervalSeconds)
	})
	failedAt := at.Add(5 * time.Second)
	failed := batch
	failed.AcceptedAt = &failedAt
	failed.ErrorCode = "collector_unreachable"
	mustTx(t, ctx, s, func(tx pgx.Tx) error { return s.ApplyAuditFeedBatchFailedTx(ctx, tx, failed) })

	after, ok, err := s.GetAuditFeed(ctx, tenantA, feedID)
	if err != nil || !ok {
		t.Fatalf("GetAuditFeed: %v (found=%v)", err, ok)
	}
	if after.LastStatus != "failed" {
		t.Fatalf("last_status = %q, want failed; the fixture did not exercise the failure path", after.LastStatus)
	}
	// The failure path must not advance the cursor, or the retry would skip the
	// very records that failed to deliver.
	if after.LastDeliveredSequence != 0 {
		t.Errorf("last_delivered_sequence = %d after a FAILED batch, want 0; a retry would skip records",
			after.LastDeliveredSequence)
	}

	// Once the interval elapses the feed must come due again.
	retryAt := after.NextRunAt.Add(time.Second)
	due, err = s.AuditFeedsDue(ctx, tenantA, retryAt, 10)
	if err != nil {
		t.Fatalf("AuditFeedsDue after failure: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("a feed whose last delivery FAILED is never scheduled again (got %d due at %s); "+
			"the tenant's audit feed is wedged permanently with no operator resume", len(due), retryAt)
	}
	if due[0].ID != feedID {
		t.Errorf("due feed = %q, want %q", due[0].ID, feedID)
	}
}

// TestQueuedAuditFeedIsNotRescheduled guards the half that must stay excluded:
// a batch in flight must not be queued a second time.
func TestQueuedAuditFeedIsNotRescheduled(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	feedID := uuid(tenantA, 741)
	at := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

	mustTx(t, ctx, s, func(tx pgx.Tx) error {
		return s.ApplyAuditFeedConfiguredTx(ctx, tx, store.AuditFeed{
			ID: feedID, TenantID: tenantA, Name: "siem2", Provider: "splunk-hec",
			EndpointURL: "https://collector.example.test/services/collector",
			TokenRef:    "env:TOKEN", IntervalSeconds: 60, BatchSize: 100, Enabled: true,
			ConfigEventSequence: 1, NextRunAt: at, UpdatedAt: at,
		})
	})
	mustTx(t, ctx, s, func(tx pgx.Tx) error {
		return s.ApplyAuditFeedBatchQueuedTx(ctx, tx, store.AuditFeedBatch{
			BatchID: uuid(tenantA, 742), TenantID: tenantA, DestinationID: feedID,
			Provider: "splunk-hec", StartSequence: 1, EndSequence: 9, RecordCount: 9,
			ChainHead: "deadbeef", OutboxIdempotencyKey: "audit-feed:741:1",
			QueuedAt: at, Status: "queued",
		}, 60)
	})

	due, err := s.AuditFeedsDue(ctx, tenantA, at.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("AuditFeedsDue: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("a feed with a batch still in flight was scheduled again (%d due); the batch would be duplicated", len(due))
	}
}

func mustTx(t *testing.T, ctx context.Context, s *store.Store, fn func(pgx.Tx) error) {
	t.Helper()
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return fn(tx) }); err != nil {
		t.Fatalf("tx: %v", err)
	}
}
