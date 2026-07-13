// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

// TestOutboxDeadLetterDepthTracksInducedPermanentFailure is the OPS-DLQ-001
// acceptance: exhausting an entry's attempts dead-letters it, and the store's
// per-tenant/destination depth query — the source the served
// trstctl_outbox_deadletter_depth gauge samples — reflects exactly that row
// so the shipped alert can fire.
func TestOutboxDeadLetterDepthTracksInducedPermanentFailure(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// The metric intentionally enumerates the tenant registry before issuing
	// tenant-predicated counts. Register the tenant exactly as production does;
	// an RLS session variable alone must never manufacture fleet membership.
	mustRegisterTenant(t, s, tenantA)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithMaxAttempts(1),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook.dlq-depth", IdempotencyKey: "dlq-depth-1", Payload: []byte(`{}`),
	})

	if depths, err := s.OutboxDeadLetterDepth(ctx); err != nil {
		t.Fatal(err)
	} else {
		for _, d := range depths {
			if d.Destination == "webhook.dlq-depth" {
				t.Fatalf("dead-letter depth reported before any failure: %+v", d)
			}
		}
	}

	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("permanent downstream failure")
	})
	if _, err := ob.Dispatch(ctx, failing); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	depths, err := s.OutboxDeadLetterDepth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range depths {
		if d.TenantID == tenantA && d.Destination == "webhook.dlq-depth" {
			found = true
			if d.Depth != 1 {
				t.Fatalf("dead-letter depth = %d, want 1", d.Depth)
			}
		}
	}
	if !found {
		t.Fatalf("induced permanent failure is not visible in the dead-letter depth: %+v", depths)
	}
}
