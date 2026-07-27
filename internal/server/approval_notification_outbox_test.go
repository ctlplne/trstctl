// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type failingApprovalOutbox struct{ err error }

func (f failingApprovalOutbox) EnqueueIfAbsent(context.Context, pgx.Tx, orchestrator.Entry) (bool, error) {
	return false, f.err
}

type approvalNotificationProbe struct {
	mu    sync.Mutex
	err   error
	count int
	last  notify.Alert
}

func (p *approvalNotificationProbe) Name() string { return "approval-probe" }

func (p *approvalNotificationProbe) Notify(_ context.Context, alert notify.Alert) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.count++
	p.last = alert
	return nil
}

func (p *approvalNotificationProbe) setError(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
}

func (p *approvalNotificationProbe) snapshot() (int, notify.Alert) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count, p.last
}

// TestRequestIssuanceQueuesNotificationAtomically proves the served dual-control
// path, not a library double: PostgreSQL commits the request and notification
// intent together; the existing notification outbox worker retries a failed
// channel and delivers once; retries and a second tenant retain independent
// durable identities.
func TestRequestIssuanceQueuesNotificationAtomically(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const (
		tenantA  = "11111111-1111-1111-1111-111111111111"
		tenantB  = "22222222-2222-2222-2222-222222222222"
		resource = "identity-approval-notification"
		action   = "issue"
	)
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant, err)
		}
	}

	// If the outbox write fails after the request insert, WithTenant rolls the
	// complete transaction back. A request without its notification cannot exist.
	failed := storeApprovalChecker{
		store: st, required: 1,
		outbox: failingApprovalOutbox{err: errors.New("injected outbox failure")},
	}
	if approved, _ := failed.IsApproved(ctx, tenantA, resource, action, "alice"); approved {
		t.Fatal("approval unexpectedly passed while its notification enqueue failed")
	}
	if _, err := st.GetIssuanceApproval(ctx, tenantA, resource, action); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("request survived failed notification enqueue: %v", err)
	}

	// PostgreSQL assigns next_attempt_at from its real clock. Keep the injected
	// worker clock safely ahead of that value so this retry test cannot expire
	// when wall time passes a hard-coded fixture timestamp.
	now := time.Now().UTC().Add(time.Hour)
	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return time.Minute }),
		orchestrator.WithRetryJitter(func(d time.Duration) time.Duration { return d }),
	)
	checker := storeApprovalChecker{store: st, outbox: outbox, required: 1}
	if approved, _ := checker.IsApproved(ctx, tenantA, resource, action, "alice"); approved {
		t.Fatal("request without a distinct approval unexpectedly passed")
	}
	// A request retry reuses the exact outbox receiver identity.
	if approved, _ := checker.IsApproved(ctx, tenantA, resource, action, "alice"); approved {
		t.Fatal("request retry without a distinct approval unexpectedly passed")
	}
	// The same resource/action in another tenant is a separate RLS-confined row
	// and a separate outbox command despite sharing the raw binding.
	if approved, _ := checker.IsApproved(ctx, tenantB, resource, action, "bob"); approved {
		t.Fatal("tenant B request without a distinct approval unexpectedly passed")
	}

	for tenant, want := range map[string]int{tenantA: 1, tenantB: 1} {
		var requests, intents int
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT
				    (SELECT count(*) FROM issuance_approval_requests
				      WHERE tenant_id = $1 AND resource = $2 AND action = $3),
				    (SELECT count(*) FROM outbox
				      WHERE tenant_id = $1 AND destination = $4)`,
				tenant, resource, action, notify.DestinationApproval).Scan(&requests, &intents)
		}); err != nil {
			t.Fatalf("load atomic pair for %s: %v", tenant, err)
		}
		if requests != want || intents != want {
			t.Fatalf("tenant %s durable pair requests=%d intents=%d, want %d/%d", tenant, requests, intents, want, want)
		}
	}

	probe := &approvalNotificationProbe{err: errors.New("temporary channel failure")}
	dispatcher := notify.NewDispatcher(probe)
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		return dispatcher.DispatchMessage(ctx, notify.DeliveryMessage{
			TenantID: message.TenantID, Destination: message.Destination,
			IdempotencyKey: message.IdempotencyKey, Payload: message.Payload,
			OutboxID: message.ID, Attempts: message.Attempts,
		})
	})
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{notify.DestinationApproval}}
	if n, err := outbox.DispatchScoped(ctx, handler, scope); err != nil || n != 2 {
		t.Fatalf("first approval notification dispatch = (%d, %v), want two attempted tenant rows", n, err)
	}
	if count, _ := probe.snapshot(); count != 0 {
		t.Fatalf("failed channel recorded %d deliveries, want zero", count)
	}

	probe.setError(nil)
	now = now.Add(2 * time.Minute)
	if n, err := outbox.DispatchScoped(ctx, handler, scope); err != nil || n != 2 {
		t.Fatalf("retry approval notification dispatch = (%d, %v), want two attempted tenant rows", n, err)
	}
	if count, alert := probe.snapshot(); count != 2 {
		t.Fatalf("successful retry deliveries=%d, want one per tenant", count)
	} else {
		if alert.Kind != notify.KindApprovalRequest || alert.Subject != resource || alert.TenantID != tenantB {
			encoded, _ := json.Marshal(alert)
			t.Fatalf("delivered approval alert has wrong binding: %s", encoded)
		}
	}
	if n, err := outbox.DispatchScoped(ctx, handler, scope); err != nil || n != 0 {
		t.Fatalf("delivered notifications replayed = (%d, %v), want zero", n, err)
	}
}
