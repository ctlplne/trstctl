// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

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

	// PostgreSQL assigns next_attempt_at from its real clock. Keep the injected
	// worker clock safely ahead of that value so this retry test cannot expire
	// when wall time passes a hard-coded fixture timestamp.
	now := time.Now().UTC().Add(time.Hour)
	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return time.Minute }),
		orchestrator.WithRetryJitter(func(d time.Duration) time.Duration { return d }),
	)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	checker := storeApprovalChecker{store: st, orch: orch, required: 1}
	intentFor := func(tenantID, requester string) api.ApprovalIntent {
		return api.ApprovalIntent{
			TenantID: tenantID, ResourceKind: "identity", ResourceID: resource,
			ResourceName: resource, Action: action, Requester: requester,
			FromState: "requested", ToState: "issued", TargetVersion: 1,
			Reason:       "authorize one exact notification test transition",
			EvidenceRefs: []string{"test-request:sha256:0123456789abcdef"}, RequiredApprovals: 1,
		}
	}
	if _, approved, _ := checker.AuthorizeApproval(ctx, intentFor(tenantA, "alice")); approved {
		t.Fatal("request without a distinct approval unexpectedly passed")
	}
	// A request retry reuses the exact outbox receiver identity.
	if _, approved, _ := checker.AuthorizeApproval(ctx, intentFor(tenantA, "alice")); approved {
		t.Fatal("request retry without a distinct approval unexpectedly passed")
	}
	// The same resource/action in another tenant is a separate RLS-confined row
	// and a separate outbox command despite sharing the raw binding.
	if _, approved, _ := checker.AuthorizeApproval(ctx, intentFor(tenantB, "bob")); approved {
		t.Fatal("tenant B request without a distinct approval unexpectedly passed")
	}

	for tenant, want := range map[string]int{tenantA: 1, tenantB: 1} {
		var requests, intents int
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT
					(SELECT count(*) FROM operation_approval_requests
				      WHERE tenant_id = $1 AND resource_id = $2 AND action = $3),
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

func TestStoreApprovalCheckerReportsStableRequesterTerminalReasons(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "approval-terminal-reasons"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	orch := orchestrator.NewOrchestrator(log, st, nil)
	checker := storeApprovalChecker{store: st, orch: orch, required: 1}
	for _, name := range []string{"expired", "superseded", "denied", "consumed"} {
		seedApplicationSecretFixture(t, st, tenantID, name, []byte("sealed-"+name))
	}

	intent := func(resourceID string) api.ApprovalIntent {
		return api.ApprovalIntent{
			TenantID: tenantID, ResourceKind: "secret", ResourceID: resourceID,
			ResourceName: strings.TrimPrefix(resourceID, "secret:"), Action: "rotate", Requester: "alice",
			FromState: "version:1", ToState: "version:2", TargetVersion: 1,
			Reason:       "authorize one exact terminal-reason test command",
			EvidenceRefs: []string{"command-sha256:" + resourceID}, RequiredApprovals: 1,
		}
	}
	open := func(in api.ApprovalIntent) api.ApprovalAuthority {
		t.Helper()
		authority, approved, reason := checker.AuthorizeApproval(ctx, in)
		if approved || authority.RequestID == "" || authority.IntentDigest == "" {
			t.Fatalf("open approval = authority %+v approved=%v reason=%q", authority, approved, reason)
		}
		return authority
	}
	reasonFor := func(in api.ApprovalIntent) string {
		t.Helper()
		_, approved, reason := checker.AuthorizeApproval(ctx, in)
		if approved {
			t.Fatalf("terminal approval unexpectedly authorized: %+v", in)
		}
		return reason
	}

	expiredIntent := intent("secret:expired")
	expiredIntent.TTL = time.Millisecond
	expired := open(expiredIntent)
	time.Sleep(5 * time.Millisecond)
	if got, want := reasonFor(expiredIntent), fmt.Sprintf("approval request %s (%s) expired", expired.RequestID, expired.IntentDigest); got != want {
		t.Errorf("expired requester reason = %q, want %q", got, want)
	}

	supersededIntent := intent("secret:superseded")
	superseded := open(supersededIntent)
	replacementIntent := supersededIntent
	replacementIntent.ToState = "version:3"
	replacementIntent.EvidenceRefs = []string{"command-sha256:replacement"}
	_ = open(replacementIntent)
	if got, want := reasonFor(supersededIntent), fmt.Sprintf("approval request %s (%s) superseded because its target or immutable intent drifted", superseded.RequestID, superseded.IntentDigest); got != want {
		t.Errorf("superseded requester reason = %q, want %q", got, want)
	}

	deniedIntent := intent("secret:denied")
	denied := open(deniedIntent)
	if _, err := orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: denied.RequestID, IntentDigest: denied.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionDeny,
	}); err != nil {
		t.Fatalf("deny request: %v", err)
	}
	if got, want := reasonFor(deniedIntent), fmt.Sprintf("approval request %s (%s) denied", denied.RequestID, denied.IntentDigest); got != want {
		t.Errorf("denied requester reason = %q, want %q", got, want)
	}

	consumedIntent := intent("secret:consumed")
	consumed := open(consumedIntent)
	approved, err := orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: consumed.RequestID, IntentDigest: consumed.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("approve request: %v", err)
	}
	use := store.OperationApprovalUse{
		RequestID: approved.ID, IntentDigest: approved.IntentDigest, Requester: approved.Requester,
		ResourceKind: approved.ResourceKind, ResourceID: approved.ResourceID, Action: approved.Action,
		FromState: approved.FromState, ToState: approved.ToState, TargetVersion: approved.TargetVersion,
		RequiredApprovals: approved.RequiredApprovals,
	}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return st.ConsumeOperationApprovalTx(ctx, tx, tenantID, use,
			"77000000-0000-4000-8000-000000000201", time.Now().UTC())
	}); err != nil {
		t.Fatalf("consume request: %v", err)
	}
	if got, want := reasonFor(consumedIntent), fmt.Sprintf("approval request %s (%s) already consumed", consumed.RequestID, consumed.IntentDigest); got != want {
		t.Errorf("consumed requester reason = %q, want %q", got, want)
	}
}
