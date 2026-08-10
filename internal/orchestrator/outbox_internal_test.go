// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// enqueue records an outbox entry under its tenant context and returns its id.
func enqueue(t *testing.T, s *store.Store, ob *orchestrator.Outbox, e orchestrator.Entry) int64 {
	t.Helper()
	var id int64
	if err := s.WithTenant(context.Background(), e.TenantID, func(tx pgx.Tx) error {
		var err error
		id, err = ob.Enqueue(context.Background(), tx, e)
		return err
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return id
}

// Two READ COMMITTED transactions can both evaluate NOT EXISTS before either
// commits. EnqueueIfAbsent must serialize the tenant/key pair so exactly one
// durable intent wins, even when both transactions reach the statement together.
func TestOutboxEnqueueIfAbsentIsAtomicAcrossConcurrentTransactions(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ob := orchestrator.NewOutbox(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entry := orchestrator.Entry{
		TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "concurrent-enqueue-1", Payload: []byte(`{"sealed":true}`),
	}

	type result struct {
		inserted bool
		err      error
	}
	const workers = 2
	ready := make(chan struct{}, workers)
	release := make(chan struct{})
	results := make(chan result, workers)
	for range workers {
		go func() {
			var inserted bool
			err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				ready <- struct{}{}
				<-release
				var err error
				inserted, err = ob.EnqueueIfAbsent(ctx, tx, entry)
				return err
			})
			results <- result{inserted: inserted, err: err}
		}()
	}
	for range workers {
		<-ready
	}
	close(release)

	inserted := 0
	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent enqueue: %v", result.err)
		}
		if result.inserted {
			inserted++
		}
	}
	if inserted != 1 {
		t.Fatalf("inserted transactions = %d, want exactly 1", inserted)
	}
	var rows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, entry.IdempotencyKey).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("durable outbox rows = %d, want exactly 1", rows)
	}
}

func TestOutboxEnqueueIfAbsentRejectsCrossSubsystemAndPayloadCollisions(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ob := orchestrator.NewOutbox(s)
	ctx := context.Background()
	first := orchestrator.Entry{
		TenantID: tenantA, Destination: "external-ca.issue",
		IdempotencyKey: "shared-raw-key", Payload: []byte(`{"authority_id":"ca-one"}`),
	}
	apply := func(entry orchestrator.Entry) (bool, error) {
		var inserted bool
		err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			var err error
			inserted, err = ob.EnqueueIfAbsent(ctx, tx, entry)
			return err
		})
		return inserted, err
	}
	if inserted, err := apply(first); err != nil || !inserted {
		t.Fatalf("initial enqueue = (%v, %v), want inserted", inserted, err)
	}
	if inserted, err := apply(first); err != nil || inserted {
		t.Fatalf("exact replay = (%v, %v), want existing exact command", inserted, err)
	}
	for label, changed := range map[string]orchestrator.Entry{
		"destination": {TenantID: tenantA, Destination: "notification.test", IdempotencyKey: first.IdempotencyKey, Payload: first.Payload},
		"payload":     {TenantID: tenantA, Destination: first.Destination, IdempotencyKey: first.IdempotencyKey, Payload: []byte(`{"authority_id":"ca-two"}`)},
		"effect lane": {TenantID: tenantA, Destination: first.Destination, IdempotencyKey: first.IdempotencyKey, Payload: first.Payload, EffectLane: "external-ca.issue:other"},
		"agent role":  {TenantID: tenantA, Destination: first.Destination, IdempotencyKey: first.IdempotencyKey, Payload: first.Payload, RequiredAgentRole: "control_plane"},
		"agent id":    {TenantID: tenantA, Destination: first.Destination, IdempotencyKey: first.IdempotencyKey, Payload: first.Payload, RequiredAgentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
	} {
		inserted, err := apply(changed)
		if inserted || !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("changed %s = (%v, %v), want durable idempotency conflict", label, inserted, err)
		}
		var commandConflict *orchestrator.OutboxCommandConflictError
		if !errors.As(err, &commandConflict) || commandConflict.ExistingOutboxID <= 0 ||
			commandConflict.ExistingPayloadSHA256 == "" || commandConflict.CandidatePayloadSHA256 == "" ||
			strings.Contains(err.Error(), "ca-one") || strings.Contains(err.Error(), "ca-two") {
			t.Fatalf("changed %s conflict lacks safe command identity: %#v", label, commandConflict)
		}
	}
}

func TestOutboxEffectLanesLetUnrelatedReceiversWithOneDestinationProgress(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
	)
	for _, entry := range []orchestrator.Entry{
		{TenantID: tenantA, Destination: "connector.deploy", EffectLane: "connector.deploy:nginx:edge-a", IdempotencyKey: "lane-a", Payload: []byte(`{}`)},
		{TenantID: tenantA, Destination: "connector.deploy", EffectLane: "connector.deploy:f5:edge-b", IdempotencyKey: "lane-b", Payload: []byte(`{}`)},
	} {
		enqueue(t, s, ob, entry)
	}
	started := make(chan string, 2)
	release := make(chan struct{})
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		started <- message.EffectLane
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := ob.DispatchScoped(context.Background(), handler, orchestrator.DestinationScope{IncludePrefixes: []string{"connector."}})
			results <- err
		}()
	}
	seen := map[string]bool{}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for len(seen) < 2 {
		select {
		case lane := <-started:
			seen[lane] = true
		case <-deadline.C:
			close(release)
			t.Fatalf("same-destination effect lanes started = %#v, want both", seen)
		}
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("lane dispatch: %v", err)
		}
	}
}

// TestOutboxDeadLettersAtMaxAttempts is the dead-letter boundary (SPINE-012): an
// entry whose handler keeps failing is retried until the attempt cap, then marked
// failed and never dispatched again. With maxAttempts=3 and a zero backoff, three
// Dispatch sweeps must take it: pending -> pending -> failed.
func TestOutboxDeadLettersAtMaxAttempts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithMaxAttempts(3),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "dead-1", Payload: []byte(`{}`),
	})

	attempts := 0
	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		attempts++
		return errors.New("boom")
	})

	// Each Dispatch drains the currently-due backlog; with a zero backoff the entry
	// is immediately due again, so ONE Dispatch call would spin — but Dispatch breaks
	// when it re-sees an already-handled id. So we sweep three times.
	for i := 0; i < 3; i++ {
		if _, err := ob.Dispatch(ctx, failing); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
	}
	if attempts != 3 {
		t.Fatalf("handler attempts = %d, want 3 (one per sweep up to the cap)", attempts)
	}

	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "failed" {
		t.Fatalf("status = %q after %d attempts, want \"failed\" (dead-lettered at the cap)", rec.Status, rec.Attempts)
	}
	if rec.Attempts != 3 {
		t.Fatalf("recorded attempts = %d, want 3", rec.Attempts)
	}

	// A dead-lettered entry is not dispatched again: a further sweep is a no-op.
	before := attempts
	if _, err := ob.Dispatch(ctx, failing); err != nil {
		t.Fatal(err)
	}
	if attempts != before {
		t.Fatalf("a failed entry was re-dispatched (attempts %d -> %d); dead-letter must be terminal", before, attempts)
	}
}

type deferredThenSuccessfulHandler struct {
	deferredCalls int
	delivered     int
	terminal      int
}

func (h *deferredThenSuccessfulHandler) Deliver(context.Context, orchestrator.Message) error {
	if h.deferredCalls < 2 {
		h.deferredCalls++
		return orchestrator.DeferDelivery(errors.New("operator prerequisite closed"))
	}
	h.delivered++
	return nil
}

func (h *deferredThenSuccessfulHandler) DeliverTerminalFailure(context.Context, orchestrator.Message, error) error {
	h.terminal++
	return nil
}

func TestOutboxDeferredDeliveryRefundsAttemptAndSurvivesPastDeadLetterCap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithMaxAttempts(1),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "secret.sync.test", IdempotencyKey: "deferred-1", Payload: []byte(`{}`),
	})
	handler := &deferredThenSuccessfulHandler{}

	for sweep := 0; sweep < 2; sweep++ {
		if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
			t.Fatalf("deferred dispatch %d = (%d, %v), want (1, nil)", sweep, n, err)
		}
		record, err := ob.Get(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != "pending" || record.Attempts != 0 || record.LastError != "delivery_deferred" {
			t.Fatalf("deferred row %d = status %q attempts %d error %q, want pending/0/delivery_deferred", sweep, record.Status, record.Attempts, record.LastError)
		}
	}
	if handler.terminal != 0 {
		t.Fatalf("deferred delivery invoked terminal callback %d times", handler.terminal)
	}
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("unblocked dispatch = (%d, %v), want (1, nil)", n, err)
	}
	record, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "delivered" || record.Attempts != 1 || handler.delivered != 1 {
		t.Fatalf("unblocked row = status %q attempts %d deliveries %d, want delivered/1/1", record.Status, record.Attempts, handler.delivered)
	}
}

type terminalFailureFixture struct {
	called bool
}

func (*terminalFailureFixture) Deliver(context.Context, orchestrator.Message) error {
	return errors.New("provider echoed sensitive body")
}

func (f *terminalFailureFixture) DeliverTerminalFailure(_ context.Context, _ orchestrator.Message, _ error) error {
	f.called = true
	return nil
}

func TestOutboxProjectsTerminalFailureBeforeDeadLetterWithSanitizedError(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s, orchestrator.WithMaxAttempts(1))
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "secret.sync.test", IdempotencyKey: "terminal-1", Payload: []byte(`{}`),
	})
	handler := &terminalFailureFixture{}
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("Dispatch = (%d, %v), want (1, nil)", n, err)
	}
	if !handler.called {
		t.Fatal("terminal domain callback was not called before dead-letter finalization")
	}
	record, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "failed" || record.LastError != "external_delivery_failed" {
		t.Fatalf("dead letter = status %q error %q, want failed/sanitized code", record.Status, record.LastError)
	}
}

// TestOutboxBackoffDefersRetry is the backoff arithmetic (SPINE-012): a failed
// entry is scheduled into the future (next_attempt_at = now + backoff(attempts)), so
// it is NOT due on an immediate re-sweep. With a long backoff, the second sweep must
// skip it.
func TestOutboxBackoffDefersRetry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
	)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "backoff-1", Payload: []byte(`{}`),
	})

	attempts := 0
	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		attempts++
		return errors.New("boom")
	})
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 1 {
		t.Fatalf("first dispatch n=%d err=%v, want 1, nil", n, err)
	}
	// The retry is an hour out, so a second sweep finds nothing due.
	if n, err := ob.Dispatch(ctx, failing); err != nil || n != 0 {
		t.Fatalf("second dispatch n=%d err=%v, want 0, nil (entry deferred by backoff)", n, err)
	}
	if attempts != 1 {
		t.Fatalf("handler attempts = %d, want 1 (backoff must defer the retry)", attempts)
	}
}

func TestOutboxRetryJitterDesynchronizesSameDestinationRows(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	jitters := []time.Duration{125 * time.Millisecond, 375 * time.Millisecond}
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return time.Second }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration {
			if len(jitters) == 0 {
				t.Fatal("retry jitter called more times than expected")
			}
			next := jitters[0]
			jitters = jitters[1:]
			return next
		}),
		orchestrator.WithCircuitBreaker(10, time.Minute),
	)
	firstID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "jitter-1", Payload: []byte(`{}`),
	})
	secondID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "jitter-2", Payload: []byte(`{}`),
	})

	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("webhook unavailable")
	}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("Dispatch processed %d rows, want both due rows", n)
	}

	nextAttempts := nextAttemptTimes(t, s, firstID, secondID)
	if !nextAttempts[firstID].Equal(now.Add(125 * time.Millisecond)) {
		t.Fatalf("first next_attempt_at = %s, want %s", nextAttempts[firstID], now.Add(125*time.Millisecond))
	}
	if !nextAttempts[secondID].Equal(now.Add(375 * time.Millisecond)) {
		t.Fatalf("second next_attempt_at = %s, want %s", nextAttempts[secondID], now.Add(375*time.Millisecond))
	}
	if nextAttempts[firstID].Equal(nextAttempts[secondID]) {
		t.Fatal("same-destination retries landed on the same next_attempt_at; jitter must desynchronize them")
	}
}

func TestOutboxOpenCircuitPreventsClaimsUntilHalfOpenProbe(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithCircuitBreaker(1, time.Minute),
	)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "circuit-1", Payload: []byte(`{}`),
	})
	secondID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "circuit-2", Payload: []byte(`{}`),
	})

	failures := 0
	failThenSucceed := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		failures++
		if failures == 1 {
			return errors.New("webhook down")
		}
		return nil
	})
	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 1 {
		t.Fatalf("first dispatch n=%d err=%v, want one failed probe", n, err)
	}
	snapshots := ob.CircuitStates()
	if len(snapshots) != 1 || snapshots[0].State != orchestrator.CircuitOpen {
		t.Fatalf("circuit snapshots after failure = %+v, want one open circuit", snapshots)
	}

	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 0 {
		t.Fatalf("open-circuit dispatch n=%d err=%v, want no claim before probe window", n, err)
	}
	rec, err := ob.Get(ctx, tenantA, secondID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 0 || rec.Status != "pending" {
		t.Fatalf("second row after open circuit = {status:%q attempts:%d}, want untouched pending row", rec.Status, rec.Attempts)
	}

	now = now.Add(time.Minute + time.Nanosecond)
	if n, err := ob.Dispatch(ctx, failThenSucceed); err != nil || n != 2 {
		t.Fatalf("half-open dispatch n=%d err=%v, want the successful probe plus the next queued row", n, err)
	}
	rec, err = ob.Get(ctx, tenantA, secondID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 1 {
		t.Fatalf("second row after half-open probe = {status:%q attempts:%d}, want delivered/1", rec.Status, rec.Attempts)
	}
	snapshots = ob.CircuitStates()
	if len(snapshots) != 1 || snapshots[0].State != orchestrator.CircuitClosed || snapshots[0].Failures != 0 {
		t.Fatalf("circuit snapshots after successful probe = %+v, want closed/reset circuit", snapshots)
	}
}

func TestOutboxScopedCircuitUsesReceiverLaneWithoutEscapingItsFamily(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithCircuitBreaker(1, time.Minute),
	)
	const lane = "dynsecret.provider:postgresql"
	for index, destination := range []string{"dynsecret.issue", "dynsecret.revoke"} {
		enqueue(t, s, ob, orchestrator.Entry{
			TenantID: tenantA, Destination: destination, EffectLane: lane,
			IdempotencyKey: fmt.Sprintf("dynsecret-circuit-%d", index), Payload: []byte(`{}`),
		})
	}
	calls := 0
	failing := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		calls++
		return errors.New("provider unavailable")
	})
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{"dynsecret."}}
	if n, err := ob.DispatchScoped(ctx, failing, scope); err != nil || n != 1 {
		t.Fatalf("first dynamic-secret dispatch n=%d err=%v, want one failed receiver call", n, err)
	}
	if n, err := ob.DispatchScoped(ctx, failing, scope); err != nil || n != 0 {
		t.Fatalf("open receiver-lane circuit dispatch n=%d err=%v, want no claim", n, err)
	}
	if calls != 1 {
		t.Fatalf("dynamic-secret provider calls=%d, want one before its lane circuit opens", calls)
	}
}

func TestManagedKeyEffectLanesKeepOneKeyCircuitFromStarvingAnother(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithNow(func() time.Time { return now }),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithCircuitBreaker(1, time.Minute),
	)
	const (
		blockedLane = "managedkey.command:aws-kms:key-blocked"
		healthyLane = "managedkey.command:aws-kms:key-healthy"
	)
	for index, lane := range []string{blockedLane, healthyLane} {
		enqueue(t, s, ob, orchestrator.Entry{
			TenantID: tenantA, Destination: "managedkey.command", EffectLane: lane,
			IdempotencyKey: fmt.Sprintf("managed-key-lane-%d", index), Payload: []byte(`{}`),
		})
	}
	seen := make([]string, 0, 2)
	handler := orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		seen = append(seen, message.EffectLane)
		if message.EffectLane == blockedLane {
			return errors.New("one managed key is unavailable")
		}
		return nil
	})
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{"managedkey."}}
	if n, err := ob.DispatchScoped(ctx, handler, scope); err != nil || n != 2 {
		t.Fatalf("managed-key lane dispatch n=%d err=%v, want failed lane plus healthy lane", n, err)
	}
	if len(seen) != 2 || seen[0] != blockedLane || seen[1] != healthyLane {
		t.Fatalf("managed-key lane delivery order=%v, want blocked then independently healthy", seen)
	}
	snapshots := ob.CircuitStates()
	if len(snapshots) != 1 || snapshots[0].TenantID != tenantA || snapshots[0].Destination != blockedLane || snapshots[0].State != orchestrator.CircuitOpen {
		t.Fatalf("managed-key circuit snapshots=%+v, want only blocked key lane open", snapshots)
	}
}

// TestOutboxDeliversAndMarksDelivered is the happy path: a succeeding handler marks
// the entry delivered, and it is not dispatched again.
func TestOutboxDeliversAndMarksDelivered(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "ok-1", Payload: []byte(`{"x":1}`),
	})

	var got []orchestrator.Message
	h := orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		got = append(got, m)
		return nil
	})
	if n, err := ob.Dispatch(ctx, h); err != nil || n != 1 {
		t.Fatalf("dispatch n=%d err=%v, want 1, nil", n, err)
	}
	if len(got) != 1 || got[0].IdempotencyKey != "ok-1" || got[0].TenantID != tenantA {
		t.Fatalf("delivered message = %+v, want the ok-1 entry carrying its tenant", got)
	}
	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" {
		t.Fatalf("status = %q, want delivered", rec.Status)
	}
	// A second sweep delivers nothing more.
	if n, err := ob.Dispatch(ctx, h); err != nil || n != 0 {
		t.Fatalf("re-dispatch n=%d err=%v, want 0, nil", n, err)
	}
}

// A relay reports after the external effect already happened. Closing its claim
// and retiring the outbox intent therefore has one commit boundary: a crash may
// leave both open for retry, but must never leave a closed claim on a pending
// row that future attempts can execute but can no longer complete.
func TestAgentJobCompletionAtomicallyClosesClaimAndDelivery(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	const agentID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "cmdb.sync", IdempotencyKey: "cmdb:atomic-1", Payload: []byte(`{"page_limit":500}`),
	})
	now := time.Now().UTC()
	jobs, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{"cmdb.sync"}, nil, 1, time.Minute, now)
	if err != nil || len(jobs) != 1 || jobs[0].ID != id {
		t.Fatalf("claim jobs=%+v err=%v", jobs, err)
	}
	job := jobs[0]

	if completed, err := ob.CompleteAgentJobClaim(ctx, tenantA, agentID, id, job.ClaimAttempts+1, now); err != nil || completed {
		t.Fatalf("wrong attempt completion=(%v, %v), want refused", completed, err)
	}
	assertState := func(wantStatus string, wantClaimComplete bool) {
		t.Helper()
		var status string
		var claimComplete bool
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT status, claim_completed_at IS NOT NULL FROM outbox WHERE tenant_id = $1 AND id = $2`,
				tenantA, id).Scan(&status, &claimComplete)
		}); err != nil {
			t.Fatal(err)
		}
		if status != wantStatus || claimComplete != wantClaimComplete {
			t.Fatalf("row=(status %q, completed %v), want (%q, %v)", status, claimComplete, wantStatus, wantClaimComplete)
		}
	}
	assertState("pending", false)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if completed, err := ob.CompleteAgentJobClaim(canceled, tenantA, agentID, id, job.ClaimAttempts, now); err == nil || completed {
		t.Fatalf("interrupted completion=(%v, %v), want error with no partial close", completed, err)
	}
	assertState("pending", false)

	if completed, err := ob.CompleteAgentJobClaim(ctx, tenantA, agentID, id, job.ClaimAttempts, now); err != nil || !completed {
		t.Fatalf("exact completion=(%v, %v), want one atomic completion", completed, err)
	}
	assertState("delivered", true)
	if completed, err := ob.CompleteAgentJobClaim(ctx, tenantA, agentID, id, job.ClaimAttempts, now); err != nil || completed {
		t.Fatalf("replay completion=(%v, %v), want no-op", completed, err)
	}

	reclaimed, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{"cmdb.sync"}, nil, 1, time.Minute, now.Add(2*time.Minute))
	if err != nil || len(reclaimed) != 0 {
		t.Fatalf("completed outbox job was reclaimable: jobs=%+v err=%v", reclaimed, err)
	}
}

// TestDispatchOneSkipLockedDoesNotDoubleDeliver is the claim guarantee
// (SPINE-012): two dispatchers sweeping the same single due entry concurrently
// must deliver it exactly once between them, never twice. One leases the row; the
// other sees no pending copy and finds nothing.
func TestDispatchOneSkipLockedDoesNotDoubleDeliver(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "race-1", Payload: []byte(`{}`),
	})

	var mu sync.Mutex
	delivered := 0
	// The handler blocks briefly so both dispatchers overlap on the claim window.
	h := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		delivered++
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	totals := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n, err := ob.Dispatch(ctx, h)
			if err != nil {
				t.Errorf("dispatch %d: %v", idx, err)
			}
			totals[idx] = n
		}(i)
	}
	wg.Wait()

	if delivered != 1 {
		t.Fatalf("entry delivered %d times under concurrent dispatch, want exactly 1 (SKIP LOCKED claim)", delivered)
	}
	if totals[0]+totals[1] != 1 {
		t.Fatalf("dispatchers processed %d entries total, want 1 (one claims, the other skips the locked row)", totals[0]+totals[1])
	}
}

// TestOutboxLeasesDoNotStarveUnrelatedTenants is the SPINE-002 acceptance: a
// slow destination for tenant A must not hold a database row lock through the
// external call, and another outbox worker must be able to deliver tenant B's fast
// destination while tenant A is still blocked.
func TestOutboxLeasesDoNotStarveUnrelatedTenants(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
		orchestrator.WithMaxInFlightPerDestination(1),
		orchestrator.WithMaxInFlightPerTenant(1),
		orchestrator.WithWorkerID("fairness-test"),
	)

	slowID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "slow-ca", IdempotencyKey: "slow-1", Payload: []byte(`{}`),
	})
	enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "slow-ca", IdempotencyKey: "slow-2", Payload: []byte(`{}`),
	})
	fastID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantB, Destination: "fast-webhook", IdempotencyKey: "fast-1", Payload: []byte(`{}`),
	})

	slowEntered := make(chan struct{})
	releaseSlow := make(chan struct{})
	fastDelivered := make(chan struct{})
	var slowOnce, fastOnce sync.Once
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		switch m.Destination {
		case "slow-ca":
			slowOnce.Do(func() { close(slowEntered) })
			select {
			case <-releaseSlow:
				return errors.New("slow destination still unavailable")
			case <-ctx.Done():
				return ctx.Err()
			}
		case "fast-webhook":
			fastOnce.Do(func() { close(fastDelivered) })
			return nil
		default:
			t.Fatalf("unexpected destination %q", m.Destination)
			return nil
		}
	})

	errs := make(chan error, 2)
	go func() {
		_, err := ob.Dispatch(ctx, handler)
		errs <- err
	}()

	select {
	case <-slowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("slow outbox handler was not entered")
	}
	assertOutboxRowNotLocked(t, s, slowID)

	go func() {
		n, err := ob.Dispatch(ctx, handler)
		if err == nil && n == 0 {
			err = errors.New("second dispatcher did not process tenant B's fast row")
		}
		errs <- err
	}()

	select {
	case <-fastDelivered:
	case <-time.After(500 * time.Millisecond):
		close(releaseSlow)
		t.Fatal("tenant B fast destination was starved behind tenant A slow destination")
	}

	close(releaseSlow)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("dispatch %d: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("dispatch %d did not return", i)
		}
	}

	rec, err := ob.Get(ctx, tenantB, fastID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" {
		t.Fatalf("tenant B fast row status = %q, want delivered", rec.Status)
	}
}

// TestOutboxDeliveryTimeoutRetriesAndDrainsUnrelatedDestination proves that a
// wedged external destination spends only one bounded message deadline on an
// outbox worker. The timed-out row is returned to pending with backoff, while an
// unrelated tenant/destination still drains in the same sweep.
func TestOutboxDeliveryTimeoutRetriesAndDrainsUnrelatedDestination(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s,
		orchestrator.WithBackoff(func(int) time.Duration { return time.Hour }),
		orchestrator.WithDeliveryTimeout(25*time.Millisecond),
		orchestrator.WithMaxInFlightPerDestination(1),
		orchestrator.WithMaxInFlightPerTenant(1),
		orchestrator.WithWorkerID("timeout-test"),
	)

	slowID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "timeout-slow-1", Payload: []byte(`{}`),
	})
	fastID := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantB, Destination: "notification.webhook", IdempotencyKey: "timeout-fast-1", Payload: []byte(`{}`),
	})

	slowEntered := make(chan struct{})
	fastDelivered := make(chan struct{})
	var slowOnce, fastOnce sync.Once
	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		switch m.Destination {
		case "connector.deploy":
			slowOnce.Do(func() { close(slowEntered) })
			<-ctx.Done()
			return ctx.Err()
		case "notification.webhook":
			fastOnce.Do(func() { close(fastDelivered) })
			return nil
		default:
			t.Fatalf("unexpected destination %q", m.Destination)
			return nil
		}
	})

	start := time.Now()
	n, err := ob.Dispatch(ctx, handler)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("Dispatch processed %d rows, want 2 (slow timeout plus unrelated fast delivery)", n)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Dispatch took %v, want it bounded by the per-message delivery timeout", elapsed)
	}

	select {
	case <-slowEntered:
	default:
		t.Fatal("slow destination was never invoked")
	}
	select {
	case <-fastDelivered:
	default:
		t.Fatal("unrelated destination did not drain after the slow timeout")
	}

	slow, err := ob.Get(ctx, tenantA, slowID)
	if err != nil {
		t.Fatal(err)
	}
	if slow.Status != "pending" || slow.Attempts != 1 || slow.LastError != "external_delivery_timeout" {
		t.Fatalf("slow row = {status:%q attempts:%d last_error:%q}, want pending/1/external_delivery_timeout",
			slow.Status, slow.Attempts, slow.LastError)
	}

	fast, err := ob.Get(ctx, tenantB, fastID)
	if err != nil {
		t.Fatal(err)
	}
	if fast.Status != "delivered" {
		t.Fatalf("fast row status = %q, want delivered", fast.Status)
	}
}

func assertOutboxRowNotLocked(t *testing.T, s *store.Store, id int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock probe: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var got int64
	if err := tx.QueryRow(ctx, `SELECT id FROM outbox WHERE id = $1 FOR UPDATE NOWAIT`, id).Scan(&got); err != nil {
		t.Fatalf("outbox row %d is still locked while handler is sleeping: %v", id, err)
	}
	if got != id {
		t.Fatalf("lock probe got row %d, want %d", got, id)
	}
}

func nextAttemptTimes(t *testing.T, s *store.Store, ids ...int64) map[int64]time.Time {
	t.Helper()
	out := make(map[int64]time.Time, len(ids))
	for _, id := range ids {
		var next time.Time
		if err := s.SystemPool().QueryRow(context.Background(), `SELECT next_attempt_at FROM outbox WHERE id = $1`, id).Scan(&next); err != nil {
			t.Fatalf("read next_attempt_at for row %d: %v", id, err)
		}
		out[id] = next
	}
	return out
}

// TestOutboxExpiredLeaseIsReclaimed proves a worker crash after claim but before
// finalize does not strand an outbox row forever: the next dispatcher returns the
// expired lease to pending and redelivers it with the same idempotency key.
func TestOutboxExpiredLeaseIsReclaimed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s, orchestrator.WithWorkerID("rescuer"))
	id := enqueue(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "webhook", IdempotencyKey: "lease-retry-1", Payload: []byte(`{}`),
	})
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox
		    SET status = 'processing',
		        worker_id = 'dead-worker',
		        lease_until = now() - interval '1 second',
		        attempts = 1
		  WHERE id = $1`, id); err != nil {
		t.Fatalf("seed expired lease: %v", err)
	}

	var delivered []orchestrator.Message
	n, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		delivered = append(delivered, m)
		return nil
	}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if n != 1 || len(delivered) != 1 {
		t.Fatalf("dispatch after expired lease = %d deliveries=%d, want exactly 1", n, len(delivered))
	}
	if delivered[0].IdempotencyKey != "lease-retry-1" {
		t.Fatalf("redelivered key = %q, want lease-retry-1", delivered[0].IdempotencyKey)
	}
	rec, err := ob.Get(ctx, tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "delivered" || rec.Attempts != 2 {
		t.Fatalf("rec = {status:%q attempts:%d}, want delivered/2", rec.Status, rec.Attempts)
	}
}

// TestIdempotencyDoRunsOnceCachesResult is the AN-5 core (SPINE-012): Do runs fn
// once per (tenant, key) and returns the recorded result on a replay without
// re-running fn.
func TestIdempotencyDoRunsOnceCachesResult(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	runs := 0
	fn := func(context.Context) ([]byte, error) {
		runs++
		return []byte("result-v1"), nil
	}
	first, err := idem.Do(ctx, tenantA, "k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := idem.Do(ctx, tenantA, "k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("fn ran %d times, want 1 (replay returns the cached result)", runs)
	}
	if string(first) != "result-v1" || string(second) != "result-v1" {
		t.Fatalf("results = %q / %q, want both result-v1", first, second)
	}
}

func TestIdempotencyDoBoundReplaysOnlyMatchingAuthenticatedCommand(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	const (
		key          = "bound-transactional-sensitive"
		binding      = "sha256:issuer-a-post-exact-path"
		otherBinding = "sha256:issuer-b-or-other-path"
		secretResult = "credential-sentinel-must-not-leak" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	)

	runs := 0
	first, err := idem.DoBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
		runs++
		return []byte(secretResult), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := idem.DoBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
		t.Fatal("matching replay executed callback")
		return nil, nil
	})
	if err != nil || string(first) != secretResult || string(replay) != secretResult || runs != 1 {
		t.Fatalf("bound replay first=%q replay=%q runs=%d err=%v", first, replay, runs, err)
	}
	changedRan := false
	changed, err := idem.DoBound(ctx, tenantA, key, otherBinding, func(context.Context) ([]byte, error) {
		changedRan = true
		return []byte("wrong-effect"), nil
	})
	if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || changedRan || len(changed) != 0 {
		t.Fatalf("changed binding result=%q err=%v callback=%v, want empty conflict", changed, err, changedRan)
	}

	const legacyKey = "legacy-unbound-credential-cache"
	if _, err := idem.Do(ctx, tenantA, legacyKey, func(context.Context) ([]byte, error) {
		return []byte(secretResult), nil
	}); err != nil {
		t.Fatal(err)
	}
	legacyRan := false
	legacyResult, err := idem.DoBound(ctx, tenantA, legacyKey, binding, func(context.Context) ([]byte, error) {
		legacyRan = true
		return []byte("must-not-run"), nil
	})
	if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || legacyRan || len(legacyResult) != 0 {
		t.Fatalf("legacy unbound collision result=%q err=%v callback=%v, want empty conflict", legacyResult, err, legacyRan)
	}
}

func TestBoundCredentialCacheIsOpaqueToEveryLegacyUnboundReader(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	const (
		binding = "sha256:authenticated-api-command"
		secret  = "bound-credential-sentinel-must-not-open" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	)
	tests := []struct {
		name string
		call func(string, func(context.Context) ([]byte, error)) ([]byte, error)
	}{
		{name: "Do", call: func(key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.Do(ctx, tenantA, key, fn)
		}},
		{name: "DoDurableEffect", call: func(key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.DoDurableEffect(ctx, tenantA, key, fn)
		}},
		{name: "DoAtMostOnceEffect", call: func(key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.DoAtMostOnceEffect(ctx, tenantA, key, fn)
		}},
		{name: "Result", call: func(key string, _ func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.Result(ctx, tenantA, key)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := "bound-to-legacy-" + test.name
			if _, err := idem.DoBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
				return []byte(secret), nil
			}); err != nil {
				t.Fatal(err)
			}
			called := false
			result, err := test.call(key, func(context.Context) ([]byte, error) {
				called = true
				return []byte("legacy-effect-must-not-run"), nil
			})
			if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || called || len(result) != 0 {
				t.Fatalf("bound->legacy result=%q err=%v callback=%v, want empty conflict", result, err, called)
			}
			if strings.Contains(string(result), secret) || strings.Contains(err.Error(), secret) {
				t.Fatalf("bound->legacy conflict disclosed secret result=%q err=%v", result, err)
			}
		})
	}
}

func TestIdempotencyDoBoundConcurrentSameBindingSingleFlight(t *testing.T) {
	s := newStore(t)
	idem := orchestrator.NewIdempotency(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const result = "transactional-single-flight-result"

	var callsMu sync.Mutex
	calls := 0
	countCall := func() {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	type callResult struct {
		result []byte
		err    error
	}
	firstDone := make(chan callResult, 1)
	go func() {
		got, err := idem.DoBound(ctx, tenantA, "bound-transactional-concurrent", "same-authenticated-command", func(context.Context) ([]byte, error) {
			countCall()
			close(entered)
			<-release
			return []byte(result), nil
		})
		firstDone <- callResult{result: got, err: err}
	}()
	<-entered

	secondStarted := make(chan struct{})
	secondDone := make(chan callResult, 1)
	go func() {
		close(secondStarted)
		got, err := idem.DoBound(ctx, tenantA, "bound-transactional-concurrent", "same-authenticated-command", func(context.Context) ([]byte, error) {
			countCall()
			return []byte("second-effect-must-not-win"), nil
		})
		secondDone <- callResult{result: got, err: err}
	}()
	<-secondStarted
	deadline := time.Now().Add(2 * time.Second)
	for s.SystemPool().Stat().AcquiredConns() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	first, second := <-firstDone, <-secondDone
	if first.err != nil || second.err != nil || string(first.result) != result || string(second.result) != result {
		t.Fatalf("single-flight first=%q/%v second=%q/%v", first.result, first.err, second.result, second.err)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("concurrent bound callback ran %d times, want 1", calls)
	}
}

// TestIdempotencyDoDurableEffectReleasesTenantTransactionBeforeEffect is the
// AN-6/AN-7 regression: a slow receiver must not pin an RLS transaction or one of
// the bounded PostgreSQL connections while it is doing external work. The result
// is still cached, so a replay does not call the receiver again.
func TestIdempotencyDoDurableEffectReleasesTenantTransactionBeforeEffect(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	baseline := s.SystemPool().Stat().AcquiredConns()

	calls := 0
	fn := func(context.Context) ([]byte, error) {
		calls++
		if got := s.SystemPool().Stat().AcquiredConns(); got != baseline {
			t.Fatalf("outbox effect runs with %d acquired database connections, baseline %d; tenant transaction was not released", got, baseline)
		}
		// A fresh query must remain usable while the effect callback is active.
		var one int
		if err := s.SystemPool().QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			return nil, fmt.Errorf("probe database while outbox effect runs: value=%d err=%w", one, err)
		}
		return []byte("external-result-v1"), nil
	}

	first, err := idem.DoDurableEffect(ctx, tenantA, "external:k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := idem.DoDurableEffect(ctx, tenantA, "external:k1", fn)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(first) != "external-result-v1" || string(second) != "external-result-v1" {
		t.Fatalf("calls=%d results=%q/%q, want one receiver call and two identical cached results", calls, first, second)
	}
}

func TestIdempotencyDoDurableEffectBoundRejectsChangedCommandAcrossCrashGap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	const (
		key          = "dynamic-issue-bound-crash"
		firstBinding = "sha256:first-principal-provider-role-ttl"
		otherBinding = "sha256:changed-principal-provider-role-ttl"
	)

	receiverCalls := 0
	receiverCreated := false
	crash := errors.New("injected crash after durable receiver commit")
	if _, err := idem.DoDurableEffectBound(ctx, tenantA, key, firstBinding, func(context.Context) ([]byte, error) {
		receiverCalls++
		receiverCreated = true
		return nil, crash
	}); !errors.Is(err, crash) {
		t.Fatalf("first bound durable effect error = %v, want injected crash", err)
	}
	if !receiverCreated || receiverCalls != 1 {
		t.Fatalf("receiver created=%v calls=%d, want one committed receiver effect", receiverCreated, receiverCalls)
	}
	if _, err := idem.BoundResult(ctx, tenantA, key, firstBinding); !errors.Is(err, orchestrator.ErrInProgress) {
		t.Fatalf("bound result during reconciliation = %v, want ErrInProgress", err)
	}
	if _, err := idem.BoundResult(ctx, tenantA, key, otherBinding); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("changed caller bound result = %v, want ErrIdempotencyConflict", err)
	}

	changedRan := false
	if _, err := idem.DoDurableEffectBound(ctx, tenantA, key, otherBinding, func(context.Context) ([]byte, error) {
		changedRan = true
		return []byte("must-not-run"), nil
	}); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("changed binding error = %v, want ErrIdempotencyConflict", err)
	}
	if changedRan {
		t.Fatal("changed authenticated command reached the durable receiver")
	}

	result, err := idem.DoDurableEffectBound(ctx, tenantA, key, firstBinding, func(context.Context) ([]byte, error) {
		receiverCalls++
		if !receiverCreated {
			t.Fatal("retry lost durable receiver state")
		}
		return []byte("sealed-original-result"), nil
	})
	if err != nil {
		t.Fatalf("identical retry after crash: %v", err)
	}
	if string(result) != "sealed-original-result" || receiverCalls != 2 {
		t.Fatalf("retry result=%q receiver calls=%d, want reconciled result and two callback attempts", result, receiverCalls)
	}
	boundResult, err := idem.BoundResult(ctx, tenantA, key, firstBinding)
	if err != nil || string(boundResult) != "sealed-original-result" {
		t.Fatalf("completed bound result=%q err=%v", boundResult, err)
	}

	replay, err := idem.DoDurableEffectBound(ctx, tenantA, key, firstBinding, func(context.Context) ([]byte, error) {
		t.Fatal("completed identical replay called receiver")
		return nil, nil
	})
	if err != nil || string(replay) != "sealed-original-result" {
		t.Fatalf("completed replay result=%q err=%v", replay, err)
	}
}

func TestIdempotencyDoDurableEffectBoundBlocksConcurrentChangedCaller(t *testing.T) {
	s := newStore(t)
	idem := orchestrator.NewIdempotency(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)

	go func() {
		_, err := idem.DoDurableEffectBound(ctx, tenantA, "bound-concurrent", "caller-a-command", func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			return []byte("caller-a-result"), nil
		})
		firstDone <- err
	}()
	<-entered
	changedRan := false
	if _, err := idem.DoDurableEffectBound(ctx, tenantA, "bound-concurrent", "caller-b-command", func(context.Context) ([]byte, error) {
		changedRan = true
		return nil, nil
	}); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		close(release)
		t.Fatalf("concurrent changed caller error = %v, want ErrIdempotencyConflict", err)
	}
	if changedRan {
		close(release)
		t.Fatal("concurrent changed caller reached callback")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first bound caller: %v", err)
	}
}

func TestIdempotencyDoAtMostOnceEffectNeverBlindlyRetriesAmbiguousReceiver(t *testing.T) {
	s := newStore(t)
	idem := orchestrator.NewIdempotency(s)
	ctx := context.Background()
	calls := 0
	fn := func(context.Context) ([]byte, error) {
		calls++
		return nil, errors.New("connection lost after request write")
	}
	if _, err := idem.DoAtMostOnceEffect(ctx, tenantA, "external-ca:ambiguous", fn); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
		t.Fatalf("first ambiguous result = %v, want ErrEffectIndeterminate", err)
	}
	if _, err := idem.DoAtMostOnceEffect(ctx, tenantA, "external-ca:ambiguous", fn); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
		t.Fatalf("replay ambiguous result = %v, want ErrEffectIndeterminate", err)
	}
	if calls != 1 {
		t.Fatalf("non-idempotent receiver called %d times, want exactly once", calls)
	}
}

// TestIdempotencyDoDoesNotCacheFailures is the failure-not-cached path (SPINE-012):
// when fn fails, the claim rolls back so a later retry is free to run fn again and
// succeed.
func TestIdempotencyDoDoesNotCacheFailures(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)

	attempt := 0
	fn := func(context.Context) ([]byte, error) {
		attempt++
		if attempt == 1 {
			return nil, errors.New("transient")
		}
		return []byte("ok"), nil
	}
	if _, err := idem.Do(ctx, tenantA, "k2", fn); err == nil {
		t.Fatal("first Do should surface fn's error")
	}
	out, err := idem.Do(ctx, tenantA, "k2", fn)
	if err != nil {
		t.Fatalf("retry after a failed attempt should run fn again and succeed, got %v", err)
	}
	if string(out) != "ok" {
		t.Fatalf("retry result = %q, want ok", out)
	}
	if attempt != 2 {
		t.Fatalf("fn ran %d times, want 2 (a failed attempt is not cached, so the retry re-runs)", attempt)
	}
}

// TestIdempotencyDoIsTenantScoped proves the AN-1 confinement: the SAME key in two
// tenants is two independent operations (RLS keys on tenant_id), so both run.
func TestIdempotencyDoIsTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	// Both tenants must exist for any FK-free idempotency_keys write; the table has
	// no FK to tenants, so a bare insert is fine, but we register them for realism.
	mustRegisterTenant(t, s, tenantA)
	mustRegisterTenant(t, s, tenantB)

	runs := map[string]int{}
	mk := func(tag string) func(context.Context) ([]byte, error) {
		return func(context.Context) ([]byte, error) { runs[tag]++; return []byte(tag), nil }
	}
	if _, err := idem.Do(ctx, tenantA, "shared", mk("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := idem.Do(ctx, tenantB, "shared", mk("B")); err != nil {
		t.Fatal(err)
	}
	if runs["A"] != 1 || runs["B"] != 1 {
		t.Fatalf("runs = %v, want each tenant's op to run once (key is tenant-scoped)", runs)
	}
}

// mustRegisterTenant inserts a tenant row directly (system role) so tenant-scoped
// writes have a parent where needed.
func mustRegisterTenant(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if err := s.UpsertTenant(context.Background(), store.Tenant{TenantID: id, Name: "t-" + id}); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
}
