// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// AN-6 regression guard for the served secret-integration outbox queues.
//
// These queues are drained twice. The outbox dispatcher
// (secretIntegrationOutboxDispatcher) claims a row, holds a lease while its
// external call is in flight, and finalizes under that lease. In-request,
// dynsecret.Engine.RunRevocations and secretsync.Engine.RunDeliveries drain the same
// rows through Queue.Pending/Queue.Done — holding no lease at all. So the queues owe
// three things:
//
//   - Pending must not hand the in-request drainer a row a dispatch worker is
//     currently performing, or the same provider revoke / secret push happens twice.
//   - Done must refuse to complete a leased row, and must NOT report success when it
//     refuses; a nil there retires an item whose effect is still in flight.
//   - A Done that really did complete the call must record the destination's circuit
//     success the way the spine's own finalizeClaim does.

// Low-entropy fixture UUID, matching the convention the rest of package server
// uses (11111111-…, 22222222-…). A random-looking UUID trips gosec G101 and
// would need a #nosec waiver for a value that is not a credential at all.
const secretOutboxCompletionTenant = "44444444-4444-4444-4444-444444444444"

func newSecretOutboxCompletionStore(t *testing.T) *store.Store {
	t.Helper()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(context.Background(), store.Tenant{
		TenantID: secretOutboxCompletionTenant, Name: "secret-outbox-completion",
	}); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	return st
}

func secretOutboxCompletionEpoch(t *testing.T, st *store.Store) string {
	t.Helper()
	epoch, err := st.DynamicSecretTenantEpoch(context.Background(), secretOutboxCompletionTenant)
	if err != nil {
		t.Fatalf("resolve dynamic-secret tenant epoch: %v", err)
	}
	return epoch
}

// secretOutboxRowState reads the durable row behind a secret-integration queue item.
func secretOutboxRowState(t *testing.T, st *store.Store, destination, key string) (status, workerID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var worker *string
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT status, worker_id FROM outbox
		  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		secretOutboxCompletionTenant, destination, key).Scan(&status, &worker); err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	if worker != nil {
		workerID = *worker
	}
	return status, workerID
}

func secretOutboxCircuitState(ob *orchestrator.Outbox, lane string) orchestrator.CircuitState {
	for _, snapshot := range ob.CircuitStates() {
		if snapshot.TenantID == secretOutboxCompletionTenant && snapshot.Destination == lane {
			return snapshot.State
		}
	}
	return ""
}

// countingRevokeProvider makes the external effect countable, so a revoke performed
// by both drainers is visible rather than merely suspected.
type countingRevokeProvider struct {
	name string
	mu   sync.Mutex
	refs []string
}

func (p *countingRevokeProvider) Name() string { return p.name }

func (p *countingRevokeProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("issuance is not exercised by this guard")
}

func (p *countingRevokeProvider) Revoke(_ context.Context, backendRef string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refs = append(p.refs, backendRef)
	return nil
}

func (p *countingRevokeProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.refs)
}

// parkedDispatch runs one Dispatch sweep whose handler claims a row and then holds
// its lease until the test releases it (or the context ends, so a t.Fatalf on the
// failure path cannot strand the worker). It returns the release func, a channel
// signalling the claim, the channel carrying Dispatch's result, and a live counter
// of handler invocations — the dispatcher-side external effect.
func parkedDispatch(ctx context.Context, t *testing.T, ob *orchestrator.Outbox) (release func(), claimed <-chan struct{}, dispatched <-chan error, calls func() int) {
	t.Helper()
	claimedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	dispatchedCh := make(chan error, 1)
	var once sync.Once
	releaseFn := func() { once.Do(func() { close(releaseCh) }) }
	t.Cleanup(releaseFn)

	var mu sync.Mutex
	handled := 0
	go func() {
		_, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(hctx context.Context, _ orchestrator.Message) error {
			mu.Lock()
			handled++
			first := handled == 1
			mu.Unlock()
			if first {
				close(claimedCh)
				select {
				case <-releaseCh:
				case <-hctx.Done():
					return hctx.Err()
				}
			}
			return nil
		}))
		dispatchedCh <- err
	}()
	return releaseFn, claimedCh, dispatchedCh, func() int {
		mu.Lock()
		defer mu.Unlock()
		return handled
	}
}

// TestDynamicSecretOutboxDoneRefusesToStealADispatchLease: the in-request drainer's
// completion must not flip a row a dispatch worker is holding, and must say so
// rather than returning nil.
func TestDynamicSecretOutboxDoneRefusesToStealADispatchLease(t *testing.T) {
	st := newSecretOutboxCompletionStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ob := orchestrator.NewOutbox(st, orchestrator.WithWorkerID("dispatch-worker-1"))
	queue := dynamicSecretOutboxQueue{store: st, outbox: ob, tenantID: secretOutboxCompletionTenant}
	item := dynsecret.RevokeItem{LeaseID: "lease-steal-1", Provider: "vault", BackendRef: "creds/steal-1"}
	if err := queue.Enqueue(ctx, item); err != nil {
		t.Fatalf("enqueue revocation intent: %v", err)
	}
	key := dynamicSecretRevokeKey(secretOutboxCompletionEpoch(t, st), item.LeaseID)

	release, claimed, dispatched, _ := parkedDispatch(ctx, t, ob)
	select {
	case <-claimed:
	case <-ctx.Done():
		t.Fatal("dispatch worker never claimed the revocation row")
	}

	err := queue.Done(ctx, item.LeaseID)
	if !errors.Is(err, orchestrator.ErrOutboxLeaseHeld) {
		t.Errorf("Done against a row a dispatch worker holds = %v, want orchestrator.ErrOutboxLeaseHeld: reporting success retires an item whose provider call is still in flight (AN-6)", err)
	}
	status, worker := secretOutboxRowState(t, st, dynamicSecretRevokeDestination, key)
	if status != "processing" || worker != "dispatch-worker-1" {
		t.Errorf("outbox row after a non-leaseholder Done = (%s, %q), want it still held as (processing, %q): the completion stole the dispatch lease, so two drainers can complete the same item (AN-6)",
			status, worker, "dispatch-worker-1")
	}

	release()
	if err := <-dispatched; err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if status, _ := secretOutboxRowState(t, st, dynamicSecretRevokeDestination, key); status != "delivered" {
		t.Fatalf("outbox row after the leaseholder finalized = %s, want delivered", status)
	}
}

// TestDynamicSecretRevocationRunsExactlyOnceWhileTheDispatcherHoldsTheLease is the
// ledger DoD's third clause: of the two competing drainers, exactly one performs the
// external revoke for a given item.
func TestDynamicSecretRevocationRunsExactlyOnceWhileTheDispatcherHoldsTheLease(t *testing.T) {
	st := newSecretOutboxCompletionStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ob := orchestrator.NewOutbox(st, orchestrator.WithWorkerID("dispatch-worker-4"))
	queue := dynamicSecretOutboxQueue{store: st, outbox: ob, tenantID: secretOutboxCompletionTenant}
	provider := &countingRevokeProvider{name: "vault"}
	engine, err := dynsecret.New(dynsecret.Config{
		TenantID: secretOutboxCompletionTenant, Providers: []dynsecret.Provider{provider}, Queue: queue,
	})
	if err != nil {
		t.Fatalf("dynsecret engine: %v", err)
	}
	item := dynsecret.RevokeItem{LeaseID: "lease-once-1", Provider: provider.name, BackendRef: "creds/once-1"}
	if err := queue.Enqueue(ctx, item); err != nil {
		t.Fatalf("enqueue revocation intent: %v", err)
	}
	key := dynamicSecretRevokeKey(secretOutboxCompletionEpoch(t, st), item.LeaseID)

	release, claimed, dispatched, dispatcherCalls := parkedDispatch(ctx, t, ob)
	select {
	case <-claimed:
	case <-ctx.Done():
		t.Fatal("dispatch worker never claimed the revocation row")
	}

	// The dispatcher is performing this revocation right now. The in-request drainer
	// must see nothing to do.
	done, err := engine.RunRevocations(ctx)
	if err != nil || done != 0 || provider.Calls() != 0 {
		t.Errorf("RunRevocations while the dispatcher holds the lease = (done=%d, err=%v) with %d provider revokes, want (0, nil) and 0: both drainers performed the same external effect (AN-6)",
			done, err, provider.Calls())
	}

	release()
	if err := <-dispatched; err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if status, _ := secretOutboxRowState(t, st, dynamicSecretRevokeDestination, key); status != "delivered" {
		t.Fatalf("outbox row after the leaseholder finalized = %s, want delivered", status)
	}
	if effects := dispatcherCalls() + provider.Calls(); effects != 1 {
		t.Fatalf("total external revokes for %s = %d (dispatcher=%d, in-request=%d), want exactly 1", item.LeaseID, effects, dispatcherCalls(), provider.Calls())
	}
}

// TestDynamicSecretOutboxDoneRecordsDestinationCircuitSuccess: a completion that did
// happen must close the destination lane's circuit, exactly as finalizeClaim does.
func TestDynamicSecretOutboxDoneRecordsDestinationCircuitSuccess(t *testing.T) {
	st := newSecretOutboxCompletionStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ob := orchestrator.NewOutbox(st,
		orchestrator.WithWorkerID("dispatch-worker-2"),
		orchestrator.WithCircuitBreaker(1, time.Minute))
	queue := dynamicSecretOutboxQueue{store: st, outbox: ob, tenantID: secretOutboxCompletionTenant}
	item := dynsecret.RevokeItem{LeaseID: "lease-circuit-1", Provider: "vault", BackendRef: "creds/circuit-1"}
	if err := queue.Enqueue(ctx, item); err != nil {
		t.Fatalf("enqueue revocation intent: %v", err)
	}
	lane := "dynsecret.provider:" + item.Provider

	// One failed delivery opens the lane's circuit.
	if _, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("provider unavailable")
	})); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if state := secretOutboxCircuitState(ob, lane); state != orchestrator.CircuitOpen {
		t.Fatalf("circuit for %s = %q, want open after a failed delivery", lane, state)
	}

	// The in-request drainer performed the same external call successfully. Its
	// completion must close the lane's circuit; otherwise the dispatcher keeps
	// backing off an endpoint that just answered.
	if err := queue.Done(ctx, item.LeaseID); err != nil {
		t.Fatalf("Done: %v", err)
	}
	if state := secretOutboxCircuitState(ob, lane); state != orchestrator.CircuitClosed {
		t.Errorf("circuit for %s = %q after a successful Done, want closed: the completion never recorded the destination's success (AN-6)", lane, state)
	}
	if status, _ := secretOutboxRowState(t, st, dynamicSecretRevokeDestination, dynamicSecretRevokeKey(secretOutboxCompletionEpoch(t, st), item.LeaseID)); status != "delivered" {
		t.Fatalf("outbox row after Done = %s, want delivered", status)
	}
}

// TestOutboxCompleteByKeyIsIdempotentAndRejectsAnIncompleteIdentity pins the
// sanctioned completion's own contract: replay is a no-op, and a partial identity
// can never complete an unrelated row.
func TestOutboxCompleteByKeyIsIdempotentAndRejectsAnIncompleteIdentity(t *testing.T) {
	st := newSecretOutboxCompletionStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ob := orchestrator.NewOutbox(st, orchestrator.WithWorkerID("dispatch-worker-3"))
	queue := dynamicSecretOutboxQueue{store: st, outbox: ob, tenantID: secretOutboxCompletionTenant}
	item := dynsecret.RevokeItem{LeaseID: "lease-replay-1", Provider: "vault", BackendRef: "creds/replay-1"}
	if err := queue.Enqueue(ctx, item); err != nil {
		t.Fatalf("enqueue revocation intent: %v", err)
	}
	key := dynamicSecretRevokeKey(secretOutboxCompletionEpoch(t, st), item.LeaseID)

	completed, err := ob.CompleteByKey(ctx, secretOutboxCompletionTenant, dynamicSecretRevokeDestination, key)
	if err != nil || !completed {
		t.Fatalf("first CompleteByKey = (%v, %v), want (true, nil)", completed, err)
	}
	completed, err = ob.CompleteByKey(ctx, secretOutboxCompletionTenant, dynamicSecretRevokeDestination, key)
	if err != nil || completed {
		t.Fatalf("replayed CompleteByKey = (%v, %v), want (false, nil)", completed, err)
	}
	if _, err := ob.CompleteByKey(ctx, secretOutboxCompletionTenant, "", key); err == nil {
		t.Fatal("CompleteByKey accepted an empty destination; an incomplete identity could complete an unrelated row")
	}
}
