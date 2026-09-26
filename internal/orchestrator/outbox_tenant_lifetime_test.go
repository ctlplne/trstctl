// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestOutboxDoesNotDeliverClaimErasedBeforeServiceAdmission(t *testing.T) {
	second := newStore(t)
	mustRegisterTenant(t, second, tenantA)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	first, err := store.Open(ctx, testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Occupy the one service-session slot on replica one. Claiming still uses
	// short ordinary transactions, so it can finish before admission begins.
	_, release, err := first.BeginTenantService(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ob := orchestrator.NewOutbox(first)
	id := enqueue(t, first, ob, orchestrator.Entry{TenantID: tenantA, Destination: "late-claim.probe", IdempotencyKey: "before-erase", Payload: []byte(`{}`)})
	var calls atomic.Int32
	finished := make(chan error, 1)
	go func() {
		_, err := ob.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { calls.Add(1); return nil }), orchestrator.DestinationScope{IncludePrefixes: []string{"late-claim.probe"}})
		finished <- err
	}()
	joined := false
	defer func() {
		release()
		if !joined {
			<-finished
		}
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var claimed bool
		if err := second.SystemPool().QueryRow(ctx, `SELECT status='processing' FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, id).Scan(&claimed); err != nil {
			t.Fatal(err)
		}
		if claimed {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Replica two can now erase the customer under its exclusive service fence:
	// the old claim exists, but it has not admitted or started any remote work.
	if err := second.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		_, err := second.OffboardTenant(fenced, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	release()
	err = <-finished
	joined = true
	if calls.Load() != 0 {
		t.Fatalf("erased claim still reached receiver %d times (finalization error=%v)", calls.Load(), err)
	}
	if err == nil {
		t.Fatal("lost claim was reported as delivered")
	}
}
