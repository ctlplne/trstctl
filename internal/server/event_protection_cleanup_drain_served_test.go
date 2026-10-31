// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type blockedEventKeyCleanupCustody struct {
	*eventprotect.FileAuthority
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockedEventKeyCleanupCustody) WithCustodyFence(ctx context.Context, ref eventprotect.KeyRef, visit func(context.Context) error) error {
	return b.FileAuthority.WithCustodyFence(ctx, ref, func(fenced context.Context) error {
		b.once.Do(func() { close(b.entered) })
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return visit(fenced)
	})
}
func TestEventProtectionDrainWaitsForPriorPooledCleanup(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, custody, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "3de09948-41c9-4b3f-9c72-21c328eb44ca"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"drain fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, custody.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: custody})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	life, err := custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation == nil {
		t.Fatalf("drain stranded preparation: %v", err)
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}

	blocker := &blockedEventKeyCleanupCustody{FileAuthority: custody.custody, entered: make(chan struct{}), release: make(chan struct{})}
	srv.eventKeyDelivery.cleanup.Custody = blocker
	var family outboxDispatchFamily
	for _, candidate := range outboxDispatchFamilies {
		if candidate.eventKeyKind == 2 {
			family = candidate
			break
		}
	}
	if family.eventKeyKind != 2 {
		t.Fatal("no exact destruction family")
	}
	workCtx, cancelWork := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancelWork()
	pooledDone := make(chan struct{})
	var pooledErr error
	pool := srv.bulk.Pool(bulkhead.SubsystemOutboxEventKeyDestruction)
	if err := pool.Submit(func() { _, pooledErr = srv.dispatchOutboxFamily(workCtx, family); close(pooledDone) }); err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	defer func() { release(); cancelWork(); <-pooledDone }()
	select {
	case <-blocker.entered:
	case <-workCtx.Done():
		t.Fatal("pooled cleanup did not reach current custody")
	}
	life, err = custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Completion == nil {
		t.Fatalf("blocked cleanup has no retained completion: %v", err)
	}
	originalReceipt := life.Completion.JWS
	headBefore, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	drainCtx, cancelDrain := context.WithTimeout(t.Context(), 4*time.Second)
	drainDone := make(chan struct{})
	var drainErr error
	go func() { drainErr = srv.Drain(drainCtx); close(drainDone) }()
	defer func() { release(); cancelDrain(); <-drainDone }()
	select {
	case <-drainDone:
		t.Fatalf("drain returned while prior pooled cleanup still held custody: %v", drainErr)
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case <-pooledDone:
	case <-workCtx.Done():
		t.Fatal("released cleanup did not finish")
	}
	if pooledErr != nil {
		t.Fatal(pooledErr)
	}
	select {
	case <-drainDone:
	case <-drainCtx.Done():
		t.Fatal("drain did not complete after verified cleanup")
	}
	if drainErr != nil {
		t.Fatal(drainErr)
	}
	receipt, erased, err := custody.custody.DestructionReceipt(t.Context(), eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID})
	if err != nil || !erased || receipt != originalReceipt {
		t.Fatalf("drain changed original completed removal: %v", err)
	}
	headAfter, err := log.LastSequence(t.Context())
	if err != nil || headAfter != headBefore {
		t.Fatal("cleanup appended a new source result")
	}
	if !eventKeyDestructionIntentAbsent(t, st, tenant, store.EventKeyDestructionOutboxKey(life.Completion.Claims.Request.OperationID)) {
		t.Fatal("drain returned before exact intent removal")
	}
	eventKeyAssertNoTenantSQLResidue(t, st, tenant)
}
