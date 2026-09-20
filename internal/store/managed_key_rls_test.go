// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestManagedKeyTablesUseProductTenantGUC proves both managed-key policies run
// under Store.WithTenant's non-superuser app role and exact
// trstctl.tenant_id GUC. It also proves cross-tenant reads are invisible and
// WITH CHECK rejects cross-tenant writes.
func TestManagedKeyTablesUseProductTenantGUC(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	var outboxA, outboxB int64
	if err := s.SystemPool().QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1,'managedkey.command','{}','managed-a') RETURNING id`, tenantA).Scan(&outboxA); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1,'managedkey.command','{}','managed-b') RETURNING id`, tenantB).Scan(&outboxB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO managed_keys
		 (tenant_id,provider,key_id,algorithm,version,state,public_der,created_at,updated_at)
		 VALUES ($1,'aws-kms','key-b','rsa-2048',1,'active',$2,now(),now())`,
		tenantB, []byte("tenant-b-public-key")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO managed_key_operations
		 (tenant_id,operation_id,provider,action,key_id,algorithm,status,outbox_id,created_at,updated_at)
		 VALUES ($1,'op-b','aws-kms','generate','','rsa-2048','queued',$2,now(),now())`,
		tenantB, outboxB); err != nil {
		t.Fatal(err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO managed_keys
			 (tenant_id,provider,key_id,algorithm,version,state,public_der,created_at,updated_at)
			 VALUES ($1,'aws-kms','key-a','rsa-2048',1,'active',$2,now(),now())`,
			tenantA, []byte("tenant-a-public-key")); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO managed_key_operations
			 (tenant_id,operation_id,provider,action,key_id,algorithm,status,outbox_id,created_at,updated_at)
			 VALUES ($1,'op-a','aws-kms','generate','','rsa-2048','queued',$2,now(),now())`,
			tenantA, outboxA); err != nil {
			return err
		}
		var visibleKeys int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM managed_keys WHERE tenant_id = $1`, tenantB).Scan(&visibleKeys); err != nil {
			return err
		}
		if visibleKeys != 0 {
			t.Fatalf("tenant A saw %d tenant-B managed-key rows", visibleKeys)
		}
		var visibleOperations int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM managed_key_operations WHERE tenant_id = $1`, tenantB).Scan(&visibleOperations); err != nil {
			return err
		}
		if visibleOperations != 0 {
			t.Fatalf("tenant A saw %d tenant-B managed-key operation rows", visibleOperations)
		}
		return nil
	}); err != nil {
		t.Fatalf("tenant A own managed-key writes: %v", err)
	}

	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO managed_keys
			 (tenant_id,provider,key_id,algorithm,version,state,public_der,created_at,updated_at)
			 VALUES ($1,'aws-kms','cross-key','rsa-2048',1,'active',$2,now(),now())`,
			tenantB, []byte("cross-tenant-public-key"))
		return err
	})
	if err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant managed_keys insert = %v, want RLS denial", err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO managed_key_operations
			 (tenant_id,operation_id,provider,action,key_id,algorithm,status,outbox_id,created_at,updated_at)
			 VALUES ($1,'cross-op','aws-kms','generate','','rsa-2048','queued',$2,now(),now())`,
			tenantB, outboxB)
		return err
	})
	if err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant managed_key_operations insert = %v, want RLS denial", err)
	}
}

func TestManagedKeyIntentPersistsBindingAndRejectsStaleOutboxIdentity(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: tenantA}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original := store.ManagedKeyOperation{
		TenantID: tenantA, OperationID: "managedkey:bound-operation", Provider: "aws-kms",
		Action: "generate", Algorithm: "RSA-2048", RequestBinding: "sha256:caller-a-generate-rsa",
		CreatedAt: now, UpdatedAt: now,
	}
	originalCommand := projections.ManagedKeyCommand{
		OperationID: original.OperationID, Provider: original.Provider, Action: original.Action,
		Algorithm: original.Algorithm, RequestBinding: original.RequestBinding,
	}
	originalPayload, err := json.Marshal(originalCommand)
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, events.Event{
		ID: "managed-key-binding-event-a", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: now, SchemaVersion: 1, Data: originalPayload,
	}); err != nil {
		t.Fatalf("project original managed-key intent: %v", err)
	}
	stored, err := s.GetManagedKeyOperation(ctx, tenantA, original.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RequestBinding != original.RequestBinding {
		t.Fatalf("operation request binding=%q, want %q", stored.RequestBinding, original.RequestBinding)
	}
	var (
		destination string
		effectLane  string
		payload     []byte
	)
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT destination, effect_lane, payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, original.OperationID).Scan(&destination, &effectLane, &payload); err != nil {
		t.Fatal(err)
	}
	if want := store.ManagedKeyEffectLane(original.Provider, original.KeyID, original.OperationID); destination != "managedkey.command" || effectLane != want || string(payload) != string(originalPayload) {
		t.Fatalf("outbox identity destination=%q lane=%q payload=%s, want exact managed-key command lane %q", destination, effectLane, payload, want)
	}

	driftedCommand := originalCommand
	driftedCommand.RequestBinding = "sha256:caller-b-generate-rsa"
	driftedPayload, err := json.Marshal(driftedCommand)
	if err != nil {
		t.Fatal(err)
	}
	err = projections.New(s).Apply(ctx, events.Event{
		ID: "managed-key-binding-event-b", Type: projections.EventManagedKeyCommandRequested,
		TenantID: tenantA, Time: now.Add(time.Second), SchemaVersion: 1, Data: driftedPayload,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("changed binding projection error=%v, want pgx.ErrNoRows conflict", err)
	}
	stored, err = s.GetManagedKeyOperation(ctx, tenantA, original.OperationID)
	if err != nil || stored.RequestBinding != original.RequestBinding {
		t.Fatalf("changed binding replaced operation: binding=%q err=%v", stored.RequestBinding, err)
	}
	var outboxRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, original.OperationID).Scan(&outboxRows); err != nil || outboxRows != 1 {
		t.Fatalf("changed binding outbox rows=%d err=%v, want original one only", outboxRows, err)
	}

	const foreignOperation = "managedkey:foreign-outbox"
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1, 'webhook', $2, $3)`, tenantA, []byte(`{"foreign":true}`), foreignOperation); err != nil {
		t.Fatal(err)
	}
	foreign := original
	foreign.OperationID = foreignOperation
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyManagedKeyIntentTx(ctx, tx, foreign, []byte(`{"operation_id":"managedkey:foreign-outbox"}`))
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign outbox reuse error=%v, want pgx.ErrNoRows conflict", err)
	}
}

// TestManagedKeyIntentConcurrentProjectionCreatesOneOutbox reproduces the
// request-projector versus tail-projector race. Both may fold the same event,
// but only one external provider command may become durable (AN-5/AN-6).
func TestManagedKeyIntentConcurrentProjectionCreatesOneOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: tenantA}); err != nil {
		t.Fatal(err)
	}
	op := store.ManagedKeyOperation{
		TenantID: tenantA, OperationID: "managedkey:concurrent-projection",
		Provider: "aws-kms", Action: "generate", Algorithm: "rsa-2048", RequestBinding: "sha256:concurrent-command-binding",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	const workers = 8
	start := make(chan struct{})
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsFound <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyManagedKeyIntentTx(ctx, tx, op, []byte(`{"operation_id":"managedkey:concurrent-projection","request_binding":"sha256:concurrent-command-binding"}`))
			})
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent projection: %v", err)
		}
	}
	var outboxRows, operationRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, op.OperationID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM managed_key_operations WHERE tenant_id = $1 AND operation_id = $2`,
		tenantA, op.OperationID).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if outboxRows != 1 || operationRows != 1 {
		t.Fatalf("concurrent fold persisted outbox/operation rows = %d/%d, want 1/1", outboxRows, operationRows)
	}
}

func TestManagedKeyIntentReplayHealsOnlyEmptyEffectLane(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: tenantA}); err != nil {
		t.Fatal(err)
	}
	op := store.ManagedKeyOperation{
		TenantID: tenantA, OperationID: "managedkey:lane-replay", Provider: "aws-kms",
		Action: "rotate", KeyID: "provider-key-current", Algorithm: "rsa-2048",
		RequestBinding: "sha256:lane-replay-binding", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	payload := []byte(`{"operation_id":"managedkey:lane-replay","provider":"aws-kms","action":"rotate","key_id":"provider-key-current","algorithm":"rsa-2048","request_binding":"sha256:lane-replay-binding"}`)
	apply := func() error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyManagedKeyIntentTx(ctx, tx, op, payload)
		})
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	want := store.ManagedKeyEffectLane(op.Provider, op.KeyID, op.OperationID)
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET effect_lane = '' WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("replay legacy empty lane: %v", err)
	}
	var got string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, op.OperationID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("healed managed-key lane=%q, want %q", got, want)
	}
	const foreignLane = "managedkey.command:aws-kms:foreign-key"
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, op.OperationID, foreignLane); err != nil {
		t.Fatal(err)
	}
	if err := apply(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("replay nonempty foreign lane error=%v, want conflict", err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, op.OperationID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != foreignLane {
		t.Fatalf("conflicting replay overwrote foreign lane=%q", got)
	}
}
