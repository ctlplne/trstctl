// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestCodeSigningOperationsUseProductTenantGUC(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var outboxB int64
	if err := s.SystemPool().QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1,'codesign.command','{}','codesign-b') RETURNING id`, tenantB).Scan(&outboxB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO code_signing_operations
		 (tenant_id,operation_id,idempotency_key,mode,request_hash,sealed_command,
		  status,cleanup_status,command_outbox_id,created_at,updated_at)
		 VALUES ($1,'op-b','idem-b','key','hash-b',$2,'queued','not_required',$3,now(),now())`,
		tenantB, []byte("ciphertext-b"), outboxB); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1`, tenantB).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("tenant A saw %d tenant-B code-signing rows", visible)
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO code_signing_operations
			 (tenant_id,operation_id,idempotency_key,mode,request_hash,sealed_command,
			  status,cleanup_status,command_outbox_id,created_at,updated_at)
			 VALUES ($1,'cross-op','cross-idem','key','cross-hash',$2,'queued','not_required',$3,now(),now())`,
			tenantB, []byte("cross-ciphertext"), outboxB)
		return err
	}); err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant code_signing_operations insert = %v, want RLS denial", err)
	}
}

func TestCodeSigningIntentConcurrentProjectionCreatesOneCommand(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	op := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: "codesign-concurrent-projection",
		IdempotencyKey: "codesign-concurrent-idem", Mode: "key",
		RequestHash: "request-hash", SealedCommand: []byte("sealed-command"),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyCodeSigningIntentTx(ctx, tx, op,
					[]byte(`{"operation_id":"codesign-concurrent-projection"}`))
			})
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent code-signing projection: %v", err)
		}
	}
	var outboxRows, operationRows int
	var effectLane string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1 AND operation_id = $2`,
		tenantA, op.OperationID).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if outboxRows != 1 || operationRows != 1 {
		t.Fatalf("concurrent fold persisted outbox/operation rows = %d/%d, want 1/1", outboxRows, operationRows)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&effectLane); err != nil {
		t.Fatal(err)
	}
	if effectLane != "codesign.command:"+op.OperationID {
		t.Fatalf("code-signing command effect lane = %q", effectLane)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET effect_lane = '' WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, op,
			[]byte(`{"operation_id":"codesign-concurrent-projection"}`))
	}); err != nil {
		t.Fatalf("replay code-signing intent with legacy empty lane: %v", err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&effectLane); err != nil {
		t.Fatal(err)
	}
	if effectLane != "codesign.command:"+op.OperationID {
		t.Fatalf("replayed code-signing command did not heal empty effect lane: %q", effectLane)
	}
}
