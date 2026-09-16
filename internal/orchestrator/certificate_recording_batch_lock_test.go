// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Count driver dispatches while executing every statement against PostgreSQL.
// Scope must be checked before batching; lock ordering and ownership are covered
// by the concurrent writer/rebuild tests in certificate_recording_lock_test.go.
func TestCertificateRecordingLockBatchesAfterTenantValidation(t *testing.T) {
	s, _, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		measured := &recordingLockDispatchTx{recoveryWorkTx: recoveryWorkTx{Tx: tx}}
		if err := s.LockCertificateRecordingTx(ctx, measured, tenantA, "bounded-lock-dispatch"); err != nil {
			return err
		}
		if measured.calls+measured.batches > 2 {
			t.Errorf("recording lock used %d individual calls and %d batches; want at most two driver dispatches", measured.calls, measured.batches)
		}
		// The batch must be drained, leaving this transaction usable.
		var scoped bool
		if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id',true)::uuid=$1::uuid`, tenantA).Scan(&scoped); err != nil || !scoped {
			t.Fatalf("transaction unusable after recording lock: scoped=%t err=%v", scoped, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		measured := &recordingLockDispatchTx{recoveryWorkTx: recoveryWorkTx{Tx: tx}}
		if err := s.LockCertificateRecordingTx(ctx, measured, tenantB, "wrong-tenant"); err == nil {
			t.Fatal("another tenant reached recording locks")
		}
		if measured.calls != 1 || measured.batches != 0 {
			t.Fatalf("tenant refusal dispatched locking work: calls=%d batches=%d", measured.calls, measured.batches)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type recordingLockDispatchTx struct {
	recoveryWorkTx
	batches uint64
}

func (tx *recordingLockDispatchTx) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	tx.batches++
	return tx.Tx.SendBatch(ctx, batch)
}
