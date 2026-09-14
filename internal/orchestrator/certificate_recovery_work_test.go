// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A completed historical event needs its exact receipt checked, not repeated
// projection setup. Count actual driver calls instead of imposing a flaky wall
// clock limit. The budget allows two round trips per added retained event and
// leaves implementations free to batch those reads or use a verified index.
func TestCertificateRecoveryCompletedHistoryHasBoundedDatabaseWork(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	certificate, _ := recordingCertificates(t)
	certificate.Source, certificate.IssuanceIdempotencyKey = "import", ""
	certificate.CertificateDER, certificate.CertificatePEM = nil, nil
	certificate.KeyOrigin = ""
	appendImport := func(i int) {
		t.Helper()
		certificate.Fingerprint = fmt.Sprintf("%064x", i)
		if _, err := o.RecordCertificate(ctx, tenantA, certificate); err != nil {
			t.Fatal(err)
		}
	}
	measure := func() (uint64, uint64) {
		t.Helper()
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state := certificateOrderState(t, ctx, s, certificate.Fingerprint)
		var calls uint64
		err = s.WithPrivacyRecoveryBarrier(ctx, tenantA, "completed history work budget", func(readCtx context.Context) error {
			return s.WithTenant(readCtx, tenantA, func(tx pgx.Tx) error {
				const absent = "unrecorded-next-certificate"
				if err := s.LockCertificateRecordingTx(readCtx, tx, tenantA, absent); err != nil {
					return err
				}
				measured := &recoveryWorkTx{Tx: tx}
				err := orchestrator.RecoverCertificateHistoryForTest(o, readCtx, measured, tenantA, absent)
				calls = measured.calls
				return err
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		after, err := log.LastSequence(ctx)
		if err != nil || after != before || !bytes.Equal(state, certificateOrderState(t, ctx, s, certificate.Fingerprint)) {
			t.Fatalf("completed recovery changed history or certificate state: %v", err)
		}
		return calls, before
	}
	appendImport(1)
	smallCalls, smallHead := measure()
	for i := 2; i <= 33; i++ {
		appendImport(i)
	}
	largeCalls, largeHead := measure()
	if growth := largeCalls - smallCalls; largeCalls < smallCalls || growth > 2*(largeHead-smallHead) {
		t.Fatalf("completed history added %d SQL calls for %d retained events; want at most two per event (small=%d large=%d)", growth, largeHead-smallHead, smallCalls, largeCalls)
	}

	// An existing row is not proof by itself. A corrupted envelope digest must
	// refuse the next append, including when every historical event was applied.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts SET event_digest=repeat('0',64) WHERE tenant_id=$1`, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	certificate.Fingerprint = fmt.Sprintf("%064x", 34)
	if _, err := o.RecordCertificate(ctx, tenantA, certificate); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("completed history accepted a mismatched receipt: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != largeHead {
		t.Fatalf("receipt refusal appended a new event: %d %v", after, err)
	}
}

// Delegate every operation to real PostgreSQL; only count the round trips.
type recoveryWorkTx struct {
	pgx.Tx
	calls uint64
}

func (t *recoveryWorkTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	t.calls++
	return t.Tx.Exec(ctx, sql, args...)
}

func (t *recoveryWorkTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	t.calls++
	return t.Tx.Query(ctx, sql, args...)
}

func (t *recoveryWorkTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	t.calls++
	return t.Tx.QueryRow(ctx, sql, args...)
}
