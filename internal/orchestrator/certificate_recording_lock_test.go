// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// These new-helper tests are after002-only source. They are deliberately not
// included in the independently compilable blocker-tests-against-001 patch.
func TestCertificateRecordingExclusiveReplayDoesNotAccumulateFingerprintLocks(t *testing.T) {
	s, _, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanupCtx)
	}()
	if err := s.SetTenantGUCTx(ctx, tx, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE certificates IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		//trstctl:system-query — this owned fixture backend's advisory-lock count only (AN-1 exemption).
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for i := range 64 {
		if err := s.LockCertificateRecordingTx(ctx, tx, tenantA, fmt.Sprintf("%064x", i)); err != nil {
			t.Fatal(err)
		}
	}
	if after := count(); after != before {
		t.Fatalf("exclusive replay retained %d extra fingerprint locks", after-before)
	}
	if err := s.LockCertificateRecordingTx(ctx, tx, tenantB, "wrong-tenant"); err == nil {
		t.Fatal("exclusive table ownership bypassed tenant context")
	}
}

func TestCertificateRecordingWaitsForRebuildTableBeforeFingerprint(t *testing.T) {
	s, log, _ := recordingSpine(t)
	in, _ := recordingCertificates(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	peer, err := store.Open(ctx, testDSN+"?application_name=first_leaf_relation_order_peer")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanupCtx)
	}()
	if _, err := tx.Exec(ctx, `LOCK TABLE certificates IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		_, err := orchestrator.NewOrchestrator(log, peer, nil).RecordCertificate(ctx, tenantA, in)
		completed <- err
	}()
	waiting := false
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		select {
		case err := <-completed:
			t.Fatalf("writer crossed exclusive rebuild table lock: %v", err)
		default:
		}
		//trstctl:system-query — exact owned connection's lock wait, no tenant rows or statement text (AN-1 exemption).
		if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name='first_leaf_relation_order_peer' AND wait_event_type='Lock' AND wait_event='relation')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("writer did not reach actual PostgreSQL relation wait")
	}
	var available bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "certificate-recording\x1f"+tenantA+"\x1f"+in.Fingerprint).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("writer holds fingerprint while waiting on rebuild table: inverted lock order")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
