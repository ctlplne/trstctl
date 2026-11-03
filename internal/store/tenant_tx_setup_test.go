// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// setupTracer records every statement and batch the store sends, in order,
// and apart from them the statements inside each batch.
type setupTracer struct {
	mu      sync.Mutex
	sent    []string
	batched []string
}

func (r *setupTracer) record(sql string) {
	r.mu.Lock()
	r.sent = append(r.sent, sql)
	r.mu.Unlock()
}

func (r *setupTracer) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

func (r *setupTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	r.record(d.SQL)
	return ctx
}
func (r *setupTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (r *setupTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	r.record("[batch]")
	return ctx
}
func (r *setupTracer) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	r.mu.Lock()
	r.batched = append(r.batched, d.SQL)
	r.mu.Unlock()
}

// takeBatched returns the statements sent inside batches since the last call.
func (r *setupTracer) takeBatched() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.batched
	r.batched = nil
	return out
}
func (r *setupTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

// A tenant transaction's setup — BEGIN, the shared backup write fence, the RLS
// role and the tenant GUC — is one round trip, in that order, and in force
// before the first tenant statement. It used to be three: BEGIN, a batch of
// the fence and the role, then the tenant.
func TestTenantTransactionSetupIsOneRoundTripInOrder(t *testing.T) {
	_ = newStore(t) // migrated, isolated tables
	tracer := &setupTracer{}
	s, err := store.Open(context.Background(), testDSN, store.WithQueryTracer(tracer))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tracer.take()

	var role, tenant string
	var fenced bool
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT current_user, current_setting('trstctl.tenant_id'),
			EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND mode = 'ShareLock' AND granted)`).
			Scan(&role, &tenant, &fenced)
	}); err != nil {
		t.Fatal(err)
	}
	if role != "trstctl_app" || tenant != tenantA || !fenced {
		t.Fatalf("the first tenant statement saw role %q, tenant %q, fence held %v", role, tenant, fenced)
	}
	if held := s.SystemPool().Stat().AcquiredConns(); held != 0 {
		t.Fatalf("%d connections are still checked out after the tenant transaction ended", held)
	}
	sent := tracer.take()
	if len(sent) != 3 || !strings.HasPrefix(sent[1], "SELECT current_user") || sent[2] != "commit" {
		t.Fatalf("tenant transaction sent %d messages %q; want setup, the tenant statement, commit", len(sent), sent)
	}
	setup := sent[0]
	at := -1
	for _, want := range []string{"BEGIN", "pg_advisory_xact_lock_shared(", "SET LOCAL ROLE trstctl_app", "set_config('trstctl.tenant_id', '" + tenantA + "', true)"} {
		i := strings.Index(setup, want)
		if i <= at {
			t.Fatalf("setup %q lacks %q after what precedes it", setup, want)
		}
		at = i
	}
}

// A failure anywhere in the setup rolls the transaction back before any tenant
// statement runs: a statement error (the fence lock past the statement
// timeout) and a canceled context both leave the callback unrun and no
// session holding the transaction open.
func TestTenantTransactionSetupFailureRunsNoTenantStatement(t *testing.T) {
	base := newStore(t)
	holder, err := base.SystemPool().Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if _, err := holder.Exec(t.Context(), "SELECT pg_advisory_lock($1)", store.BackupWriteFenceAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = holder.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", store.BackupWriteFenceAdvisoryLockKey)
	}()

	tracer := &setupTracer{}
	timed, err := store.Open(context.Background(), testDSN, store.WithQueryTracer(tracer), store.WithStatementTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer timed.Close()
	tracer.take()
	ran := false
	err = timed.WithTenant(t.Context(), tenantA, func(pgx.Tx) error { ran = true; return nil })
	if err == nil || ran {
		t.Fatalf("setup past the statement timeout: err %v, callback ran %v", err, ran)
	}
	if sent := tracer.take(); len(sent) != 1 || !strings.HasPrefix(sent[0], "BEGIN;") {
		t.Fatalf("after a failed setup the store sent %q; want only the setup", sent)
	}

	short, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err = timed.WithTenant(short, tenantA, func(pgx.Tx) error { ran = true; return nil })
	if err == nil || ran {
		t.Fatalf("setup under a canceled context: err %v, callback ran %v", err, ran)
	}
	if sent := tracer.take(); len(sent) != 1 || !strings.HasPrefix(sent[0], "BEGIN;") {
		t.Fatalf("after a canceled setup the store sent %q; want only the setup", sent)
	}

	// Neither left a session inside a transaction.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var open int
		if err := base.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND pid <> $1 AND state LIKE 'idle in transaction%'`,
			holder.Conn().PgConn().PID()).Scan(&open); err != nil {
			t.Fatal(err)
		}
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions are still inside a transaction after the failed setups", open)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
