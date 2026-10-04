// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDiscardAmbiguousHistoryLockSessionReleasesGrantedPostgresLock(t *testing.T) {
	ctx := t.Context()
	dsn := os.Getenv("TRSTCTL_STORE_TEST_DSN")
	if dsn == "" {
		t.Fatal("real PostgreSQL fixture DSN was not provided by TestMain")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	peer, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, HistoryRewriteOperationAdvisoryLockKey); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	// Model the response-lost case: PostgreSQL granted the lock, while the
	// caller knows only that acquisition failed. The session must be destroyed.
	if err := discardHistoryRewriteSession(conn); err != nil {
		t.Fatal(err)
	}
	peerConn, err := peer.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Release()
	var acquired bool
	if err := peerConn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, HistoryRewriteOperationAdvisoryLockKey).Scan(&acquired); err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("ambiguous acquisition retained the deployment-wide history lock")
	}
	var released bool
	if err := peerConn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, HistoryRewriteOperationAdvisoryLockKey).Scan(&released); err != nil {
		t.Fatal(err)
	}
	if !released {
		t.Fatal("peer session did not release its test lock")
	}
}
