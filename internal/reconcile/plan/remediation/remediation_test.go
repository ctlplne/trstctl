// SPDX-License-Identifier: BUSL-1.1

package remediation_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/reconcile/canon"
	xrecplan "trstctl.com/trstctl/internal/reconcile/plan"
	"trstctl.com/trstctl/internal/reconcile/plan/remediation"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-xrec-remediation-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(port).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p < 0 || p > math.MaxUint16 {
		panic(fmt.Sprintf("listener reported out-of-range tcp port %d", p))
	}
	return uint32(p)
}

func newStore(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	dbName := fmt.Sprintf("xrec_remediation_%d", time.Now().UTC().UnixNano())
	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		admin, err := pgx.Connect(context.Background(), testDSN)
		if err != nil {
			t.Logf("admin reconnect for cleanup: %v", err)
			return
		}
		defer func() { _ = admin.Close(context.Background()) }()
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()); err != nil {
			t.Logf("drop database %s: %v", dbName, err)
		}
	})

	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/" + dbName
	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(remediation.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(cs.Close)
	return cs
}

func newManager(t *testing.T, cs *corestore.Store, opts ...remediation.Option) *remediation.Manager {
	t.Helper()
	mgr, err := remediation.NewManager(cs, orchestrator.NewOutbox(cs,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
	), opts...)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return mgr
}

// TestRemediation_OutboxSameTxn proves the authorization ledger row and outbox
// row commit or roll back together.
// Authorization and corrective job share one transaction (XREC-claim-14).
func TestRemediation_OutboxSameTxn(t *testing.T) {
	cs := newStore(t)
	ctx := context.Background()
	boom := errors.New("rollback")
	mgr := newManager(t, cs, remediation.WithAfterEnqueue(func(context.Context) error { return boom }))

	req := authRequest(t, "same-txn")
	if _, err := mgr.Authorize(ctx, req); !errors.Is(err, boom) {
		t.Fatalf("Authorize rollback error = %v, want %v", err, boom)
	}
	if got := countTable(t, cs, tenantA, "xrec_remediation_authorizations"); got != 0 {
		t.Fatalf("authorizations after rollback = %d, want 0", got)
	}
	if got := countOutbox(t, cs, tenantA); got != 0 {
		t.Fatalf("outbox rows after rollback = %d, want 0", got)
	}

	mgr = newManager(t, cs)
	if rec, err := mgr.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize commit: %v", err)
	} else if !rec.Inserted || !rec.OutboxInserted {
		t.Fatalf("Authorize inserted=(%v,%v), want both true", rec.Inserted, rec.OutboxInserted)
	}
	if got := countTable(t, cs, tenantA, "xrec_remediation_authorizations"); got != 1 {
		t.Fatalf("authorizations after commit = %d, want 1", got)
	}
	if got := countOutbox(t, cs, tenantA); got != 1 {
		t.Fatalf("outbox rows after commit = %d, want 1", got)
	}
}

// TestRemediation_IdempotentOnWitnessKey proves the same
// (witness_hash, record_key, operation) tuple is recorded and enqueued once.
// Idempotency keyed on the witness digest (XREC-claim-14).
func TestRemediation_IdempotentOnWitnessKey(t *testing.T) {
	cs := newStore(t)
	ctx := context.Background()
	mgr := newManager(t, cs)

	req := authRequest(t, "idempotent")
	first, err := mgr.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize first: %v", err)
	}
	second, err := mgr.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize second: %v", err)
	}
	if !first.Inserted || !first.OutboxInserted {
		t.Fatalf("first insert flags = (%v,%v), want both true", first.Inserted, first.OutboxInserted)
	}
	if second.Inserted || second.OutboxInserted {
		t.Fatalf("second insert flags = (%v,%v), want both false", second.Inserted, second.OutboxInserted)
	}
	if first.IdempotencyKey != second.IdempotencyKey {
		t.Fatalf("idempotency key changed: %q != %q", first.IdempotencyKey, second.IdempotencyKey)
	}
	if got := countTable(t, cs, tenantA, "xrec_remediation_authorizations"); got != 1 {
		t.Fatalf("authorizations = %d, want 1", got)
	}
	if got := countOutbox(t, cs, tenantA); got != 1 {
		t.Fatalf("outbox rows = %d, want 1", got)
	}
}

// TestJobs_CrashRestartNoDoubleExecute simulates a process dying after durable
// enqueue and before dispatch. A fresh dispatcher drains the pending row once;
// subsequent restarts see it delivered and do not execute it again.
func TestJobs_CrashRestartNoDoubleExecute(t *testing.T) {
	cs := newStore(t)
	ctx := context.Background()
	mgr := newManager(t, cs)
	if _, err := mgr.Authorize(ctx, authRequest(t, "restart")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	executed := 0
	var seenKey string
	handler := remediation.NewHandler(remediation.ExecutorFunc(func(_ context.Context, job remediation.Job) error {
		executed++
		seenKey = job.IdempotencyKey
		return nil
	}))

	restarted := orchestrator.NewOutbox(cs,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithWorkerID("restart-1"),
	)
	if n, err := restarted.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("first restart dispatch = (%d,%v), want (1,nil)", n, err)
	}
	if executed != 1 || seenKey == "" {
		t.Fatalf("executed=%d seenKey=%q, want one execution with idempotency key", executed, seenKey)
	}

	restartedAgain := orchestrator.NewOutbox(cs,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
		orchestrator.WithWorkerID("restart-2"),
	)
	if n, err := restartedAgain.Dispatch(ctx, handler); err != nil || n != 0 {
		t.Fatalf("second restart dispatch = (%d,%v), want (0,nil)", n, err)
	}
	if executed != 1 {
		t.Fatalf("executed after second restart = %d, want 1", executed)
	}
}

func authRequest(t *testing.T, suffix string) remediation.AuthorizationRequest {
	t.Helper()
	action := xrecplan.Action{
		AuthorityID: "vault-prod",
		RecordKey: canon.RecordKey{
			TenantID:   tenantA,
			RecordType: canon.RecordTypeKey,
			StableID:   "key-ed25519-prod-" + suffix,
		},
		Operation: "rotate-key",
	}
	plan := xrecplan.Plan{
		PlanID:      "plan-" + suffix,
		TenantID:    tenantA,
		WitnessID:   "witness-" + suffix,
		WitnessHash: []byte("0123456789abcdef0123456789abcdef-" + suffix),
		Actions:     []xrecplan.Action{action},
		GeneratedAt: time.Unix(1_700_000_000, 0).UTC().Unix(),
	}
	hash, err := plan.Hash()
	if err != nil {
		t.Fatalf("plan hash: %v", err)
	}
	return remediation.AuthorizationRequest{
		TenantID: tenantA,
		SignedPlan: xrecplan.SignedPlan{
			Plan:     plan,
			PlanHash: hash,
		},
		Action: action,
		Decision: signing.OperationDecision{
			Approved:      true,
			Authorization: []byte(`{"approved":true}`),
		},
	}
}

func countTable(t *testing.T, cs *corestore.Store, tenantID, table string) int {
	t.Helper()
	var count int
	if err := cs.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			"SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid").Scan(&count)
	}); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func countOutbox(t *testing.T, cs *corestore.Store, tenantID string) int {
	t.Helper()
	var count int
	if err := cs.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT count(*)
			   FROM outbox
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND destination = $1`, remediation.OutboxDestination).Scan(&count)
	}); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return count
}
