package orchestrator_test

// In-package integration harness for internal/orchestrator (SPINE-012). The
// orchestrator is the most sensitive spine package — idempotency (AN-5), the
// outbox (AN-6), the append-then-project crash window (SPINE-011), and the
// backoff/dead-letter arithmetic — yet it had zero co-located tests; its behavior
// was exercised only from package projections_test. These tests run against the
// same real embedded PostgreSQL + in-process NATS the rest of the spine uses
// (never mocks), so they are white-box where it matters (claim/skip-locked, the
// crash gap) while staying faithful to production wiring.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// tenantRegisteredJSON builds a tenant.registered payload (the projector decodes
// {"name": ...}).
func tenantRegisteredJSON(name string) []byte {
	b, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{name})
	return b
}

// ownerCreatedJSON builds an owner.created payload matching projections.OwnerCreated.
func ownerCreatedJSON(id, name string) []byte {
	b, _ := json.Marshal(map[string]string{
		"id": id, "kind": "team", "name": name, "email": name + "@example.test",
	})
	return b
}

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real PostgreSQL (downloaded once, cached) for the whole
// package; the orchestrator is integration-tested against it, never mocked. The
// embedded-postgres version + binaries path mirror the projections package so the
// supply-chain-pinned binary is reused (deploy/supply-chain/embedded-postgres.json).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-orch-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin"). // per-package, not a shared /tmp dir: parallel `go test ./...` packages race the file-by-file extraction into a shared BinariesPath
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

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// The package shares one database; reset the spine tables between tests.
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE tenants, idempotency_keys, outbox,
		          owners, issuers, identities, identity_transitions, deployment_targets, certificates,
		          connector_delivery_receipts, lifecycle_rotation_runs
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset projection checkpoint: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset outbox reconciliation checkpoint: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}
