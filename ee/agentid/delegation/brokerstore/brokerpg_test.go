// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/internal/broker"
	corestore "trstctl.com/trstctl/internal/store"
)

// brokerpg_test.go proves the two AGID-07b paths that require durable state against REAL
// embedded PostgreSQL (no mocks): the attestation-binding replay refusal (AGID-claim-9 /
// INV-A6) and the idempotency-key single-issuance-event property (AGID-claim-15 / AN-5). It
// spins ONE embedded PostgreSQL lazily, migrates ONE shared AGID database once (disk-
// frugal), isolates the two tests by tenant (RLS), and skips if PG cannot start. It
// exercises the production brokerstore.Recorder behind the full BrokerPrecondition, so the
// replay + idempotency behavior is proven end-to-end.

const (
	pgTenantReplay = "11111111-1111-1111-1111-111111111111"
	pgTenantIdem   = "22222222-2222-2222-2222-222222222222"
)

var (
	pgOnce sync.Once
	pgDSN  string
	pgErr  error
	pgInst *embeddedpostgres.EmbeddedPostgres

	storeOnce  sync.Once
	sharedCS   *corestore.Store
	sharedErr  error
	sharedName = "agid07b_shared"
)

func startPG() {
	dir, err := os.MkdirTemp("", "trstctl-agid-brokerpg")
	if err != nil {
		pgErr = err
		return
	}
	port, err := freeTCPPort()
	if err != nil {
		pgErr = err
		return
	}
	inst := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := inst.Start(); err != nil {
		pgErr = fmt.Errorf("embedded postgres start: %w", err)
		_ = os.RemoveAll(dir)
		return
	}
	pgInst = inst
	pgDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
}

func ensurePG(t *testing.T) string {
	t.Helper()
	pgOnce.Do(startPG)
	if pgErr != nil {
		t.Skipf("embedded PostgreSQL unavailable, skipping AGID-07b durable-path test: %v", pgErr)
	}
	return pgDSN
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// sharedStore opens (once for the whole package) a single core store against one AGID
// database, migrating it through the feature-neutral WithExtraMigrations seam. Sharing one
// migrated DB keeps the disk footprint to a single full schema; the tests isolate by
// tenant (RLS).
func sharedStore(t *testing.T) *corestore.Store {
	t.Helper()
	dsn := ensurePG(t)
	storeOnce.Do(func() {
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			sharedErr = err
			return
		}
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{sharedName}.Sanitize()); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			_ = admin.Close(ctx)
			sharedErr = fmt.Errorf("create db %s: %w", sharedName, err)
			return
		}
		_ = admin.Close(ctx)

		dbDSN := strings.TrimSuffix(dsn, "/postgres") + "/" + sharedName
		cs, err := corestore.Open(ctx, dbDSN)
		if err != nil {
			sharedErr = fmt.Errorf("core store open: %w", err)
			return
		}
		cs.WithExtraMigrations(agidstore.MigrationsFS())
		if err := cs.Migrate(ctx); err != nil {
			cs.Close()
			sharedErr = fmt.Errorf("migrate: %w", err)
			return
		}
		sharedCS = cs
	})
	if sharedErr != nil {
		t.Fatalf("shared AGID store: %v", sharedErr)
	}
	return sharedCS
}

// newRecorderPG returns the production recorder over the shared migrated store, clocked
// deterministically, plus the store for row-count assertions.
func newRecorderPG(t *testing.T, clock func() time.Time) (*Recorder, *corestore.Store) {
	t.Helper()
	cs := sharedStore(t)
	return New(cs).WithClock(clock), cs
}

// countRows returns the number of rows matching the query under tenant RLS scope.
func countRows(t *testing.T, cs *corestore.Store, tenantID, sql string, args ...any) int {
	t.Helper()
	var n int
	err := cs.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	return n
}

// ---- TestAttestation_BoundToIssuanceReplayRefused (AGID-claim-9 / INV-A6) ----

// TestAttestation_BoundToIssuanceReplayRefused proves the verified attestation is recorded
// bound to the issuance it justified, and a SECOND issuance presenting the SAME attestation
// evidence is refused (the durable evidence-digest unique index rejects it). It drives the
// full BrokerPrecondition with the production recorder so the replay refusal is end-to-end.
func TestAttestation_BoundToIssuanceReplayRefused(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	rec, cs := newRecorderPG(t, clock)
	tenant := pgTenantReplay

	gate, att, req := attestedRequest(t, tenant, "tpm", delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, "privileged", clock)
	pre := NewBrokerPrecondition(Config{Gate: gate, Policy: &fakePolicy{allow: true}, Resolver: staticResolver{req: req, found: true}, Recorder: rec, Clock: clock})

	// First issuance: approved, one binding bound to its issuance.
	if err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-replay", IdempotencyKey: "k-1", AttestationMethod: "tpm",
	}); err != nil {
		t.Fatalf("first chain-bound issuance refused: %v", err)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_attestation_bindings WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 1 {
		t.Fatalf("attestation bindings after first issuance = %d, want 1", got)
	}
	// The binding references the issuance it justified (join on credential_id).
	boundToIssuance := countRows(t, cs, tenant,
		`SELECT count(*) FROM agent_attestation_bindings b
		   JOIN agent_issuances i ON i.tenant_id = b.tenant_id AND i.credential_id = b.credential_id
		  WHERE b.tenant_id = current_setting('trstctl.tenant_id')::uuid`)
	if boundToIssuance != 1 {
		t.Fatalf("attestation binding not joined to its issuance (bound rows = %d, want 1) — must reference the issuance it justified (AGID-claim-9)", boundToIssuance)
	}

	// SECOND issuance with the SAME attestation (DIFFERENT idempotency key = a genuine
	// replay, not a retry): refused (INV-A6).
	err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-replay-2", IdempotencyKey: "k-2", AttestationMethod: "tpm",
	})
	if err == nil {
		t.Fatal("a second issuance with the SAME attestation evidence was NOT refused (INV-A6 violated)")
	}
	if !errors.Is(err, delegation.ErrAttestationReplay) {
		t.Fatalf("replayed-attestation refusal = %v, want delegation.ErrAttestationReplay", err)
	}
	// The replay wrote nothing: still exactly one binding and one issuance (rollback).
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_attestation_bindings WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 1 {
		t.Fatalf("attestation bindings after refused replay = %d, want 1 (replay must write nothing)", got)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_issuances WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 1 {
		t.Fatalf("issuances after refused replay = %d, want 1 (replay must not mint)", got)
	}

	// A DIFFERENT attestation (fresh evidence) for the same agent IS allowed — the replay
	// refusal keys on the evidence, not the agent.
	att.seed("hsm", []byte("fresh-hsm-evidence"), delegation.VerifiedAttestation{Subject: "instance-2", Method: "hsm"})
	req2 := req
	req2.Attestation = attBody(t, "hsm", []byte("fresh-hsm-evidence"))
	req2.AttestationMethod = "hsm"
	pre2 := NewBrokerPrecondition(Config{Gate: gate, Policy: &fakePolicy{allow: true}, Resolver: staticResolver{req: req2, found: true}, Recorder: rec, Clock: clock})
	if err := pre2.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-replay", IdempotencyKey: "k-3", AttestationMethod: "hsm",
	}); err != nil {
		t.Fatalf("a FRESH attestation was refused (only a REPLAY should be): %v", err)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_attestation_bindings WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 2 {
		t.Fatalf("attestation bindings after a fresh attestation = %d, want 2", got)
	}
}

// ---- TestIssue_IdempotencyKeySingleEvent (AGID-claim-15 / AN-5) ----

// TestIssue_IdempotencyKeySingleEvent proves N identical chain-bound requests (SAME
// idempotency key) yield EXACTLY ONE issuance event: one agent_issuances row, one
// attestation binding, and one AN-6 outbox message carrying the idempotency key.
func TestIssue_IdempotencyKeySingleEvent(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	rec, cs := newRecorderPG(t, clock)
	tenant := pgTenantIdem

	gate, att, req := attestedRequest(t, tenant, "tpm", delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, "privileged", clock)
	pre := NewBrokerPrecondition(Config{Gate: gate, Policy: &fakePolicy{allow: true}, Resolver: staticResolver{req: req, found: true}, Recorder: rec, Clock: clock})

	const key = "k-idem-single"
	view := broker.IssuanceView{TenantID: tenant, AgentID: "agent-idem", IdempotencyKey: key, AttestationMethod: "tpm"}

	const n = 5
	for i := 0; i < n; i++ {
		if err := pre.CheckIssuancePrecondition(context.Background(), view); err != nil {
			t.Fatalf("identical request %d refused: %v", i, err)
		}
	}

	// Exactly one issuance event: one issuance row, one binding, one outbox message.
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_issuances WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 1 {
		t.Fatalf("agent_issuances rows after %d identical requests = %d, want exactly 1 (AGID-claim-15 / AN-5)", n, got)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_attestation_bindings WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 1 {
		t.Fatalf("attestation bindings after %d identical requests = %d, want exactly 1", n, got)
	}
	if got := countRows(t, cs, tenant,
		`SELECT count(*) FROM outbox WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND destination = $1 AND idempotency_key = $2`,
		delegation.AttestationBindingDestination, key); got != 1 {
		t.Fatalf("outbox messages for the idempotency key after %d identical requests = %d, want exactly 1 (AN-6)", n, got)
	}

	// A DIFFERENT idempotency key (fresh attestation) is a distinct issuance event.
	att.seed("hsm", []byte("idem-fresh-hsm"), delegation.VerifiedAttestation{Subject: "instance-3", Method: "hsm"})
	req2 := req
	req2.Attestation = attBody(t, "hsm", []byte("idem-fresh-hsm"))
	req2.AttestationMethod = "hsm"
	pre2 := NewBrokerPrecondition(Config{Gate: gate, Policy: &fakePolicy{allow: true}, Resolver: staticResolver{req: req2, found: true}, Recorder: rec, Clock: clock})
	if err := pre2.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-idem", IdempotencyKey: "k-idem-other", AttestationMethod: "hsm",
	}); err != nil {
		t.Fatalf("distinct-key issuance refused: %v", err)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_issuances WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 2 {
		t.Fatalf("agent_issuances rows after a distinct key = %d, want 2 (idempotency is keyed)", got)
	}
}
