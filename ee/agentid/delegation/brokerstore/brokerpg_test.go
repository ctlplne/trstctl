// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/eventspec"
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
	pgTenantReplay  = "11111111-1111-1111-1111-111111111111"
	pgTenantIdem    = "22222222-2222-2222-2222-222222222222"
	pgTenantRefusal = "33333333-3333-3333-3333-333333333333"
)

var (
	pgOnce sync.Once
	pgDSN  string
	pgErr  error
	pgInst *embeddedpostgres.EmbeddedPostgres
	pgDir  string

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
		Port(port).
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
	pgDir = dir
	pgDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
}

// TestMain stops the embedded server this package starts.
//
// Without it, inst.Start() ran and nothing ever called Stop: every invocation of
// this package left a PostgreSQL server running for the life of the machine,
// each holding a SysV shared-memory segment. macOS allows 32
// (kern.sysv.shmmni), so after roughly thirty runs NO Postgres-backed test in
// the repository can start — initdb fails with "could not create shared memory
// segment", and the failure surfaces in whatever package happens to run next
// rather than in the one that leaked. That misdirection is what makes this worth
// a teardown rather than a cleanup script.
func TestMain(m *testing.M) {
	code := m.Run()
	if pgInst != nil {
		if err := pgInst.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "brokerstore: stop embedded postgres: %v\n", err)
		}
	}
	if pgDir != "" {
		_ = os.RemoveAll(pgDir)
	}
	os.Exit(code)
}

func ensurePG(t *testing.T) string {
	t.Helper()
	pgOnce.Do(startPG)
	if pgErr != nil {
		t.Skipf("embedded PostgreSQL unavailable, skipping AGID-07b durable-path test: %v", pgErr)
	}
	return pgDSN
}

// freeTCPPort reserves an ephemeral port and returns it as the uint32 the embedded-postgres
// config expects, so no narrowing conversion is needed at the call site. The kernel only ever
// hands back a 16-bit port; the bound check makes that provable here and fails closed rather
// than wrapping if the assumption ever breaks.
func freeTCPPort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p < 0 || p > math.MaxUint16 {
		return 0, fmt.Errorf("listener reported out-of-range TCP port %d", p)
	}
	return uint32(p), nil
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

// ---- TestSignerRefusal_RecordedDurably (INV-A1 signed-refusal substrate / AUD-4) ----

// capturingAppender is the recorder's eventAppender seam, capturing appended events and
// assigning sequences, so the test can assert the agent.refusal.recorded fact without a
// live JetStream.
type capturingAppender struct {
	mu     sync.Mutex
	events []eventspec.Event
}

func (c *capturingAppender) Append(_ context.Context, e eventspec.Event) (eventspec.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.Sequence = uint64(len(c.events) + 1)
	c.events = append(c.events, e)
	return e, nil
}

func (c *capturingAppender) byType(typ string) []eventspec.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []eventspec.Event
	for _, e := range c.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// TestSignerRefusal_RecordedDurably is the AUD-4 regression, driven through the FULL
// precondition with the PRODUCTION recorder: a chain-bound issuance whose attestation
// evidence fails verification is refused with ErrSignerRefused AND the gate's signed
// refusal artifact lands as one agent_refusal_records row naming the failed check, plus
// one agent.refusal.recorded event. Asserting only ErrSignerRefused passes on the
// pre-fix tree — the row and the event are what AUD-4 found missing.
func TestSignerRefusal_RecordedDurably(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	rec, cs := newRecorderPG(t, clock)
	log := &capturingAppender{}
	rec = rec.WithEventLog(log)
	tenant := pgTenantRefusal

	// A valid chain, but the presented attestation payload is NOT the seeded one:
	// the in-signer gate refuses naming the attestation check.
	gate, _, req := attestedRequest(t, tenant, "tpm", delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, "privileged", clock)
	req.Attestation = attBody(t, "tpm", []byte("tampered-evidence"))
	pre := NewBrokerPrecondition(Config{Gate: gate, Policy: &fakePolicy{allow: true}, Resolver: staticResolver{req: req, found: true}, Recorder: rec, Clock: clock})

	err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-refused", IdempotencyKey: "k-refusal-1", AttestationMethod: "tpm",
	})
	if !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("tampered-attestation issuance = %v, want ErrSignerRefused", err)
	}

	// The refusal is DURABLE: one row naming the failed check, with the signature.
	if got := countRows(t, cs, tenant,
		`SELECT count(*) FROM agent_refusal_records
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND failed_check = $1 AND subject_id = $2`,
		delegation.CheckAttestation, "leaf"); got != 1 {
		all := countRows(t, cs, tenant, `SELECT count(*) FROM agent_refusal_records WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		t.Fatalf("refusal rows naming check %q = %d (total %d), want exactly 1 — the signed refusal was minted and thrown away (AUD-4)", delegation.CheckAttestation, got, all)
	}
	if got := countRows(t, cs, tenant,
		`SELECT count(*) FROM agent_refusal_records
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND octet_length(signature) > 0`); got != 1 {
		t.Fatalf("refusal rows carrying a signature = %d, want 1 (the artifact is SIGNED)", got)
	}

	// And the AN-2 fact exists: exactly one agent.refusal.recorded event.
	refusalEvents := log.byType(delegation.TypeRefusalRecorded)
	if len(refusalEvents) != 1 {
		t.Fatalf("agent.refusal.recorded events = %d, want exactly 1", len(refusalEvents))
	}

	// A SECOND refused attempt mints a fresh signed artifact (ECDSA signatures are
	// randomized) and records as its own refusal fact: two refused attempts are two
	// refusals, and hiding the second would under-report exactly what this
	// substrate exists to show.
	err = pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: tenant, AgentID: "agent-refused", IdempotencyKey: "k-refusal-2", AttestationMethod: "tpm",
	})
	if !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("retried tampered-attestation issuance = %v, want ErrSignerRefused", err)
	}
	if got := countRows(t, cs, tenant, `SELECT count(*) FROM agent_refusal_records WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`); got != 2 {
		t.Fatalf("refusal rows after a second refused attempt = %d, want 2 (each refusal is its own fact)", got)
	}

	// Re-recording the SAME artifact bytes (a crash-retry between insert and ack) is
	// idempotent: the refusal id derives from the artifact digest.
	art, err := delegation.DecodeRefusal(mustFirstRefusalRecord(t, log))
	if err != nil {
		t.Fatalf("decode captured refusal: %v", err)
	}
	raw, err := delegation.EncodeRefusal(art)
	if err != nil {
		t.Fatalf("re-encode refusal: %v", err)
	}
	if err := rec.RecordRefusal(context.Background(), tenant, raw); err != nil {
		t.Fatalf("re-record same artifact: %v", err)
	}
	if err := rec.RecordRefusal(context.Background(), tenant, raw); err != nil {
		t.Fatalf("re-record same artifact twice: %v", err)
	}
	after := countRows(t, cs, tenant, `SELECT count(*) FROM agent_refusal_records WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
	if after != 3 {
		t.Fatalf("refusal rows after re-recording one artifact twice = %d, want 3 (2 live refusals + 1 re-encoded, deduped on digest)", after)
	}
}

// mustFirstRefusalRecord rebuilds the raw artifact bytes carried by the first captured
// agent.refusal.recorded event so the same-bytes idempotency path can be exercised.
// The event payload carries the artifact fields; re-encoding through the public codec
// yields stable bytes for the digest-keyed insert.
func mustFirstRefusalRecord(t *testing.T, log *capturingAppender) []byte {
	t.Helper()
	events := log.byType(delegation.TypeRefusalRecorded)
	if len(events) == 0 {
		t.Fatal("no captured agent.refusal.recorded event")
	}
	decoded, err := delegation.Decode(events[0])
	if err != nil {
		t.Fatalf("decode refusal event: %v", err)
	}
	p, ok := decoded.(delegation.RefusalRecordedV1)
	if !ok {
		t.Fatalf("decoded refusal event = %T, want RefusalRecordedV1", decoded)
	}
	raw, err := delegation.EncodeRefusal(delegation.RefusalArtifact{
		TenantID:    p.TenantID,
		SubjectID:   p.SubjectID,
		FailedCheck: p.FailedCheck, RequestDigest: p.RequestDigest, Signature: p.Signature,
	})
	if err != nil {
		t.Fatalf("encode artifact: %v", err)
	}
	return raw
}
