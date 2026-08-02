// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke_test

// Integration harness for the AGID-10 cascade. It runs against ONE real embedded
// PostgreSQL (shared across the package, per-test database) and an in-process embedded
// NATS JetStream event log — the same substrates the spine runs under, never mocks —
// so the transactional-outbox atomicity (INV-A8), the idempotent at-least-once job
// execution (AGID-claim-21), and the durable-first directive append + reconcile (G3) are
// exercised faithfully. Mirrors the AGID-02 store and internal/orchestrator harnesses.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL for the whole package (downloaded once,
// cached), mirroring the AGID-02 store harness. Each test opens its own database so
// tables start empty and tests do not interfere.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-agid-revoke-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
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

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// harness bundles the live substrates a cascade test drives.
type harness struct {
	core   *corestore.Store
	repo   *agidstore.Repo
	log    *events.Log
	outbox *orchestrator.Outbox
	signer crypto.Signer
}

// newHarness opens a core store on a fresh database with the AGID DDL applied through
// the feature-neutral WithExtraMigrations seam, an embedded NATS event log, the AN-6
// outbox over the store, and a software evidence signer.
func newHarness(t *testing.T, dbName string) *harness {
	t.Helper()
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil &&
		!containsAlreadyExists(err.Error()) {
		t.Fatalf("create db %s: %v", dbName, err)
	}
	dsn := trimSuffix(testDSN, "/postgres") + "/" + dbName

	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(agidstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	ob := orchestrator.NewOutbox(cs)

	be := crypto.NewSoftwareBackend()
	signer, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate evidence signer: %v", err)
	}

	return &harness{core: cs, repo: agidstore.New(cs), log: log, outbox: ob, signer: signer}
}

// cascade builds a cascade over the harness substrates.
func (h *harness) cascade(t *testing.T) *revoke.Cascade {
	t.Helper()
	c, err := revoke.NewCascade(h.log, h.core, h.repo, h.outbox)
	if err != nil {
		t.Fatalf("NewCascade: %v", err)
	}
	return c
}

// executor builds a job executor over the harness substrates with a fixed clock and a
// named executor identity (deterministic evidence).
func (h *harness) executor(t *testing.T, opts ...revoke.ExecutorOption) *revoke.Executor {
	t.Helper()
	base := []revoke.ExecutorOption{
		revoke.WithExecutorID("test-executor"),
		revoke.WithClock(func() int64 { return 1_700_000_000 }),
	}
	ex, err := revoke.NewExecutor(h.log, h.core, h.outbox, h.signer, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// appendEvent appends a typed delegation-lifecycle payload to the live log and returns
// the stored event (with its assigned sequence). It is how tests seed the delegation
// tree the cascade folds to determine descendants.
func (h *harness) appendEvent(t *testing.T, p delegation.Payload) eventspec.Event {
	t.Helper()
	ev, err := delegation.Encode(p)
	if err != nil {
		t.Fatalf("encode %T: %v", p, err)
	}
	stored, err := h.log.Append(context.Background(), ev)
	if err != nil {
		t.Fatalf("append %T: %v", p, err)
	}
	return stored
}

// seedChainCredential appends a single-hop root->agent delegation record and an
// issuance of credentialID over it, for subject, in tenant. It returns nothing; the
// cascade folds the log to find the descendant. label seeds the digests so multiple
// credentials are distinct.
func (h *harness) seedChainCredential(t *testing.T, tenant, label, delegator, delegate, subject, credentialID string) {
	t.Helper()
	recDigest := crypto.SHA256Sum([]byte("rec:" + label))
	credDigest := crypto.SHA256Sum([]byte(credentialID))
	h.appendEvent(t, delegation.DelegationRecordedV1{
		TenantID: tenant, RecordDigest: recDigest, DelegatorID: delegator, DelegateID: delegate,
		RootAnchor: true, DepthRemaining: 3,
	})
	h.appendEvent(t, delegation.IssuanceRecordedV1{
		TenantID: tenant, CredentialDigest: credDigest, SubjectID: subject, ChainDigest: recDigest,
	})
}

// outboxHasKey reports whether the tenant has a not-yet-delivered outbox entry with
// the given idempotency key. It is directive-scoped, so atomicity assertions are
// independent of other directives' rows (stable under repeated runs on a shared db).
func (h *harness) outboxHasKey(t *testing.T, tenant, idempotencyKey string) bool {
	t.Helper()
	recs, err := h.outbox.Pending(context.Background(), tenant)
	if err != nil {
		t.Fatalf("outbox pending: %v", err)
	}
	for _, r := range recs {
		if r.IdempotencyKey == idempotencyKey {
			return true
		}
	}
	return false
}

// pendingByDestination returns the tenant's not-yet-delivered outbox entries for one
// destination.
func (h *harness) pendingByDestination(t *testing.T, tenant, destination string) []orchestrator.Record {
	t.Helper()
	recs, err := h.outbox.Pending(context.Background(), tenant)
	if err != nil {
		t.Fatalf("outbox pending: %v", err)
	}
	var out []orchestrator.Record
	for _, r := range recs {
		if r.Destination == destination {
			out = append(out, r)
		}
	}
	return out
}

// credID renders the credential id the seed uses for a credential label: hex of the
// credential digest, matching what the projection emits (hex of the credential digest).
func credID(credentialID string) string {
	return hexEncode(crypto.SHA256Sum([]byte(credentialID)))
}

// drainOutbox dispatches the revocation-job outbox to the executor until no due work
// remains or maxRounds is reached, returning the total processed. It drives the real
// dispatcher over the real outbox, so at-least-once delivery + the executor's
// idempotency are exercised end to end.
func drainOutbox(t *testing.T, ob *orchestrator.Outbox, ex *revoke.Executor, maxRounds int) int {
	t.Helper()
	total := 0
	for i := 0; i < maxRounds; i++ {
		n, err := ob.Dispatch(context.Background(), ex.Handler())
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		total += n
		if n == 0 {
			break
		}
	}
	return total
}

// withTenantTx runs fn on a tenant-scoped tx (test helper for the atomicity test's
// fault injection).
func (h *harness) withTenantTx(t *testing.T, tenant string, fn func(pgx.Tx) error) error {
	t.Helper()
	return h.core.WithTenant(context.Background(), tenant, fn)
}

// terminal builds a terminal-transition engine over the harness substrates with a fixed
// clock (deterministic terminal_at) and the harness evidence signer as the aggregate
// signer. terminalAt fixes the terminal_at timestamp so interval tests are deterministic.
func (h *harness) terminal(t *testing.T, terminalAt int64) *revoke.TerminalTransition {
	t.Helper()
	tt, err := revoke.NewTerminalTransition(h.repo, h.core, h.log, h.signer,
		revoke.WithTerminalClock(func() int64 { return terminalAt }))
	if err != nil {
		t.Fatalf("NewTerminalTransition: %v", err)
	}
	return tt
}

// intervalMonitor builds an interval monitor over the harness substrates with the given
// policy interval (seconds) and a fixed clock (deterministic elapsed time for a
// still-draining directive).
func (h *harness) intervalMonitor(t *testing.T, intervalSecs, now int64) *revoke.IntervalMonitor {
	t.Helper()
	m, err := revoke.NewIntervalMonitor(h.repo, h.log, intervalSecs,
		revoke.WithIntervalClock(func() int64 { return now }))
	if err != nil {
		t.Fatalf("NewIntervalMonitor: %v", err)
	}
	return m
}

// enqueueAndDrain enqueues a directive for subject in tenant and drains the outbox to the
// executor until every job records signed completion evidence, returning the directive
// result. It is the "run the whole cascade to completion" helper the terminal tests use.
func (h *harness) enqueueAndDrain(t *testing.T, tenant, subject string, reason revoke.ReasonClass) revoke.DirectiveResult {
	t.Helper()
	c := h.cascade(t)
	ex := h.executor(t)
	res, err := c.EnqueueDirective(context.Background(), revoke.Directive{TenantID: tenant, Subject: subject, Reason: reason})
	if err != nil {
		t.Fatalf("EnqueueDirective: %v", err)
	}
	drainOutbox(t, h.outbox, ex, 16)
	return res
}

// countEvents counts events of the given type for tenant in the live log (used to assert
// distinct terminal / interval-exceeded events were appended exactly once).
func (h *harness) countEvents(t *testing.T, tenant, eventType string) int {
	t.Helper()
	n := 0
	err := h.log.Replay(context.Background(), 1, func(e eventspec.Event) error {
		if e.Type == eventType && e.TenantID == tenant {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replay counting %s: %v", eventType, err)
	}
	return n
}

// orchMsg builds an orchestrator.Message the executor consumes, matching what the
// dispatcher hands a claimed revocation-job entry (used to execute a single job directly).
func orchMsg(tenant, idempotencyKey string, payload []byte) orchestrator.Message {
	return orchestrator.Message{
		TenantID:       tenant,
		Destination:    revoke.DestinationRevocationJob,
		IdempotencyKey: idempotencyKey,
		Payload:        payload,
	}
}

// ---- tiny std-free string helpers (kept local so the harness imports stay minimal) ----

func containsAlreadyExists(s string) bool { return contains(s, "already exists") }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func trimSuffix(s, suf string) string {
	if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)]
	}
	return s
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
