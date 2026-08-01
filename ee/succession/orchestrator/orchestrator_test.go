// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	pcasstore "trstctl.com/trstctl/ee/succession/store"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/ee/succession/orchestrator"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-pcas-orch-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)).
		RuntimePath(dir + "/rt").DataPath(dir + "/data").BinariesPath(dir + "/bin").
		Logger(io.Discard).StartTimeout(60 * time.Second))
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
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

type mapResolver map[string]crypto.Signer

func (r mapResolver) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no handle")
	}
	return s, nil
}

type memFloor struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemFloor() *memFloor { return &memFloor{m: map[string]uint64{}} }
func (f *memFloor) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}
func (f *memFloor) Advance(id string, e uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = e
	return nil
}

// countingMinter counts MintSuccessor calls to prove exactly-once minting.
type countingMinter struct {
	inner *minter.Minter
	calls int
}

func (c *countingMinter) MintSuccessor(ctx context.Context, req signing.MintRequest) (signing.MintResult, error) {
	c.calls++
	return c.inner.MintSuccessor(ctx, req)
}

func setup(t *testing.T) (*orchestrator.Orchestrator, *countingMinter, *corestore.Store) {
	t.Helper()
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	m, err := minter.New(mapResolver{"pred": pred}, be, newMemFloor())
	if err != nil {
		t.Fatal(err)
	}
	cm := &countingMinter{inner: m}
	return orchestrator.New(cs, cm), cm, cs
}

func req(identity string) signing.MintRequest {
	return signing.MintRequest{
		IdentityID: identity, TenantID: tenantA, DeploymentScope: "spiffe://d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "policy:1", NotBefore: 1, NotAfter: 1000,
	}
}

// TestSuccession_IdempotentSingleMint: a retry with the same key mints exactly
// once and returns the original record (PCAS-claim-6 / INV-4).
func TestSuccession_IdempotentSingleMint(t *testing.T) {
	orch, cm, cs := setup(t)
	ctx := context.Background()

	r1, err := orch.RunSuccession(ctx, tenantA, req("spiffe://d/idem"), "key-1")
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if r1.Epoch != 1 || r1.Replayed {
		t.Fatalf("run 1: epoch=%d replayed=%v, want 1,false", r1.Epoch, r1.Replayed)
	}
	r2, err := orch.RunSuccession(ctx, tenantA, req("spiffe://d/idem"), "key-1")
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if r2.Epoch != 1 || !r2.Replayed {
		t.Fatalf("run 2: epoch=%d replayed=%v, want 1,true", r2.Epoch, r2.Replayed)
	}
	if string(r1.Record) != string(r2.Record) {
		t.Fatal("replay returned a different record")
	}
	if cm.calls != 1 {
		t.Fatalf("minter called %d times, want exactly 1", cm.calls)
	}
	// Exactly one succession row for the identity.
	var n int
	if err := cs.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM succession_records WHERE identity_id = $1`, "spiffe://d/idem").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("succession_records rows = %d, want 1", n)
	}
}

// TestPublish_OnlyViaOutbox: publication of a minted record flows only through the
// transactional outbox, written in the same txn as the record (PCAS-claim-6 / INV-4).
func TestPublish_OnlyViaOutbox(t *testing.T) {
	orch, _, cs := setup(t)
	ctx := context.Background()

	r, err := orch.RunSuccession(ctx, tenantA, req("spiffe://d/outbox"), "key-2")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var payload []byte
	var dest string
	if err := cs.SystemPool().QueryRow(ctx,
		`SELECT destination, payload FROM outbox WHERE idempotency_key = $1`, "key-2").Scan(&dest, &payload); err != nil {
		t.Fatalf("outbox row missing (publication did not go through the outbox): %v", err)
	}
	if dest != orchestrator.PublishDestination {
		t.Fatalf("outbox destination = %q, want %q", dest, orchestrator.PublishDestination)
	}
	if string(payload) != string(r.Record) {
		t.Fatal("outbox payload does not match the minted record")
	}
}
