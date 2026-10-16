// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

type legacyRetirementSigner struct {
	signerpb.UnimplementedSignerServiceServer
	mu              sync.Mutex
	held            map[string]bool
	failAfterDelete bool
}

func (s *legacyRetirementSigner) ZeroizeKey(_ context.Context, req *signerpb.ZeroizeKeyRequest) (*signerpb.ZeroizeKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.held, req.GetHandle())
	if s.failAfterDelete {
		s.failAfterDelete = false
		return nil, status.Error(codes.Unavailable, "response lost after signer deletion")
	}
	return &signerpb.ZeroizeKeyResponse{}, nil
}

func (s *legacyRetirementSigner) GetPublicKey(_ context.Context, req *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held[req.GetHandle().GetId()] {
		return nil, status.Error(codes.NotFound, "key is absent")
	}
	return &signerpb.GetPublicKeyResponse{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, PublicKey: []byte("public")}, nil
}

func (s *legacyRetirementSigner) has(handle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[handle]
}

type legacyRetirementSignerProvider struct{ client *signing.Client }

func (p legacyRetirementSignerProvider) Client() *signing.Client { return p.client }

func legacyRetirementFreePort(t *testing.T) uint32 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	if port < 0 || port > math.MaxUint16 {
		t.Fatalf("invalid PostgreSQL test port %d", port)
	}
	return uint32(port) // #nosec G115 -- TCP port was checked against [0, 65535] above.
}

// A prior build recorded retirement after zeroizing a legacy unscoped handle.
// The real tenant-bound key must be removed on cold replay, even if the policy
// projection already says retired and the first signer response is ambiguous.
func TestRetiredLegacyPolicyRepairsSignerCustodyAfterColdRestart(t *testing.T) {
	ctx := context.Background()
	port := legacyRetirementFreePort(t)
	pgRoot := t.TempDir()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(port).
		RuntimePath(filepath.Join(pgRoot, "rt")).DataPath(filepath.Join(pgRoot, "data")).
		BinariesPath(filepath.Join(pgRoot, "bin")).Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	store, err := corestore.Open(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	store.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const identityID = "spiffe://qa.local/pcas/legacy-retired"
	if err := store.UpsertTenant(ctx, corestore.Tenant{TenantID: tenantID, Name: "legacy retirement"}); err != nil {
		t.Fatal(err)
	}
	repo := pcasstore.New(store)
	if err := repo.UpsertRetirementPolicy(ctx, tenantID, pcasstore.RetirementPolicy{
		IdentityID: identityID, PredecessorEpoch: 0, Threshold: 1,
		PredecessorHandle: "", Status: "retired",
	}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	payload, err := json.Marshal(succession.RetirementV1{TenantID: tenantID, IdentityID: identityID, Epoch: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: succession.TypeRetirement, Data: payload}); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp(os.TempDir(), "pcas-ret-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "signer.sock")
	socketListener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	bound := succession.TenantKeyHandle(tenantID, identityID, 0)
	other := succession.TenantKeyHandle("22222222-2222-4222-8222-222222222222", identityID, 0)
	fake := &legacyRetirementSigner{held: map[string]bool{bound: true, other: true}, failAfterDelete: true}
	grpcServer := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(grpcServer, fake)
	go func() { _ = grpcServer.Serve(socketListener) }()
	t.Cleanup(grpcServer.Stop)
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	newWorker := func() *retirementWorker {
		return &retirementWorker{store: store, repo: repo, log: log, signer: legacyRetirementSignerProvider{client: client}}
	}
	if err := newWorker().runOnce(ctx); status.Code(err) != codes.Unavailable {
		t.Fatalf("lost signer response = %v, want retryable Unavailable", err)
	}
	if err := newWorker().runOnce(ctx); err != nil {
		t.Fatalf("cold retry of retired custody: %v", err)
	}
	if fake.has(bound) || !fake.has(other) {
		t.Fatalf("tenant-bound predecessor held=%t, other tenant key held=%t; want false,true", fake.has(bound), fake.has(other))
	}
	policy, found, err := repo.GetRetirementPolicy(ctx, tenantID, identityID, 0)
	if err != nil || !found || policy.Status != "retired" {
		t.Fatalf("retirement status after custody retry = %q, found=%t, err=%v", policy.Status, found, err)
	}
}
