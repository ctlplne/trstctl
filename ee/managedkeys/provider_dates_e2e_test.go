// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// datedKMS is a cloud-KMS-like provider for the isolated signer: it keeps each
// key's own creation date and, once deletion is scheduled, its deletion date.
type datedKMS struct {
	mu        sync.Mutex
	keys      map[string]*crypto.LockedSigner
	created   map[string]time.Time
	deletes   map[string]time.Time
	byOp      map[string]string
	destroyed map[string]bool
}

func newDatedKMS() *datedKMS {
	return &datedKMS{keys: map[string]*crypto.LockedSigner{}, created: map[string]time.Time{}, deletes: map[string]time.Time{},
		byOp: map[string]string{}, destroyed: map[string]bool{}}
}

func (k *datedKMS) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return k.GenerateManagedKeyForOperation(ctx, "", alg)
}

func (k *datedKMS) GenerateManagedKeyForOperation(_ context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if id, ok := k.byOp[operationID]; ok && operationID != "" {
		return datedSigner{k.keys[id]}, crypto.KeyRef{ID: id, Algorithm: alg}, nil
	}
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	id := fmt.Sprintf("dated-key-%d", len(k.keys)+1)
	k.keys[id], k.created[id] = signer, time.Date(2026, 11, 13, 8, 0, len(k.keys)+1, 0, time.UTC)
	k.byOp[operationID] = id
	return datedSigner{signer}, crypto.KeyRef{ID: id, Algorithm: alg}, nil
}

// datedSigner signs with a provider-held key, as a KMS signer does.
type datedSigner struct{ key *crypto.LockedSigner }

func (s datedSigner) Public() crypto.PublicKey    { return s.key.Public() }
func (s datedSigner) Algorithm() crypto.Algorithm { return s.key.Algorithm() }
func (s datedSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	hash := opts.Hash
	if hash == "" {
		hash = crypto.SHA256
	}
	digest, err := crypto.Digest(hash, message)
	if err != nil {
		return nil, err
	}
	return s.key.SignDigest(digest, opts)
}

func (k *datedKMS) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return k.GenerateManagedKeyForOperation(ctx, "", ref.Algorithm)
}

func (k *datedKMS) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return k.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
}

func (k *datedKMS) RevokeKey(context.Context, crypto.KeyRef) error { return nil }

func (k *datedKMS) RevokeKeyForOperation(context.Context, string, crypto.KeyRef) error { return nil }

func (k *datedKMS) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	return k.ZeroizeKeyForOperation(ctx, "", ref)
}

func (k *datedKMS) ZeroizeKeyForOperation(_ context.Context, _ string, ref crypto.KeyRef) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.destroyed[ref.ID] {
		k.destroyed[ref.ID] = true
		k.deletes[ref.ID] = k.created[ref.ID].Add(30 * 24 * time.Hour)
	}
	return nil
}

func (k *datedKMS) KeyDates(_ context.Context, ref crypto.KeyRef) (crypto.KeyDates, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return crypto.KeyDates{Created: k.created[ref.ID], DeletionScheduled: k.deletes[ref.ID]}, nil
}

func (k *datedKMS) destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		key.Destroy()
	}
}

// refuseDestructive is the exact-approval authority the durable factory
// requires; this test issues no destructive command.
type refuseDestructive struct{}

func (refuseDestructive) AuthorizeApproval(context.Context, api.ApprovalIntent) (api.ApprovalAuthority, bool, string) {
	return api.ApprovalAuthority{}, false, "no destructive command in this test"
}

// A168-L3 Done-when (end to end through the licensed executor): a key generated
// through the durable managed-key service, executed by the outbox handler
// through a real isolated signer over its socket, lands in the managed-key
// record with the provider's own creation date — not the moment the operation
// completed. (A destructive command's deletion date takes the same completion
// path; its projection is proven in the store and served tests.)
func TestManagedKeyRecordsTheProvidersOwnDatesEndToEndA168L3(t *testing.T) {
	ctx := context.Background()
	st := openDatesStore(t)
	const tenant = "11111111-2222-4333-8444-a168a1683333"
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a168l3 tenant') ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kms := newDatedKMS()
	t.Cleanup(kms.destroy)
	client := serveDatedSigner(t, kms)

	built, err := NewDurableFactory(ProviderSelection{Default: "aws-kms", Enabled: []string{"aws-kms"}})(server.ManagedKeyServiceDeps{
		Store: st, Log: log, Idempotency: orchestrator.NewIdempotency(st), ApprovalChecker: refuseDestructive{}})
	if err != nil {
		t.Fatal(err)
	}
	svc := built.(*durableService)
	svc.waitDuration = time.Millisecond
	handler, err := NewDurableOutboxFactory()(editionseam.LicensedOutboxDeps{Store: st, Log: log, ManagedKeyCustody: client})
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(idempotencyKey string) {
		t.Helper()
		operationID, err := durableOperationID(tenant, idempotencyKey)
		if err != nil {
			t.Fatal(err)
		}
		var message orchestrator.Message
		message.TenantID = tenant
		if err := st.SystemPool().QueryRow(ctx,
			`SELECT id, destination, effect_lane, payload, idempotency_key FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenant, operationID).Scan(&message.ID, &message.Destination, &message.EffectLane, &message.Payload, &message.IdempotencyKey); err != nil {
			t.Fatalf("read the queued command for %s: %v", idempotencyKey, err)
		}
		if handled, err := handler.DeliverLicensed(ctx, message); !handled || err != nil {
			t.Fatalf("deliver %s: handled %v, %v", idempotencyKey, handled, err)
		}
	}
	record := func(keyID string) store.ManagedKey {
		t.Helper()
		keys, err := st.ListManagedKeysPage(ctx, tenant, "", "", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			if key.KeyID == keyID {
				return key
			}
		}
		t.Fatalf("managed key %s not recorded: %+v", keyID, keys)
		return store.ManagedKey{}
	}

	const binding = "7de7890fd3d4a5d98398c6c3c5af8c08e07fc174e7e1f071f9f5496c097e47d0"
	if _, err := svc.Generate(ctx, tenant, "aws-kms", crypto.ECDSAP256, "a168l3-generate", binding); err == nil {
		t.Fatal("generate completed without the outbox handler running")
	}
	deliver("a168l3-generate")
	key := record("dated-key-1")
	created := time.Date(2026, 11, 13, 8, 0, 1, 0, time.UTC)
	if key.ProviderCreatedAt == nil || !key.ProviderCreatedAt.Equal(created) || key.ProviderDeletionAt != nil || key.CreatedAt.Equal(created) {
		t.Fatalf("generated key = created %v (record %v), deletion %v; want the provider's %s", key.ProviderCreatedAt, key.CreatedAt, key.ProviderDeletionAt, created)
	}

	// A redelivered command is acknowledged from the projected completion; the
	// recorded dates stay the provider's.
	deliver("a168l3-generate")
	if again := record("dated-key-1"); again.ProviderCreatedAt == nil || !again.ProviderCreatedAt.Equal(created) {
		t.Fatalf("after a redelivery = %v", again.ProviderCreatedAt)
	}
	// The completed result the service returns now is the recorded key. The
	// replay gets an ordinary wait: its reads share the wait's budget.
	svc.waitDuration = 5 * time.Second
	if result, err := svc.Generate(ctx, tenant, "aws-kms", crypto.ECDSAP256, "a168l3-generate", binding); err != nil || result.KeyID != "dated-key-1" {
		t.Fatalf("replayed generate = %+v %v", result, err)
	}
}

func serveDatedSigner(t *testing.T, provider crypto.RemoteKeyLifecycle) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "a168l3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv := signing.NewServer(signing.WithManagedKeyProviders(filepath.Join(dir, "journal"), map[string]crypto.RemoteKeyLifecycle{"aws-kms": provider}))
	go func() {
		done <- signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("signer server did not stop")
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// openDatesStore starts an embedded PostgreSQL for this test alone.
func openDatesStore(t *testing.T) *store.Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "trstctl-managedkeys-pg")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	if port <= 0 || port > math.MaxUint16 {
		t.Fatal("no free port")
	}
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)). // #nosec G115 -- port is checked to be 1..65535 above (CWE-190)
		RuntimePath(dir + "/rt").DataPath(dir + "/data").BinariesPath(dir + "/bin").
		Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop(); _ = os.RemoveAll(dir) })
	st, err := store.Open(context.Background(), fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}
