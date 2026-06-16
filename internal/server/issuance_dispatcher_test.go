package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestIssuanceDispatcherRenewalMintsSuccessorAndSupersedesPredecessor(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "renewal-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "renew.served.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)

	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("after initial issue certificates = %d, want 1", len(certs))
	}
	old := certs[0]
	if old.Status != "active" {
		t.Fatalf("initial cert status = %q, want active", old.Status)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatalf("transition to deployed: %v", err)
	}
	dispatchOutbox(t, h, 1) // connector.deploy is explicitly acknowledged when no plugin owns it.

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "operator renewal"); err != nil {
		t.Fatalf("transition to renewing: %v", err)
	}
	renew := pendingOutboxByDestination(t, h, "ca.renew")
	msg := orchestrator.Message{
		TenantID: h.tenant, Destination: renew.Destination,
		Payload: renew.Payload, IdempotencyKey: renew.IdempotencyKey,
	}

	dispatchOutbox(t, h, 1)
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatalf("idempotent ca.renew redelivery: %v", err)
	}

	certs = dispatcherCertificates(t, h)
	if len(certs) != 2 {
		t.Fatalf("after renewal certificates = %d, want exactly 2 (predecessor + successor)", len(certs))
	}
	var gotOld, successor store.Certificate
	for _, c := range certs {
		if c.ID == old.ID {
			gotOld = c
		}
		if c.ReplacesID != nil && *c.ReplacesID == old.ID {
			successor = c
		}
	}
	if gotOld.ID == "" {
		t.Fatal("predecessor certificate disappeared from inventory")
	}
	if gotOld.Status != "superseded" || gotOld.RenewedAt == nil {
		t.Fatalf("predecessor status=%q renewed_at=%v, want superseded with renewal timestamp", gotOld.Status, gotOld.RenewedAt)
	}
	if successor.ID == "" {
		t.Fatal("renewal did not record a successor linked with replaces_id")
	}
	if successor.Status != "active" {
		t.Fatalf("successor status = %q, want active", successor.Status)
	}
	if successor.Serial == "" || successor.Serial == old.Serial {
		t.Fatalf("successor serial = %q, predecessor serial = %q; renewal must mint a distinct cert", successor.Serial, old.Serial)
	}
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), successor.Serial); err != nil {
		t.Fatalf("lookup successor issued-cert row: %v", err)
	} else if !found {
		t.Fatal("successor serial was not bridged into ca_issued_certs for OCSP/CRL")
	}
	state, err := h.orch.State(ctx, h.tenant, ident.ID)
	if err != nil {
		t.Fatalf("identity state: %v", err)
	}
	if state != orchestrator.StateDeployed {
		t.Fatalf("identity state after renewal = %q, want deployed", state)
	}
}

func TestIssuanceDispatcherFailsUnsupportedFirstPartyDestination(t *testing.T) {
	d := &issuanceDispatcher{}
	err := d.Deliver(context.Background(), orchestrator.Message{Destination: "ca.rotate"})
	if err == nil || !strings.Contains(err.Error(), "unsupported first-party outbox destination") {
		t.Fatalf("unsupported ca.* destination error = %v, want fail-closed error", err)
	}
	if err := d.Deliver(context.Background(), orchestrator.Message{Destination: "notification.expiry"}); err != nil {
		t.Fatalf("non-owned notification destination should remain unrouted, got %v", err)
	}
}

type issuanceDispatcherHarness struct {
	store   *store.Store
	log     *events.Log
	outbox  *orchestrator.Outbox
	orch    *orchestrator.Orchestrator
	handler *issuanceDispatcher
	tenant  string
}

func newIssuanceDispatcherHarness(t *testing.T) *issuanceDispatcherHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "trstctl-issuance-dispatcher-pg")
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("embedded postgres start: %v", err)
	}
	t.Cleanup(func() {
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
	})
	st, err := store.Open(ctx, fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Test Issuance Dispatcher CA", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	outbox := orchestrator.NewOutbox(st)
	idem := orchestrator.NewIdempotency(st)
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	handler := &issuanceDispatcher{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, crypto.LeafProfile{})
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: orch, idem: idem, store: st, log: log,
	}
	h := &issuanceDispatcherHarness{
		store: st, log: log, outbox: outbox, orch: orch, handler: handler,
		tenant: "11111111-1111-1111-1111-111111111111",
	}
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: h.tenant, Name: "dispatcher-renewal"}); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	return h
}

func dispatchOutbox(t *testing.T, h *issuanceDispatcherHarness, want int) {
	t.Helper()
	n, err := h.outbox.Dispatch(context.Background(), h.handler)
	if err != nil {
		t.Fatalf("dispatch outbox: %v", err)
	}
	if n != want {
		t.Fatalf("dispatched %d outbox rows, want %d", n, want)
	}
}

func pendingOutboxByDestination(t *testing.T, h *issuanceDispatcherHarness, dest string) orchestrator.Record {
	t.Helper()
	pending, err := h.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	for _, r := range pending {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("no pending %s outbox row in %+v", dest, pending)
	return orchestrator.Record{}
}

func dispatcherCertificates(t *testing.T, h *issuanceDispatcherHarness) []store.Certificate {
	t.Helper()
	certs, err := h.store.ListCertificatesPage(context.Background(), h.tenant, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	return certs
}
