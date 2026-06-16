package projections_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// esServer wires the real served API over a fresh store + event log, returning
// the httptest server alongside the store and log so a test can both drive HTTP
// mutations and inspect the event log and read model.
func esServer(t *testing.T) (*httptest.Server, *store.Store, *events.Log) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)), api.WithInsecureHeaderResolver())
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, s, log
}

// leafPEM mints a valid certificate PEM (via the crypto boundary) for ingest.
func leafPEM(t *testing.T, dnsName string) string {
	t.Helper()
	ca, err := mtls.NewCA("root")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCertificate([]string{dnsName}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
}

// readModelSnapshot serializes the full served read model for tenant A in a
// deterministic order, so two snapshots are comparable byte-for-byte.
func readModelSnapshot(t *testing.T, s *store.Store) string {
	t.Helper()
	ctx := context.Background()
	owners, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	issuers, err := s.ListIssuers(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	idents, err := s.ListIdentities(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].ID < owners[j].ID })
	sort.Slice(issuers, func(i, j int) bool { return issuers[i].ID < issuers[j].ID })
	sort.Slice(idents, func(i, j int) bool { return idents[i].ID < idents[j].ID })
	sort.Slice(certs, func(i, j int) bool { return certs[i].ID < certs[j].ID })
	b, err := json.MarshalIndent(struct {
		Owners     []store.Owner
		Issuers    []store.Issuer
		Identities []store.Identity
		Certs      []store.Certificate
	}{owners, issuers, idents, certs}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func countReadModel(t *testing.T, s *store.Store) (nOwners, nIssuers, nIdents, nCerts int) {
	t.Helper()
	ctx := context.Background()
	o, _ := s.ListOwners(ctx, tenantA)
	i, _ := s.ListIssuers(ctx, tenantA)
	d, _ := s.ListIdentities(ctx, tenantA)
	c, _ := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 1000, nil)
	return len(o), len(i), len(d), len(c)
}

// seedReadModel drives every served domain mutation through the real HTTP API:
// owner create/update, issuer create, identity create + a lifecycle transition,
// and a certificate ingest (twice, to exercise the fingerprint upsert). It
// returns the created owner/issuer/identity ids.
func seedReadModel(t *testing.T, srv *httptest.Server) (ownerID, issuerID, identityID string) {
	t.Helper()

	st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "o1", body: map[string]any{"kind": "service", "name": "billing", "email": "ops@acme.test"}})
	if st != http.StatusCreated {
		t.Fatalf("create owner1 = %d: %s", st, body)
	}
	ownerID = decode(t, body)["id"].(string)

	st, _, body = do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "o2", body: map[string]any{"kind": "workload", "name": "payments"}})
	if st != http.StatusCreated {
		t.Fatalf("create owner2 = %d: %s", st, body)
	}
	owner2 := decode(t, body)["id"].(string)
	if st, _, body = do(t, srv, "PUT", "/api/v1/owners/"+owner2, reqOpts{tenant: tenantA, idem: "o2u", body: map[string]any{"kind": "workload", "name": "payments-v2"}}); st != http.StatusOK {
		t.Fatalf("update owner2 = %d: %s", st, body)
	}

	st, _, body = do(t, srv, "POST", "/api/v1/issuers", reqOpts{tenant: tenantA, idem: "i1", body: map[string]any{"kind": "x509_ca", "name": "Acme CA", "chain": []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}}})
	if st != http.StatusCreated {
		t.Fatalf("create issuer = %d: %s", st, body)
	}
	issuerID = decode(t, body)["id"].(string)

	st, _, body = do(t, srv, "POST", "/api/v1/identities", reqOpts{tenant: tenantA, idem: "id1", body: map[string]any{"kind": "x509_certificate", "name": "svc-cred", "owner_id": ownerID, "issuer_id": issuerID, "attributes": map[string]any{"cn": "svc.acme.test"}}})
	if st != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", st, body)
	}
	identityID = decode(t, body)["id"].(string)
	if st, _, body = do(t, srv, "POST", "/api/v1/identities/"+identityID+"/transitions", reqOpts{tenant: tenantA, idem: "t1", body: map[string]any{"to": "issued"}}); st != http.StatusOK {
		t.Fatalf("transition identity = %d: %s", st, body)
	}

	cpem := leafPEM(t, "svc.acme.test")
	if st, _, body = do(t, srv, "POST", "/api/v1/certificates", reqOpts{tenant: tenantA, idem: "c1", body: map[string]any{"pem": cpem, "deployment_location": "edge-a"}}); st != http.StatusCreated {
		t.Fatalf("ingest cert = %d: %s", st, body)
	}
	// Re-ingest the same certificate (same fingerprint) with a new location: an
	// upsert, so it stays one row but emits a second event.
	if st, _, body = do(t, srv, "POST", "/api/v1/certificates", reqOpts{tenant: tenantA, idem: "c2", body: map[string]any{"pem": cpem, "deployment_location": "edge-b"}}); st != http.StatusCreated {
		t.Fatalf("re-ingest cert = %d: %s", st, body)
	}
	return ownerID, issuerID, identityID
}

// TestServedReadModelIsAProjectionOfTheLog is the AN-2 acceptance (closing audit
// B7): after every served mutation, emptying the read model and replaying the
// event log reconstructs the identical read model. If any served mutation wrote
// the read table directly instead of emitting an event, the replay would not
// reproduce it and the snapshots would differ.
func TestServedReadModelIsAProjectionOfTheLog(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	srv, s, log := esServer(t)
	ctx := context.Background()

	seedReadModel(t, srv)

	// The live read model is non-empty across every served entity.
	if no, ni, nd, nc := countReadModel(t, s); no < 2 || ni < 1 || nd < 1 || nc != 1 {
		t.Fatalf("seeded read model = owners %d, issuers %d, identities %d, certs %d; want >=2,>=1,>=1,==1", no, ni, nd, nc)
	}
	before := readModelSnapshot(t, s)

	// Empty the read model: it now holds nothing of its own.
	if err := s.TruncateReadModel(ctx); err != nil {
		t.Fatalf("TruncateReadModel: %v", err)
	}
	if no, ni, nd, nc := countReadModel(t, s); no+ni+nd+nc != 0 {
		t.Fatalf("after truncate, read model not empty: owners %d, issuers %d, identities %d, certs %d", no, ni, nd, nc)
	}

	// Rebuild the read model purely from the event log.
	if err := projections.New(s).Project(ctx, log); err != nil {
		t.Fatalf("Project (rebuild from log): %v", err)
	}
	after := readModelSnapshot(t, s)

	if before != after {
		t.Errorf("rebuild from the event log did not reproduce the read model.\n--- live ---\n%s\n--- rebuilt ---\n%s", before, after)
	}
}

// TestEveryServedMutationEmitsExactlyOneEvent asserts the served mutations are
// the source of the events (one event each), and that an idempotent replay of a
// mutation does NOT emit a second event.
func TestEveryServedMutationEmitsExactlyOneEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	srv, _, log := esServer(t)
	ctx := context.Background()

	ownerID, _, _ := seedReadModel(t, srv)

	counts := countEventTypes(t, ctx, log)
	want := map[string]int{
		"owner.created":        2,
		"owner.updated":        1,
		"issuer.created":       1,
		"identity.created":     1,
		"identity.issued":      1,
		"certificate.recorded": 2,
	}
	for typ, n := range want {
		if counts[typ] != n {
			t.Errorf("event %q count = %d, want %d (all counts: %v)", typ, counts[typ], n, counts)
		}
	}

	// An idempotent replay (same Idempotency-Key as owner1) must return the
	// original result and emit NO new event.
	st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "o1", body: map[string]any{"kind": "service", "name": "billing", "email": "ops@acme.test"}})
	if st != http.StatusCreated {
		t.Fatalf("idempotent replay = %d: %s", st, body)
	}
	if got := decode(t, body)["id"].(string); got != ownerID {
		t.Errorf("idempotent replay returned a different id %q, want original %q", got, ownerID)
	}
	if again := countEventTypes(t, ctx, log)["owner.created"]; again != 2 {
		t.Errorf("idempotent replay emitted a duplicate event: owner.created = %d, want 2", again)
	}
}

func countEventTypes(t *testing.T, ctx context.Context, log *events.Log) map[string]int {
	t.Helper()
	counts := map[string]int{}
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		counts[e.Type]++
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return counts
}
