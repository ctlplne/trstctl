package query_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trustctl.io/trustctl/internal/authz"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/query"
	"trustctl.io/trustctl/internal/store"
)

// The adversarial suite (SF.7): the security boundary is proven against a live,
// two-tenant control plane on real Postgres (RLS) + embedded NATS — never mocked.

const (
	tenantA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// foreignMarkers are substrings unique to the OTHER tenant's seeded data; no row a
// principal receives may contain one.
var foreignMarkers = map[string][]string{
	tenantA: {"beta", "b.svc", "B0", "fb0", tenantB},
	tenantB: {"alpha", "a.svc", "A0", "fa0", tenantA},
}

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trustctl-query-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(os.TempDir() + "/trustctl-pg-bin").
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
	if _, err := s.Pool().Exec(ctx,
		`TRUNCATE tenants, owners, certificates, crypto_assets, identities, issuers
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
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

// seed populates both tenants with distinguishable inventory, CBOM, and log events,
// and returns a built engine.
func seed(t *testing.T) (*query.Engine, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)

	type fix struct {
		tenant, who, svc, serial, fp, alg, loc string
	}
	for _, f := range []fix{
		{tenantA, "alpha-owner", "CN=a.svc", "A01", "fa01", "RSA", "a:443"},
		{tenantB, "beta-owner", "CN=b.svc", "B01", "fb01", "ECDSA", "b:443"},
	} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: f.tenant, Name: f.who}); err != nil {
			t.Fatalf("UpsertTenant: %v", err)
		}
		owner, err := st.CreateOwner(ctx, store.Owner{TenantID: f.tenant, Kind: store.OwnerKind("workload"), Name: f.who})
		if err != nil {
			t.Fatalf("CreateOwner: %v", err)
		}
		oid := owner.ID
		na := time.Now().Add(24 * time.Hour)
		if _, err := st.UpsertCertificate(ctx, store.Certificate{
			TenantID: f.tenant, OwnerID: &oid, Subject: f.svc, Serial: f.serial,
			Fingerprint: f.fp, KeyAlgorithm: "ECDSA-P256", NotAfter: &na, Source: "issued",
		}); err != nil {
			t.Fatalf("UpsertCertificate: %v", err)
		}
		if _, err := st.UpsertCryptoAsset(ctx, store.CryptoAsset{
			TenantID: f.tenant, Kind: "tls", Location: f.loc, Algorithm: f.alg, Library: "openssl", Strength: "ok",
		}); err != nil {
			t.Fatalf("UpsertCryptoAsset: %v", err)
		}
		if _, err := log.Append(ctx, events.Event{Type: "owner.created", TenantID: f.tenant, Data: []byte(`{}`)}); err != nil {
			t.Fatalf("log.Append: %v", err)
		}
	}
	return query.New(st, log, nil, query.Config{MaxRows: 500, MaxDepth: 6, Timeout: 5 * time.Second}), st
}

func admin(tenant string) authz.Principal {
	return authz.Principal{TenantID: tenant, Subject: "admin",
		Grants: []authz.Grant{{Role: authz.BuiltinRoles()["admin"], Scope: authz.Scope{TenantID: tenant}}}}
}

func allSurfaces() []query.Surface {
	return []query.Surface{query.SurfaceOwners, query.SurfaceCertificates, query.SurfaceGraph, query.SurfaceCBOM, query.SurfaceLog}
}

func assertNoForeignRows(t *testing.T, tenant string, rows []query.Row) {
	t.Helper()
	for _, r := range rows {
		// Log rows carry the tenant explicitly — the strongest check.
		if r.Surface == query.SurfaceLog {
			if r.Columns["tenant_id"] != tenant {
				t.Errorf("log row leaked tenant %q to caller %q", r.Columns["tenant_id"], tenant)
			}
		}
		for col, v := range r.Columns {
			for _, marker := range foreignMarkers[tenant] {
				if marker != "" && strings.Contains(v, marker) {
					t.Errorf("row %s.%s=%q leaked a foreign-tenant marker %q to caller %q", r.Surface, col, v, marker, tenant)
				}
			}
		}
	}
}

// TestCrossTenantReturnsNothingByConstruction is the defining test: a caller in one
// tenant cannot see any of the other tenant's rows across any surface — and even a
// query deliberately filtered by the other tenant's owner id returns nothing,
// because the RLS floor confines the read regardless of the predicate.
func TestCrossTenantReturnsNothingByConstruction(t *testing.T) {
	e, st := seed(t)
	ctx := context.Background()

	// Find tenant B's owner id, then have a tenant-A principal try to use it.
	var bOwnerID string
	if owners, err := st.ListOwners(ctx, tenantB); err != nil || len(owners) == 0 {
		t.Fatalf("seed B owners: %v (n=%d)", err, len(owners))
	} else {
		bOwnerID = owners[0].ID
	}

	res, err := e.Query(ctx, admin(tenantA), query.Spec{Select: allSurfaces()})
	if err != nil {
		t.Fatalf("A query: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("A query returned nothing; seed/scoping is broken")
	}
	assertNoForeignRows(t, tenantA, res.Rows)

	// Deliberately feed B's owner id as a certificate filter from tenant A: RLS makes
	// it return zero, by construction (not post-filtering).
	res2, err := e.Query(ctx, admin(tenantA), query.Spec{
		Select: []query.Surface{query.SurfaceCertificates},
		Where:  []query.Predicate{{Field: query.FieldOwnerID, Op: query.OpEq, Value: bOwnerID}},
	})
	if err != nil {
		t.Fatalf("A cross-id query: %v", err)
	}
	if len(res2.Rows) != 0 {
		t.Errorf("a tenant-A query filtered by tenant-B's owner id returned %d rows; want 0", len(res2.Rows))
	}
}

// TestPropertyNoQueryPathLeaksOutOfScope is the core security property: across many
// randomized principals (either tenant) and randomized specs, no returned row ever
// belongs to another tenant.
func TestPropertyNoQueryPathLeaksOutOfScope(t *testing.T) {
	e, _ := seed(t)
	ctx := context.Background()
	surfaces := allSurfaces()
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 300; i++ {
		tenant := tenantA
		if rng.Intn(2) == 0 {
			tenant = tenantB
		}
		// A random non-empty subset of surfaces.
		var sel []query.Surface
		for _, s := range surfaces {
			if rng.Intn(2) == 0 {
				sel = append(sel, s)
			}
		}
		if len(sel) == 0 {
			sel = []query.Surface{surfaces[rng.Intn(len(surfaces))]}
		}
		res, err := e.Query(ctx, admin(tenant), query.Spec{Select: sel, Limit: rng.Intn(200)})
		if err != nil {
			t.Fatalf("iter %d tenant %s: %v", i, tenant, err)
		}
		assertNoForeignRows(t, tenant, res.Rows)
	}
}

// TestJoinAcrossSurfaces is the positive acceptance: a single query joins across at
// least the event log, the graph, and the inventory and returns a correct, fully
// tenant-A-scoped result.
func TestJoinAcrossSurfaces(t *testing.T) {
	e, _ := seed(t)
	res, err := e.Query(context.Background(), admin(tenantA), query.Spec{Select: allSurfaces()})
	if err != nil {
		t.Fatalf("join query: %v", err)
	}
	seen := map[query.Surface]bool{}
	for _, r := range res.Rows {
		seen[r.Surface] = true
	}
	for _, s := range []query.Surface{query.SurfaceLog, query.SurfaceGraph, query.SurfaceOwners, query.SurfaceCertificates} {
		if !seen[s] {
			t.Errorf("join result missing rows from surface %q", s)
		}
	}
	if res.Offset == 0 {
		t.Error("result should report a non-zero log offset (AN-2 consistency pin)")
	}
	assertNoForeignRows(t, tenantA, res.Rows)
}

// TestRBACViewerCannotReadLog: a viewer (no audit:read) is denied the log surface at
// this layer, but can read the surfaces it is granted.
func TestRBACViewerCannotReadLog(t *testing.T) {
	e, _ := seed(t)
	ctx := context.Background()
	viewer := authz.Principal{TenantID: tenantA, Subject: "v",
		Grants: []authz.Grant{{Role: authz.BuiltinRoles()["viewer"], Scope: authz.Scope{TenantID: tenantA}}}}

	if _, err := e.Query(ctx, viewer, query.Spec{Select: []query.Surface{query.SurfaceLog}}); err != query.ErrForbidden {
		t.Errorf("viewer reading the log should be ErrForbidden, got %v", err)
	}
	res, err := e.Query(ctx, viewer, query.Spec{Select: []query.Surface{query.SurfaceOwners, query.SurfaceCertificates}})
	if err != nil {
		t.Fatalf("viewer reading granted surfaces: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Error("viewer should see its tenant's owners/certificates")
	}
}

// TestDeadlineGuardTrips: an impossibly small wall-clock budget fails closed rather
// than returning a partial result.
func TestDeadlineGuardTrips(t *testing.T) {
	e, st := seed(t)
	tight := query.New(st, nil, nil, query.Config{MaxRows: 500, MaxDepth: 6, Timeout: time.Nanosecond})
	_, err := e.Query(context.Background(), admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceOwners}})
	if err != nil { // the normal engine still works
		t.Fatalf("baseline query: %v", err)
	}
	if _, err := tight.Query(context.Background(), admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceOwners}}); err != query.ErrDeadline {
		t.Errorf("a 1ns budget must trip the deadline guard, got %v", err)
	}
}
