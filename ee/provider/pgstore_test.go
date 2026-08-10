// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

// The durable half of L3, against real PostgreSQL: a provider's customer list
// survives a restart (the MemStore lost it on every deploy), and the
// per-customer health view counts a customer's active certificates under THAT
// customer's RLS context — never bleeding another customer's inventory in.

var providerTestDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-provider-pg")
	if err != nil {
		panic(err)
	}
	port := providerFreePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(port).
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
	providerTestDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func providerFreePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p <= 0 || p > math.MaxUint16 {
		panic("no free port")
	}
	return uint32(p)
}

// openProviderStore opens a migrated store and clears the registry so each test
// starts from an empty customer list. It returns the core store; the caller
// wraps it in whatever PGStore instances the scenario needs.
func openProviderStore(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	s, err := corestore.Open(ctx, providerTestDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE provider_tenants, provider_breakglass_grants, certificates RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// projectAuthorityFixture creates a derived provider row through the same
// projection that owns production writes. These read-store tests do not get a
// hidden PostgreSQL mutation API merely for fixture setup.
func projectAuthorityFixture(t *testing.T, st *corestore.Store, typ, tenantID string, payload AuthorityEvent) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s fixture: %v", typ, err)
	}
	if err := NewAuthorityProjection(st).Apply(t.Context(), events.Event{
		ID:   "fixture-" + typ + "-" + tenantID,
		Type: typ, TenantID: tenantID, Time: time.Now().UTC(), Data: data,
	}); err != nil {
		t.Fatalf("project %s fixture: %v", typ, err)
	}
}

func projectTenantFixture(t *testing.T, st *corestore.Store, tenant Tenant) {
	t.Helper()
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now().UTC()
	}
	if tenant.UpdatedAt.IsZero() {
		tenant.UpdatedAt = tenant.CreatedAt
	}
	projectAuthorityFixture(t, st, AuditTenantProvisioned, tenant.ID, AuthorityEvent{
		Tenant: &tenant, Audit: AuditEvent{Type: AuditTenantProvisioned, TenantID: tenant.ID, At: tenant.CreatedAt},
	})
}

func projectGrantFixture(t *testing.T, st *corestore.Store, typ string, grant BreakGlassGrant) {
	t.Helper()
	projectAuthorityFixture(t, st, typ, grant.TenantID, AuthorityEvent{
		Grant: &grant, Audit: AuditEvent{Type: typ, TenantID: grant.TenantID, GrantID: grant.ID, At: grant.RequestedAt},
	})
}

// A provider provisions a customer, then the process restarts. The customer —
// and the break-glass grant recorded against them — must still be there, read
// through a brand-new store handle that shares nothing but the database.
func TestProviderRegistrySurvivesARestart(t *testing.T) {
	ctx := context.Background()

	// First "process": provision a customer and record a break-glass grant.
	s1 := openProviderStore(t)
	id := CustomerID("acme")
	projectTenantFixture(t, s1, Tenant{ID: id, Slug: "acme", Name: "Acme Corp", Status: TenantActive})
	grant := BreakGlassGrant{
		ID: "bg-1", TenantID: id, OperatorID: "op-1", OperatorEmail: "op@example.test",
		Reason: "customer requested emergency diagnosis", RequestedAt: time.Unix(1700, 0).UTC(),
		ExpiresAt: time.Unix(5000, 0).UTC(),
	}
	projectGrantFixture(t, s1, AuditBreakGlassRequested, grant)
	s1.Close()

	// Second "process": a fresh store handle over the same database.
	s2, err := corestore.Open(ctx, providerTestDSN)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	reader := NewPGStore(s2)

	tenants, err := reader.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants after restart: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != id || tenants[0].Slug != "acme" {
		t.Fatalf("customer list after restart = %+v, want the one provisioned customer", tenants)
	}
	if n, err := reader.CountBillableTenants(ctx); err != nil || n != 1 {
		t.Fatalf("CountBillableTenants after restart = %d (err %v), want 1", n, err)
	}
	got, err := reader.BreakGlassGrant(ctx, "bg-1")
	if err != nil {
		t.Fatalf("BreakGlassGrant after restart: %v", err)
	}
	if got.TenantID != id || got.Reason != grant.Reason {
		t.Fatalf("break-glass grant after restart = %+v, want the recorded grant", got)
	}
}

// Both approvers' consents survive a restart: a grant that reached two-person
// approval reads back active through a fresh store handle, not silently
// downgraded to awaiting a co-approver because the second consent was dropped.
func TestBreakGlassDualConsentIsDurable(t *testing.T) {
	ctx := context.Background()
	s1 := openProviderStore(t)
	id := CustomerID("bgc")
	projectTenantFixture(t, s1, Tenant{ID: id, Slug: "bgc", Name: "BG Corp", Status: TenantActive})
	base := time.Unix(1000, 0).UTC()
	projectGrantFixture(t, s1, AuditBreakGlassRequested, BreakGlassGrant{
		ID: "bg-dual", TenantID: id, OperatorID: "requester", Reason: "incident",
		RequestedAt: base, ExpiresAt: base.Add(time.Hour),
	})
	// Record both consents, from two distinct approvers, and persist them.
	both := BreakGlassGrant{
		ID: "bg-dual", TenantID: id, OperatorID: "requester", Reason: "incident",
		RequestedAt: base, ExpiresAt: base.Add(time.Hour),
		ConsentedAt: base.Add(time.Minute), ConsentedBy: "approver-a",
		SecondConsentedAt: base.Add(2 * time.Minute), SecondConsentedBy: "approver-b",
	}
	projectGrantFixture(t, s1, AuditBreakGlassConsented, both)
	s1.Close()

	s2, err := corestore.Open(ctx, providerTestDSN)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	got, err := NewPGStore(s2).BreakGlassGrant(ctx, "bg-dual")
	if err != nil {
		t.Fatalf("BreakGlassGrant after restart: %v", err)
	}
	if got.ConsentedBy != "approver-a" || got.SecondConsentedBy != "approver-b" || got.SecondConsentedAt.IsZero() {
		t.Fatalf("consents after restart = %+v, want both approvers persisted", got)
	}
	if st := got.State(base.Add(3 * time.Minute)); st != GrantActive {
		t.Fatalf("state after restart = %q, want active (both consents durable)", st)
	}
}

// The per-customer health view counts a customer's OWN active certificates,
// under that customer's RLS context, and derives health from status. A
// certificate belonging to another customer must not be counted — the count is
// a per-tenant read confined exactly like any other.
func TestDirectTenantSnapshotCountsActiveCertificatesUnderRLS(t *testing.T) {
	ctx := context.Background()
	s := openProviderStore(t)
	store := NewPGStore(s)

	beta := CustomerID("beta")
	other := CustomerID("other")
	for _, id := range []string{beta, other} {
		projectTenantFixture(t, s, Tenant{ID: id, Slug: id, Name: id, Status: TenantActive})
	}
	// beta: two active certificates and one revoked. other: one active cert
	// that must NOT leak into beta's count.
	seedCert(t, s, beta, "beta-a", "active")
	seedCert(t, s, beta, "beta-b", "active")
	seedCert(t, s, beta, "beta-c", "revoked")
	seedCert(t, s, other, "other-a", "active")

	snap, err := store.DirectTenantSnapshot(ctx, beta)
	if err != nil {
		t.Fatalf("DirectTenantSnapshot(beta): %v", err)
	}
	if snap.ActiveCertificates != 2 {
		t.Fatalf("beta active certificates = %d, want 2 (revoked excluded, other's cert not leaked)", snap.ActiveCertificates)
	}
	if snap.Health != "healthy" {
		t.Fatalf("beta health = %q, want healthy", snap.Health)
	}

	// A customer with a registry status of suspended reports degraded, whatever
	// their certificate count.
	gamma := CustomerID("gamma")
	projectTenantFixture(t, s, Tenant{ID: gamma, Slug: "gamma", Name: "gamma", Status: TenantSuspended})
	if snap, err := store.DirectTenantSnapshot(ctx, gamma); err != nil || snap.Health != "suspended" {
		t.Fatalf("gamma snapshot = %+v (err %v), want health suspended", snap, err)
	}

	// An active customer with no certificates is reported as "no certificates",
	// not silently healthy.
	delta := CustomerID("delta")
	projectTenantFixture(t, s, Tenant{ID: delta, Slug: "delta", Name: "delta", Status: TenantActive})
	if snap, err := store.DirectTenantSnapshot(ctx, delta); err != nil || snap.Health != "no_certificates" || snap.ActiveCertificates != 0 {
		t.Fatalf("delta snapshot = %+v (err %v), want no_certificates/0", snap, err)
	}
}

// seedCert inserts one certificate for tenantID under that tenant's RLS context,
// proving the row is written the same confined way a real issuance would be.
func seedCert(t *testing.T, s *corestore.Store, tenantID, fingerprint, status string) {
	t.Helper()
	certID := CustomerID("cert:" + fingerprint) // any stable uuid; identity is per-fingerprint
	if err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO certificates (id, tenant_id, subject, fingerprint, status)
			 VALUES ($1, $2, $3, $4, $5)`,
			certID, tenantID, "CN="+fingerprint, fingerprint, status)
		return err
	}); err != nil {
		t.Fatalf("seed certificate %s: %v", fingerprint, err)
	}
}
