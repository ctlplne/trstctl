package store_test

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

	"trstctl.com/trstctl/internal/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL for the store integration tests
// (no external service, no mocks) so OffboardTenant's RLS-scoped erase is exercised
// against the same FORCE-d row-level security the product runs under.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-store-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin"). // per-package, not a shared /tmp dir: parallel `go test ./...` packages race the file-by-file extraction into a shared BinariesPath
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
	// Per-test isolation: the package shares one database, so reset every
	// tenant-scoped table (and the operational tables) between tests.
	if _, err := s.Pool().Exec(ctx,
		`TRUNCATE tenants, idempotency_keys, outbox, rate_limits,
		          owners, issuers, identities, identity_transitions, deployment_targets,
		          agents, agent_bootstrap_tokens, policy_bindings, attestations, api_tokens, certificates,
		          ca_authorities, ca_key_ceremonies, ca_ceremony_approvals,
		          ca_issued_certs, ca_crls, ssh_keys, ct_watched_domains, ct_log_checkpoints,
		          crypto_assets, credentials, audit_checkpoints, certificate_profiles,
		          issuance_approval_requests, issuance_approvals
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedTenant inserts a representative spread of tenant-scoped rows for tenantID,
// including a parent→child FK relationship (owner ← identity, owner ← certificate)
// so the offboarding's FK-ordered erase is genuinely exercised, plus a "sealed
// secret" (credentials), an SSH key, an API token, and a revocation row.
func seedTenant(t *testing.T, s *store.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	ownerID := uuid(tenantID, 1)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name) VALUES ($1,$2,'Service','seed')`,
			ownerID, tenantID); err != nil {
			return err
		}
		// identity references owner (FK RESTRICT) → proves the erase deletes children first.
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities (id, tenant_id, kind, name, owner_id) VALUES ($1,$2,'x509','id',$3)`,
			uuid(tenantID, 2), tenantID, ownerID); err != nil {
			return err
		}
		// certificate references owner (FK RESTRICT).
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, fingerprint)
			 VALUES ($1,$2,$3,'CN=seed',$4)`,
			uuid(tenantID, 3), tenantID, ownerID, "fp-"+tenantID); err != nil {
			return err
		}
		// a sealed secret (the data-deletion concern).
		if _, err := tx.Exec(ctx,
			`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
			 VALUES ($1,$2,'issuer','ref','api_key',$3)`,
			uuid(tenantID, 4), tenantID, []byte("ciphertext")); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ssh_keys (id, tenant_id, fingerprint) VALUES ($1,$2,$3)`,
			uuid(tenantID, 5), tenantID, "ssh-"+tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject) VALUES ($1,$2,$3,'svc')`,
			uuid(tenantID, 6), tenantID, "hash-"+tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ca_issued_certs (tenant_id, ca_id, serial) VALUES ($1,$2,'01')`,
			tenantID, uuid(tenantID, 7)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("seed tenant %s: %v", tenantID, err)
	}
}

// countTenantRows returns the number of rows visible for tenantID across the
// seeded tables, read under that tenant's RLS context.
func countTenantRows(t *testing.T, s *store.Store, tenantID string) int {
	t.Helper()
	ctx := context.Background()
	total := 0
	tables := []string{"owners", "identities", "certificates", "credentials", "ssh_keys", "api_tokens", "ca_issued_certs"}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, tbl := range tables {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil {
				return err
			}
			total += n
		}
		return nil
	}); err != nil {
		t.Fatalf("count tenant %s: %v", tenantID, err)
	}
	return total
}

// TestOffboardTenantErasesOnlyThatTenant is the TENANT-002 acceptance: seed two
// tenants, offboard A, and assert every seeded surface is empty for A (and the
// attestation reports a complete erase with zero residue) while B's rows are
// intact. It fails on the pre-fix tree (no OffboardTenant) and passes after.
func TestOffboardTenantErasesOnlyThatTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)

	if got := countTenantRows(t, s, tenantA); got == 0 {
		t.Fatal("precondition: tenant A should have seeded rows")
	}
	bBefore := countTenantRows(t, s, tenantB)

	att, err := s.OffboardTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("OffboardTenant(A): %v", err)
	}
	if !att.Complete {
		t.Errorf("attestation not complete: %+v", att)
	}
	if att.Total == 0 {
		t.Error("attestation reports 0 rows deleted; expected the seeded rows")
	}
	if len(att.Residue) != 0 {
		t.Errorf("attestation reports residue after erase: %v", att.Residue)
	}
	// Every seeded table must have a recorded delete count (the deletion proof).
	for _, tbl := range []string{"owners", "identities", "certificates", "credentials", "ssh_keys", "api_tokens", "ca_issued_certs", "tenants"} {
		if _, ok := att.Deleted[tbl]; !ok {
			t.Errorf("attestation missing a delete count for %s", tbl)
		}
	}

	// A's surfaces are empty (read under A's own RLS context).
	if got := countTenantRows(t, s, tenantA); got != 0 {
		t.Errorf("after offboarding, tenant A still has %d rows; want 0", got)
	}
	// A's tenant row is gone too (system view).
	if _, err := s.GetTenant(ctx, tenantA); !store.IsNotFound(err) {
		t.Errorf("tenant A's row should be gone after offboarding; GetTenant err = %v", err)
	}
	// B is untouched.
	if got := countTenantRows(t, s, tenantB); got != bBefore || got == 0 {
		t.Errorf("tenant B rows changed by A's offboarding: got %d, want %d (and >0)", got, bBefore)
	}
	if _, err := s.GetTenant(ctx, tenantB); err != nil {
		t.Errorf("tenant B's row must survive A's offboarding: %v", err)
	}
}

// TestOffboardTenantRejectsEmptyTenant: an empty tenant id is rejected (fail
// closed) — under RLS it would match nothing and silently "succeed", which for a
// deletion path is the fail-open we refuse.
func TestOffboardTenantRejectsEmptyTenant(t *testing.T) {
	s := newStore(t)
	if _, err := s.OffboardTenant(context.Background(), ""); err == nil {
		t.Error("OffboardTenant(\"\") must fail closed, not silently no-op")
	}
}

// TestOffboardTenantIsIdempotent: offboarding an already-erased tenant is a safe
// no-op (every count 0, still Complete), so replaying the tenant.offboarded event
// on a rebuild does not error.
func TestOffboardTenantIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	seedTenant(t, s, tenantA)
	if _, err := s.OffboardTenant(ctx, tenantA); err != nil {
		t.Fatalf("first offboard: %v", err)
	}
	att, err := s.OffboardTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("second offboard (should be a no-op): %v", err)
	}
	if !att.Complete || att.Total != 0 {
		t.Errorf("re-offboard should delete 0 rows and be complete; got %+v", att)
	}
}

// uuid builds a deterministic uuid for a tenant + a small ordinal, so seeded rows
// have stable, distinct primary keys without importing a uuid library.
func uuid(tenantID string, n int) string {
	// tenantID is "11111111-1111-1111-1111-111111111111" form; swap the last block
	// for a per-row suffix so the ids are valid and unique within the tenant.
	return tenantID[:24] + fmt.Sprintf("%012d", n)
}
