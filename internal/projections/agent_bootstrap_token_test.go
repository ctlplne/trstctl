package projections_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// dbTokenStore adapts the PostgreSQL store to enroll.TokenStore for these
// integration tests — the same adapter the served binary uses (server.storeTokenStore),
// reconstructed here so the enroll.Authority is exercised over REAL durable
// storage, not the in-memory store. A redemption miss (unknown/expired/used) maps
// to enroll.ErrBadToken.
type dbTokenStore struct{ st *store.Store }

func (d dbTokenStore) Save(ctx context.Context, t enroll.MintedToken) error {
	_, err := d.st.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:        t.TenantID,
		TokenHash:       t.TokenHash,
		AllowedIdentity: t.AllowedIdentity,
		ExpiresAt:       t.ExpiresAt,
	})
	return err
}

func (d dbTokenStore) Redeem(ctx context.Context, tokenHash string) (enroll.RedeemedToken, error) {
	rec, err := d.st.RedeemBootstrapToken(ctx, tokenHash)
	if err != nil {
		if store.IsNotFound(err) {
			return enroll.RedeemedToken{}, enroll.ErrBadToken
		}
		return enroll.RedeemedToken{}, err
	}
	return enroll.RedeemedToken{TenantID: rec.TenantID, AllowedIdentity: rec.AllowedIdentity}, nil
}

func bootstrapCSR(t *testing.T, cn string) []byte {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestDurableBootstrapTokenTenantAttributed is the WIRE-003 durable-store
// acceptance: a token minted (and persisted) under tenant A yields a client
// certificate stamped with tenant A's SPIFFE SAN. The attribution flows through
// real PostgreSQL, not a process-local map.
func TestDurableBootstrapTokenTenantAttributed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	a, err := enroll.NewAuthority("cp", dbTokenStore{s})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := a.EnrollBootstrap(ctx, tok, bootstrapCSR(t, "edge-agent"))
	if err != nil {
		t.Fatalf("EnrollBootstrap: %v", err)
	}
	der, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mtls.TenantFromClientCert(der)
	if err != nil {
		t.Fatalf("TenantFromClientCert: %v", err)
	}
	if got != tenantA {
		t.Errorf("issued cert carries tenant %q, want %q (durable, not header-derived)", got, tenantA)
	}
}

// TestDurableBootstrapTokenSingleUseAcrossInstances is the WIRE-003 multi-instance
// + restart acceptance: a token minted on one control-plane instance is redeemed
// on a SECOND instance (a separate *store.Store over the same database), and a
// second redemption — on either instance — is rejected. This is exactly what the
// old process-local map[string]bool could not do: it lost the token on restart
// and could not share it across instances.
func TestDurableBootstrapTokenSingleUseAcrossInstances(t *testing.T) {
	ctx := context.Background()

	// Instance 1 mints the token (and persists it durably).
	s1 := newStore(t) // newStore truncates once; both handles share the same DB
	a1, err := enroll.NewAuthority("cp-1", dbTokenStore{s1})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a1.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}

	// Instance 2 is a fresh control plane (separate store handle, separate
	// in-process CA) — modeling both a second replica AND a restart of instance 1.
	s2, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("open second instance: %v", err)
	}
	t.Cleanup(s2.Close)
	a2, err := enroll.NewAuthority("cp-2", dbTokenStore{s2})
	if err != nil {
		t.Fatal(err)
	}

	// The token survives and redeems once on the second instance.
	chain, err := a2.EnrollBootstrap(ctx, tok, bootstrapCSR(t, "agent"))
	if err != nil {
		t.Fatalf("token minted on instance 1 should redeem on instance 2: %v", err)
	}
	der, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := mtls.TenantFromClientCert(der); got != tenantA {
		t.Errorf("cert from instance 2 carries tenant %q, want %q", got, tenantA)
	}

	// A second redemption is rejected on instance 2 (single-use)...
	if _, err := a2.EnrollBootstrap(ctx, tok, bootstrapCSR(t, "agent")); err == nil {
		t.Error("second redemption on instance 2 should be rejected (single-use)")
	}
	// ...and ALSO on instance 1 — the single-use is global, not per-instance.
	if _, err := a1.EnrollBootstrap(ctx, tok, bootstrapCSR(t, "agent")); err == nil {
		t.Error("redemption on instance 1 of a token already spent on instance 2 should be rejected")
	}
}

// TestDurableBootstrapTokenTenantIsolation is the AN-1 cross-tenant guard: a token
// minted under tenant A is, when redeemed, only ever attributed to tenant A — never
// tenant B — and tenant B's RLS context cannot see tenant A's token row.
func TestDurableBootstrapTokenTenantIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	a, err := enroll.NewAuthority("cp", dbTokenStore{s})
	if err != nil {
		t.Fatal(err)
	}

	// Mint one token per tenant.
	tokA, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := a.IssueBootstrapToken(ctx, tenantB, "")
	if err != nil {
		t.Fatal(err)
	}

	// Each redeems to its own tenant — no bleed.
	for tok, want := range map[string]string{tokA: tenantA, tokB: tenantB} {
		chain, err := a.EnrollBootstrap(ctx, tok, bootstrapCSR(t, "agent"))
		if err != nil {
			t.Fatalf("EnrollBootstrap(%s): %v", want, err)
		}
		der, _ := mtls.FirstCertDER(chain)
		got, err := mtls.TenantFromClientCert(der)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("token minted for %s yielded a cert attributed to %s", want, got)
		}
	}

	// RLS proof: tenant B's context sees zero of tenant A's bootstrap-token rows.
	// (Both tokens were just consumed, so re-mint one for tenant A and count under B.)
	if _, err := a.IssueBootstrapToken(ctx, tenantA, ""); err != nil {
		t.Fatal(err)
	}
	var sawA int
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM agent_bootstrap_tokens WHERE tenant_id = $1", tenantA).Scan(&sawA)
	}); err != nil {
		t.Fatalf("WithTenant(B): %v", err)
	}
	if sawA != 0 {
		t.Errorf("tenant B can see %d of tenant A's bootstrap tokens; RLS must hide them", sawA)
	}
}

// freshToken mints a random raw bootstrap-token secret and its SHA-256 hex hash
// (the form the store persists), so a test can insert a row directly.
func freshToken(t *testing.T) (raw, hash string) {
	t.Helper()
	b, err := crypto.RandomBytes(24)
	if err != nil {
		t.Fatal(err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum, err := crypto.Digest(crypto.SHA256, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return raw, hex.EncodeToString(sum)
}

// TestBootstrapTokenExpiryRejected: an expired token is rejected even though it
// exists in the store (the conditional redeem checks expires_at).
func TestBootstrapTokenExpiryRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Insert a token that is already expired, then attempt to redeem it.
	raw, hash := freshToken(t)
	if _, err := s.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:  tenantA,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateBootstrapToken: %v", err)
	}
	_ = raw
	if _, err := s.RedeemBootstrapToken(ctx, hash); !store.IsNotFound(err) {
		t.Fatalf("expired token redeem = %v, want not-found (expired)", err)
	}
}
