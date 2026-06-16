package authmethod

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// oidcFixture builds a signer, a single-key JWKS, and a fixed clock for the OIDC
// claim tests.
type oidcFixture struct {
	signer *crypto.LockedSigner
	jwks   crypto.JWKS
	kid    string
	now    time.Time
}

func newOIDCFixture(t *testing.T) oidcFixture {
	t.Helper()
	s, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Destroy)
	jwk, err := crypto.PublicJWK(s.Public(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	return oidcFixture{
		signer: s,
		jwks:   crypto.JWKS{Keys: []crypto.JWK{jwk}},
		kid:    "k1",
		now:    time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
	}
}

func (f oidcFixture) sign(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	tok, err := crypto.SignJWT(f.signer, f.kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

func (f oidcFixture) method() OIDCMethod {
	return OIDCMethod{
		JWKS:     f.jwks,
		Issuer:   "https://issuer.example",
		Audience: "trstctl",
		Now:      func() time.Time { return f.now },
	}
}

// TestProbe_OIDC_FutureNbf_Rejected is the regression for GAP-003: a token whose
// nbf is far in the future must be rejected NOW (pre-fix it was accepted because
// nbf was never read).
func TestProbe_OIDC_FutureNbf_Rejected(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "spiffe://acme/svc",
		"exp": f.now.Add(72 * time.Hour).Unix(),
		"nbf": f.now.Add(48 * time.Hour).Unix(), // not valid until +48h
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err == nil {
		t.Fatal("future-nbf token accepted; want rejection")
	}
}

// A nbf within the leeway window is accepted (small clock skew tolerated).
func TestProbe_OIDC_NbfWithinLeeway_Accepted(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
		"nbf": f.now.Add(10 * time.Second).Unix(), // within defaultLeeway
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err != nil {
		t.Fatalf("nbf-within-leeway token rejected: %v", err)
	}
}

// TestProbe_OIDC_FutureIat_Rejected: a token claiming to be issued in the future
// (beyond leeway) is rejected.
func TestProbe_OIDC_FutureIat_Rejected(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(72 * time.Hour).Unix(),
		"iat": f.now.Add(time.Hour).Unix(),
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err == nil {
		t.Fatal("future-iat token accepted; want rejection")
	}
}

// TestProbe_OIDC_ArrayAud_Accepted is the regression for GAP-003: a token with an
// array audience that includes the expected value must parse and be accepted
// (pre-fix the single-string decode failed closed on an array).
func TestProbe_OIDC_ArrayAud_Accepted(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": []string{"other-service", "trstctl"},
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
	})
	sub, _, err := f.method().Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("array-aud token rejected: %v", err)
	}
	if sub != "svc" {
		t.Fatalf("principal = %q, want svc", sub)
	}
}

// An array audience that does NOT include the expected value is rejected.
func TestProbe_OIDC_ArrayAud_Mismatch_Rejected(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": []string{"a", "b"},
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err == nil {
		t.Fatal("array-aud without expected audience accepted; want rejection")
	}
}

// Single-string audience still works (no regression).
func TestProbe_OIDC_StringAud_Accepted(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err != nil {
		t.Fatalf("string-aud token rejected: %v", err)
	}
}

// TestProbe_OIDC_ReplayedJTI_Rejected is the regression for GAP-003: with a
// replay guard configured, the same jti presented twice is rejected the second
// time.
func TestProbe_OIDC_ReplayedJTI_Rejected(t *testing.T) {
	f := newOIDCFixture(t)
	m := f.method().WithReplayGuard(1024)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
		"jti": "token-abc",
	})
	if _, _, err := m.Authenticate(context.Background(), cred); err != nil {
		t.Fatalf("first presentation rejected: %v", err)
	}
	if _, _, err := m.Authenticate(context.Background(), cred); err == nil {
		t.Fatal("replayed jti accepted; want rejection")
	}
}

// With a replay guard, a token lacking jti is rejected (single-use cannot be
// enforced without one).
func TestProbe_OIDC_ReplayGuard_RequiresJTI(t *testing.T) {
	f := newOIDCFixture(t)
	m := f.method().WithReplayGuard(1024)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(time.Hour).Unix(),
	})
	if _, _, err := m.Authenticate(context.Background(), cred); err == nil {
		t.Fatal("token without jti accepted under replay guard; want rejection")
	}
}

// Distinct jtis are both accepted (the guard rejects only replays).
func TestProbe_OIDC_DistinctJTI_Accepted(t *testing.T) {
	f := newOIDCFixture(t)
	m := f.method().WithReplayGuard(1024)
	for _, jti := range []string{"a", "b", "c"} {
		cred := f.sign(t, map[string]any{
			"iss": "https://issuer.example",
			"aud": "trstctl",
			"sub": "svc",
			"exp": f.now.Add(time.Hour).Unix(),
			"jti": jti,
		})
		if _, _, err := m.Authenticate(context.Background(), cred); err != nil {
			t.Fatalf("distinct jti %q rejected: %v", jti, err)
		}
	}
}

// Expired token still rejected (no regression of the exp check).
func TestProbe_OIDC_Expired_Rejected(t *testing.T) {
	f := newOIDCFixture(t)
	cred := f.sign(t, map[string]any{
		"iss": "https://issuer.example",
		"aud": "trstctl",
		"sub": "svc",
		"exp": f.now.Add(-time.Hour).Unix(),
	})
	if _, _, err := f.method().Authenticate(context.Background(), cred); err == nil {
		t.Fatal("expired token accepted; want rejection")
	}
}

// TestJTICache_BoundedEviction proves the replay cache stays bounded and evicts
// expired entries (AN-7).
func TestJTICache_BoundedEviction(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := NewJTICache(4)
	// Fill with already-expired entries.
	for _, jti := range []string{"e1", "e2", "e3", "e4"} {
		if !c.Add(jti, now.Add(time.Second), now) {
			t.Fatalf("first add of %q rejected", jti)
		}
	}
	if c.Len() != 4 {
		t.Fatalf("len = %d, want 4", c.Len())
	}
	// Advance past their expiry; a new add must sweep them and succeed, keeping
	// the cache within its cap.
	later := now.Add(time.Hour)
	if !c.Add("fresh", later.Add(time.Minute), later) {
		t.Fatal("add after expiry sweep rejected")
	}
	if c.Len() > 4 {
		t.Fatalf("len = %d exceeds cap 4", c.Len())
	}
}
