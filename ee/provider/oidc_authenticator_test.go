// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// OIDC federation for provider operators (L1). Every refusal here exists
// because the previous authenticator was the opposite: it parsed a
// self-describing token for SHAPE and returned an MFA'd administrator. Role
// and MFA must come from claims the IdP signed, and anything not positively
// verified must be nobody.

type oidcFixture struct {
	auth   *OIDCAuthenticator
	signer *crypto.LockedSigner
	rogue  *crypto.LockedSigner
	now    time.Time
}

func newOIDCFixture(t *testing.T) oidcFixture {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	rogue, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rogue.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "idp-k1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	auth := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer: "https://idp.provider.example", Audience: "trstctl-provider",
		JWKS:        crypto.JWKS{Keys: []crypto.JWK{jwk}},
		RoleClaim:   "groups",
		AdminValues: []string{"trstctl-admins"}, OperatorValues: []string{"trstctl-operators"},
		Now: func() time.Time { return now },
	})
	if auth == nil {
		t.Fatal("a fully pinned config built no authenticator")
	}
	return oidcFixture{auth: auth, signer: signer, rogue: rogue, now: now}
}

func (f oidcFixture) request(t *testing.T, signer *crypto.LockedSigner, kid string, claims map[string]any) *http.Request {
	t.Helper()
	token, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func (f oidcFixture) baseClaims() map[string]any {
	return map[string]any{
		"iss": "https://idp.provider.example", "aud": "trstctl-provider",
		"exp": f.now.Add(10 * time.Minute).Unix(),
		"sub": "op-1", "email": "dana@provider.example",
		"groups": []string{"trstctl-admins"}, "amr": []string{"pwd", "mfa"},
	}
}

func TestOIDCAuthenticatorMapsVerifiedClaims(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	op, ok := f.auth.AuthenticateOperator(f.request(t, f.signer, "idp-k1", f.baseClaims()))
	if !ok || op.ID != "op-1" || op.Email != "dana@provider.example" || op.Role != OperatorAdmin || !op.MFA {
		t.Fatalf("operator = %+v ok=%v; role and MFA must come from the claims the IdP signed", op, ok)
	}

	claims := f.baseClaims()
	claims["groups"] = []string{"trstctl-operators"}
	op, ok = f.auth.AuthenticateOperator(f.request(t, f.signer, "idp-k1", claims))
	if !ok || op.Role != OperatorOperator {
		t.Fatalf("operator-group token = %+v ok=%v", op, ok)
	}

	// aud as an array — the other legal JWT shape.
	claims = f.baseClaims()
	claims["aud"] = []string{"something-else", "trstctl-provider"}
	if _, ok := f.auth.AuthenticateOperator(f.request(t, f.signer, "idp-k1", claims)); !ok {
		t.Fatal("array-aud token refused; both aud shapes are legal JWT")
	}
}

func TestOIDCAuthenticatorRefusesEverythingNotPositivelyVerified(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	cases := []struct {
		name   string
		mutate func(map[string]any)
		signer *crypto.LockedSigner
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }, f.signer},
		{"wrong audience", func(c map[string]any) { c["aud"] = "someone-else" }, f.signer},
		{"expired", func(c map[string]any) { c["exp"] = f.now.Add(-time.Minute).Unix() }, f.signer},
		{"no expiry", func(c map[string]any) { delete(c, "exp") }, f.signer},
		{"not yet valid", func(c map[string]any) { c["nbf"] = f.now.Add(time.Hour).Unix() }, f.signer},
		{"no subject", func(c map[string]any) { c["sub"] = "" }, f.signer},
		{"no matching role", func(c map[string]any) { c["groups"] = []string{"everyone", "hr"} }, f.signer},
		{"rogue signer", func(map[string]any) {}, f.rogue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := f.baseClaims()
			tc.mutate(claims)
			if op, ok := f.auth.AuthenticateOperator(f.request(t, tc.signer, "idp-k1", claims)); ok {
				t.Fatalf("accepted (%+v).\n\n"+
					"The IdP vouches for the whole workforce; anything not positively verified — "+
					"or verified but not role-mapped — must be nobody, or federation quietly turns "+
					"every employee into someone who can suspend customers", op)
			}
		})
	}
}

// An authenticated single-factor operator is a 403 at the mutation, not a 401
// at the door: the gap is MFA, and the error should say so rather than read
// as a broken credential.
func TestSingleFactorOperatorIsAuthenticatedButRefusedMutations(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	claims := f.baseClaims()
	claims["amr"] = []string{"pwd"}
	op, ok := f.auth.AuthenticateOperator(f.request(t, f.signer, "idp-k1", claims))
	if !ok || op.MFA {
		t.Fatalf("single-factor operator = %+v ok=%v; authentication succeeded, MFA did not", op, ok)
	}

	// Through the real handler: the plane must refuse the mutation.
	store := NewMemStore()
	h := NewHandler(Config{
		License: providerLicense(t, 10), Store: store, Audit: &captureAudit{},
		Clock: fixedClock(), Authenticator: f.auth,
		Delegations: fullyDelegated("op-1", "tenant-x"),
	})
	token, err := crypto.SignJWT(f.signer, "idp-k1", claims)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants", strings.NewReader(`{"slug":"x","name":"X"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("single-factor provision = %d, want 403: authenticated is not authorized, and the "+
			"MFA requirement must bite at the mutation", rec.Code)
	}
}

// The acceptance's full sentence in one test: an operator authenticates
// through a REAL IdP (a signed token verified against the pinned JWKS) and
// can act only within their delegated customer scope.
func TestOIDCFederatedOperatorIsBoundByDelegation(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	store := NewMemStore()
	now := fixedClock()()
	for _, id := range []string{"tenant-alpha", "tenant-beta"} {
		if _, err := store.CreateTenant(t.Context(), Tenant{
			ID: id, Slug: strings.TrimPrefix(id, "tenant-"), Name: id,
			Status: TenantActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(Config{
		License: providerLicense(t, 10), Store: store, Audit: &captureAudit{},
		Clock: fixedClock(), Authenticator: f.auth,
		Delegations: fullyDelegated("op-1", "tenant-alpha"),
	})
	token, err := crypto.SignJWT(f.signer, "idp-k1", f.baseClaims())
	if err != nil {
		t.Fatal(err)
	}
	do := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("/provider/v1/tenants/tenant-alpha/suspend"); code != http.StatusNoContent {
		t.Fatalf("delegated suspend through the federated identity = %d, want 204", code)
	}
	if code := do("/provider/v1/tenants/tenant-beta/suspend"); code != http.StatusForbidden {
		t.Fatalf("UNdelegated suspend through the federated identity = %d, want 403.\n\n"+
			"Federation answers who the operator is; the delegation answers which customers they "+
			"may touch. A federated identity that bypassed the partition would be the L1 defect "+
			"rebuilt on better credentials.", code)
	}
}
