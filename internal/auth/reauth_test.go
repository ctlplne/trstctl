// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// TestFreshSignInIsCarriedFromTheProviderA277: the id_token's auth_time
// reaches the claims (a future one is refused), a re-authentication asks the
// provider for prompt=login and max_age=0 on top of the ordinary request, and
// the browser session carries the sign-in time in its signed cookie, never
// later than the session itself.
func TestFreshSignInIsCarriedFromTheProviderA277(t *testing.T) {
	sk, err := jose.GenerateRSASigningKey("idp-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	v := auth.OIDCVerifier{Issuer: testIssuer, ClientID: testClientID, Keys: sk.JWKS(), Now: func() time.Time { return now }}
	base := map[string]any{"iss": testIssuer, "aud": testClientID, "sub": "u", "nonce": "n", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}
	claims, err := v.Verify(idToken(t, sk, base), "n")
	if err != nil || claims.AuthTime != 0 {
		t.Fatalf("a token without auth_time: %+v %v", claims, err)
	}
	signedIn := cloneClaims(base)
	signedIn["auth_time"] = now.Add(-90 * time.Second).Unix()
	if claims, err = v.Verify(idToken(t, sk, signedIn), "n"); err != nil || claims.AuthTime != now.Add(-90*time.Second).Unix() {
		t.Fatalf("auth_time did not reach the claims: %+v %v", claims, err)
	}
	future := cloneClaims(base)
	future["auth_time"] = now.Add(10 * time.Minute).Unix()
	if _, err := v.Verify(idToken(t, sk, future), "n"); err == nil {
		t.Fatal("a token authenticated in the future was accepted")
	}

	plain, err := auth.AuthCodeURL("https://idp.example/authorize", "c", "https://trstctl.example/auth/callback", "s", "n", "ch")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := auth.ReauthenticationCodeURL("https://idp.example/authorize", "c", "https://trstctl.example/auth/callback", "s", "n", "ch")
	if err != nil || !strings.HasPrefix(fresh, plain+"&") {
		t.Fatalf("the re-authentication request is not the ordinary one plus its parameters: %s %v", fresh, err)
	}
	u, _ := url.Parse(fresh)
	if q := u.Query(); q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("re-authentication parameters: %v", q)
	}
	if _, err := auth.ReauthenticationCodeURL("https://idp.example/authorize", "c", "r", "s", "n", ""); err == nil {
		t.Fatal("a re-authentication without PKCE was built")
	}

	issuer := auth.NewSessionIssuerWithStore([]byte("0123456789abcdef0123456789abcdef"), time.Hour, time.Hour, auth.NewMemorySessionStore())
	issuer.Now = func() time.Time { return now }
	for _, tc := range []struct {
		name string
		at   time.Time
		want int64
	}{
		{"a sign-in the provider dated", now.Add(-time.Minute), now.Add(-time.Minute).Unix()},
		{"a provider clock running ahead", now.Add(30 * time.Second), now.Unix()},
		{"a sign-in that cannot say", time.Time{}, 0},
	} {
		token, err := issuer.IssueSignIn(context.Background(), auth.SignIn{Subject: "u", TenantID: "t", Roles: []string{"operator"}, AuthTime: tc.at})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		sess, err := issuer.VerifyContext(context.Background(), token)
		if err != nil || sess.AuthTime != tc.want {
			t.Fatalf("%s: session auth time %d (%v), want %d", tc.name, sess.AuthTime, err, tc.want)
		}
	}
	if _, err := issuer.IssueSignIn(context.Background(), auth.SignIn{Subject: "u", TenantID: "t", OIDC: &auth.OIDCSessionBinding{}}); err == nil {
		t.Fatal("an OIDC sign-in without its provider binding was issued")
	}
}
