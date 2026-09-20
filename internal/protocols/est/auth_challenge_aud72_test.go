// SPDX-License-Identifier: BUSL-1.1

package est_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/protocols/est"
)

type aud72ChallengeAuthenticator struct {
	result est.AuthenticationResult
}

func (a aud72ChallengeAuthenticator) Authenticate(*http.Request) est.AuthenticationResult {
	return a.result
}

func TestAuthenticatorOwnsESTChallengeAUD72(t *testing.T) {
	t.Parallel()
	const challenge = `Bearer realm="est", scope="certs:request"`
	srv := est.New(est.Config{
		Auth: aud72ChallengeAuthenticator{result: est.AuthenticationResult{
			StatusCode: http.StatusUnauthorized,
			Challenge:  challenge,
		}},
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	rawHeader := map[string][]string(rec.Header())
	if got := rawHeader["WWW-Authenticate"]; len(got) != 1 || got[0] != challenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, challenge)
	}
	if _, canonicalized := rawHeader["Www-Authenticate"]; canonicalized {
		t.Fatal("challenge header was rewritten to libest-incompatible Www-Authenticate casing")
	}
}

func TestBasicAuthenticatorResultKeepsBasicChallengeAUD72(t *testing.T) {
	t.Parallel()
	authenticator := est.NewBasicAuthenticator(est.BasicAuthConfig{Password: []byte("test-only-password")})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil)

	denied := authenticator.Authenticate(req)
	if denied.Allowed || denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing Basic credential result = %+v, want denied 401", denied)
	}
	if got, want := denied.Challenge, `Basic realm="est"`; got != want {
		t.Fatalf("Basic challenge = %q, want %q", got, want)
	}

	req.SetBasicAuth("device", "test-only-password")
	allowed := authenticator.Authenticate(req)
	if !allowed.Allowed || allowed.StatusCode != 0 || allowed.Challenge != "" {
		t.Fatalf("valid Basic credential result = %+v, want clean allow", allowed)
	}
}
