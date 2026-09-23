// SPDX-License-Identifier: LicenseRef-trstctl-EE
package enterpriseauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

type mockIdP struct {
	srv      *httptest.Server
	sk       *jose.SigningKey
	issuer   string
	clientID string
	codes    map[string]map[string]any // authorization code -> id_token claims
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	sk, err := jose.GenerateRSASigningKey("idp-test-key")
	if err != nil {
		t.Fatalf("generate idp key: %v", err)
	}
	idp := &mockIdP{sk: sk, clientID: clientID, codes: map[string]map[string]any{}}
	mux := http.NewServeMux()
	// /authorize: a real IdP authenticates the user and redirects to redirect_uri with
	// ?code=...&state=.... Here we mint a code bound to the user the test selected via
	// a sentinel "login_as" param, echo the server's nonce into the token-to-be, and
	// bounce back to the server's redirect_uri preserving state.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		nonce := q.Get("nonce")
		code := q.Get("login_as")
		claims := idp.codes[code]
		if redirectURI == "" || claims == nil {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		claims["nonce"] = nonce // the IdP binds the request nonce into the id_token
		idp.codes[code] = claims
		http.Redirect(w, r, redirectURI+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), http.StatusFound) // #nosec G710 -- test redirect within its own local server (CWE-601)
	})
	// /token: exchange the code for a signed id_token (RFC 6749 §4.1.3).
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := idp.codes[r.Form.Get("code")]
		if claims == nil {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		payload, _ := json.Marshal(claims)
		signed, err := sk.Sign(payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "token_type": "Bearer"})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	idp.issuer = idp.srv.URL
	return idp
}

// registerUser pre-seeds an authorization code that, when redeemed, yields an
// id_token for sub with the given extra claims. The IdP fills iss/aud/exp/iat and
// the request nonce.
func (idp *mockIdP) registerUser(code, sub string, extra map[string]any) {
	now := time.Now()
	claims := map[string]any{
		"iss": idp.issuer, "aud": idp.clientID, "sub": sub,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	idp.codes[code] = claims
}

func (idp *mockIdP) jwksJSON(t *testing.T) string {
	t.Helper()
	b, err := idp.sk.PublicJWKS()
	if err != nil {
		t.Fatalf("marshal idp jwks: %v", err)
	}
	return string(b)
}
