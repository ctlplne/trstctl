// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type oauthLab struct {
	mu      sync.Mutex
	issued  map[string]string // token -> scope
	revoked map[string]bool
	reply   func(scope string) (int, map[string]any)
}

func newOAuthLab(t *testing.T, reply func(scope string) (int, map[string]any)) (*oauthLab, *httptest.Server) {
	t.Helper()
	lab := &oauthLab{issued: map[string]string{}, revoked: map[string]bool{}, reply: reply}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, pass, ok := r.BasicAuth(); !ok || id != "lab-client" || pass != "lab+secret%2F" { // #nosec G101 -- fabricated lab client secret, form-encoded (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		switch r.URL.Path {
		case "/token":
			if r.PostForm.Get("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			status, body := lab.reply(r.PostForm.Get("scope"))
			if tok, ok := body["access_token"].(string); ok {
				lab.issued[tok] = r.PostForm.Get("scope")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		case "/revoke":
			if r.PostForm.Get("token_type_hint") != "access_token" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			lab.revoked[r.PostForm.Get("token")] = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func newLabBackend(t *testing.T, srv *httptest.Server, revocation bool, now time.Time) *OAuthClientCredentialsBackend {
	t.Helper()
	cfg := OAuthClientCredentialsConfig{
		TokenURL: srv.URL + "/token", ClientID: "lab-client", ClientSecret: []byte("lab secret/"),
		RoleScopes:  map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"},
		MaxLifetime: 10 * time.Minute, HTTPClient: srv.Client(), Now: func() time.Time { return now },
	}
	if revocation {
		cfg.RevocationURL = srv.URL + "/revoke"
	}
	b, err := NewOAuthClientCredentialsBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestOAuthClientCredentialsIssuesTheRoleScopesAndRevokesA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	n := 0
	lab, srv := newOAuthLab(t, func(scope string) (int, map[string]any) {
		n++
		return http.StatusOK, map[string]any{"access_token": fmt.Sprintf("tok-%d", n), "token_type": "bearer", "expires_in": 300, "scope": scope}
	})
	b := newLabBackend(t, srv, true, now)
	ref, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		AccessToken string    `json:"access_token"`
		TokenType   string    `json:"token_type"`
		ExpiresAt   time.Time `json:"expires_at"`
		Scope       string    `json:"scope"`
	}
	if err := json.Unmarshal(credential, &got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "tok-1" || got.TokenType != "Bearer" || got.Scope != "orders.read" || !got.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("credential %+v", got)
	}
	if lab.issued["tok-1"] != "orders.read" {
		t.Fatalf("token request scope %q, want the reader role's", lab.issued["tok-1"])
	}
	if strings.Contains(ref, "tok-1") {
		t.Fatalf("the provider reference %q carries the token", ref)
	}
	if exp, ok := OAuthExpiration(ref); !ok || !exp.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("OAuthExpiration(%q) = %v %v", ref, exp, ok)
	}
	if err := b.RevokeCredential(context.Background(), ref, []byte(`{"access_token":"tok-other"}`)); err == nil {
		t.Fatal("a revocation carrying another token was sent")
	}
	if err := b.RevokeCredential(context.Background(), ref, credential); err != nil || !lab.revoked["tok-1"] {
		t.Fatalf("revoke: %v revoked=%v", err, lab.revoked)
	}
}

func TestOAuthClientCredentialsRefusesWiderOrLongerTokensA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		reply map[string]any
		ttl   time.Duration
		want  string
	}{
		{"wider scope", map[string]any{"access_token": "t1", "token_type": "Bearer", "expires_in": 300, "scope": "orders.read admin"}, time.Minute, "beyond the role: admin"},
		{"longer than declared", map[string]any{"access_token": "t2", "token_type": "Bearer", "expires_in": 3600}, time.Minute, "beyond the declared maximum"},
		{"shorter than the lease", map[string]any{"access_token": "t3", "token_type": "Bearer", "expires_in": 30}, time.Minute, "shorter than the 1m0s lease"},
		{"no lifetime", map[string]any{"access_token": "t4", "token_type": "Bearer"}, time.Minute, "no expires_in"},
		{"not bearer", map[string]any{"access_token": "t5", "token_type": "DPoP", "expires_in": 300}, time.Minute, "not Bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revocation := range []bool{true, false} {
				lab, srv := newOAuthLab(t, func(string) (int, map[string]any) { return http.StatusOK, tc.reply })
				b := newLabBackend(t, srv, revocation, now)
				_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: tc.ttl})
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("revocation=%v: err = %v, want %q", revocation, err, tc.want)
				}
				tok := tc.reply["access_token"].(string)
				if revocation != lab.revoked[tok] {
					t.Fatalf("revocation endpoint=%v but the refused token revoked=%v", revocation, lab.revoked[tok])
				}
				if revocation && !strings.Contains(err.Error(), "the token was revoked") {
					t.Fatalf("err = %v, want the revocation stated", err)
				}
			}
		})
	}
}

func TestOAuthClientCredentialsTTLOnlyWaitsForNativeExpiryA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	_, srv := newOAuthLab(t, func(scope string) (int, map[string]any) {
		return http.StatusOK, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 300, "scope": scope}
	})
	b := newLabBackend(t, srv, false, now)
	ref, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeCredential(context.Background(), ref, credential); !errors.Is(err, ErrNativeExpiryPending) {
		t.Fatalf("TTL-only revoke before expiry = %v, want ErrNativeExpiryPending", err)
	}
	if exp, ok := NativeExpiration(ref); !ok || !exp.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("NativeExpiration = %v %v", exp, ok)
	}
	b.now = func() time.Time { return now.Add(5 * time.Minute) }
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("revoke at expiry: %v", err)
	}
}

// oauthEndpoints is a configuration with only the two endpoints set.
func oauthEndpoints(tokenURL, revocationURL string) OAuthClientCredentialsConfig {
	return OAuthClientCredentialsConfig{TokenURL: tokenURL, RevocationURL: revocationURL}
}

func TestOAuthClientCredentialsConfigA239(t *testing.T) {
	badScope := oauthEndpoints("https://as.example/token", "")
	badScope.ClientID, badScope.ClientSecret = "c", []byte("s") // #nosec G101 -- fabricated fixture secret; the case fails on its scope (CWE-798)
	badScope.HTTPClient, badScope.MaxLifetime, badScope.RoleScopes = http.DefaultClient, time.Minute, map[string]string{"r": `a"b`}
	for _, tc := range []struct {
		name string
		cfg  OAuthClientCredentialsConfig
		want string
	}{
		{"http token URL", oauthEndpoints("http://as.example/token", ""), "https URL"},
		{"http loopback without the exception", oauthEndpoints("http://127.0.0.1:8080/token", ""), "https URL"},
		{"credentials in URL", oauthEndpoints("https://u:p@as.example/token", ""), "https URL"},
		{"http revocation", oauthEndpoints("https://as.example/token", "http://as.example/revoke"), "revocation endpoint"},
		{"bad scope", badScope, "scope-token"},
	} {
		if _, err := NewOAuthClientCredentialsBackend(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
