// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const githubLabInstallation = "4242"

// githubAppStandIn follows GitHub's installation-token endpoints as its REST
// documentation describes them: the token request authenticates with the app's
// RS256 JWT (verified here against the app's public key), answers 201 with a
// one-hour token narrowed to the requested permissions and repositories, and
// DELETE /installation/token answers 204, or 401 for a token no longer valid.
type githubAppStandIn struct {
	mu     sync.Mutex
	jwks   crypto.JWKS
	now    time.Time
	tokens map[string]bool
	extra  map[string]string // permissions GitHub adds beyond the request
	issued int
}

func newGitHubAppStandIn(t *testing.T, jwks crypto.JWKS, now time.Time) (*githubAppStandIn, *httptest.Server) {
	t.Helper()
	gh := &githubAppStandIn{jwks: jwks, now: now, tokens: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gh.mu.Lock()
		defer gh.mu.Unlock()
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/"+githubLabInstallation+"/access_tokens":
			claims, err := crypto.VerifyJWT(bearer, gh.jwks)
			var c struct {
				Iss      string
				Iat, Exp int64
			}
			if err != nil || json.Unmarshal(claims, &c) != nil || c.Iss != "Iv1.lab" || c.Exp-c.Iat > 600 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			for name, level := range gh.extra {
				in.Permissions[name] = level
			}
			gh.issued++
			token := "ghs_lab" + strings.Repeat("x", 30) + strconv.Itoa(gh.issued)
			gh.tokens[token] = true
			var repos []map[string]string
			for _, name := range in.Repositories {
				repos = append(repos, map[string]string{"name": name})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": gh.now.Add(time.Hour).Format(time.RFC3339),
				"permissions": in.Permissions, "repository_selection": "selected", "repositories": repos})
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
			if !gh.tokens[bearer] {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			delete(gh.tokens, bearer)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return gh, srv
}

// githubAppTestKey is an RSA app key held through the crypto boundary: its
// PKCS #8 PEM (a GitHub App's PKCS #1 key works the same way) and its JWKS.
func githubAppTestKey(t *testing.T) ([]byte, crypto.JWKS) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	keyPEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(signer.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, crypto.JWKS{Keys: []crypto.JWK{jwk}}
}

func newLabGitHubApp(t *testing.T, srv *httptest.Server, keyPEM []byte, now *time.Time) *GitHubAppBackend {
	t.Helper()
	b, err := NewGitHubAppBackend(GitHubAppConfig{
		Endpoint: srv.URL, ClientID: "Iv1.lab", PrivateKey: keyPEM, InstallationID: githubLabInstallation,
		RoleBindings: map[string]string{"ci": "contents:read,metadata:read on api,web"}, MaxLifetime: time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(), Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestGitHubAppLeaseIsANarrowedInstallationTokenA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	keyPEM, jwks := githubAppTestKey(t)
	gh, srv := newGitHubAppStandIn(t, jwks, now)
	b := newLabGitHubApp(t, srv, keyPEM, &now)
	ref, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-0001", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Token        string
		ExpiresAt    time.Time `json:"expires_at"`
		Permissions  map[string]string
		Repositories []string
	}
	if err := json.Unmarshal(credential, &got); err != nil || !gh.tokens[got.Token] || !got.ExpiresAt.Equal(now.Add(time.Hour)) ||
		got.Permissions["contents"] != "read" || len(got.Permissions) != 2 || !slices.Equal(got.Repositories, []string{"api", "web"}) {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	if expiry, ok := NativeExpiration(ref); !ok || !expiry.Equal(now.Add(time.Hour)) || !strings.HasPrefix(ref, "github-app:") {
		t.Fatalf("ref %q expiry %v", ref, expiry)
	}
	// Without the token at hand, revocation waits for the native expiry.
	if err := b.Revoke(context.Background(), ref); !errors.Is(err, ErrNativeExpiryPending) {
		t.Fatalf("revoke by reference before expiry: %v", err)
	}
	if err := b.RevokeCredential(context.Background(), ref, []byte(`{"token":"ghs_someone_else"}`)); err == nil {
		t.Fatal("revoked with a token the reference does not name")
	}
	if err := b.RevokeCredential(context.Background(), ref, credential); err != nil || gh.tokens[got.Token] {
		t.Fatalf("revoke with the token: %v", err)
	}
	if err := b.RevokeCredential(context.Background(), ref, credential); err != nil {
		t.Fatalf("a second revocation of an ended token: %v", err)
	}
	later := now.Add(61 * time.Minute)
	now = later
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("revoke by reference after expiry: %v", err)
	}
}

func TestGitHubAppRefusesABroaderTokenA239(t *testing.T) {
	now := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	keyPEM, jwks := githubAppTestKey(t)
	gh, srv := newGitHubAppStandIn(t, jwks, now)
	gh.extra = map[string]string{"administration": "write"}
	b := newLabGitHubApp(t, srv, keyPEM, &now)
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-0002"}); err == nil ||
		!strings.Contains(err.Error(), "administration:write beyond the role") || len(gh.tokens) != 0 {
		t.Fatalf("a broader token: %v, live tokens %d", err, len(gh.tokens))
	}
	gh.extra = nil
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-0003", TTL: 2 * time.Hour}); err == nil || len(gh.tokens) != 0 {
		t.Fatalf("a lease longer than the token: %v, live tokens %d", err, len(gh.tokens))
	}
	other, _ := githubAppTestKey(t)
	wrongKey := newLabGitHubApp(t, srv, other, &now)
	if _, _, err := wrongKey.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-0004"}); err == nil {
		t.Fatal("GitHub accepted a JWT signed with another key")
	}
}

func TestGitHubAppConfigA239(t *testing.T) {
	grant, err := ParseGitHubAppGrant("contents:write, pull_requests:read on api")
	if err != nil || grant.Permissions["pull_requests"] != "read" || !slices.Equal(grant.Repositories, []string{"api"}) {
		t.Fatalf("grant %+v (%v)", grant, err)
	}
	for _, bad := range []string{"contents:read", "contents:read on ", "contents on api", "contents:owner on api", "Contents:read on api",
		"contents:read on org/api", "contents:read on *"} {
		if _, err := ParseGitHubAppGrant(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	keyPEM, _ := githubAppTestKey(t)
	base := GitHubAppConfig{ClientID: "Iv1.lab", PrivateKey: keyPEM, InstallationID: "4242", MaxLifetime: time.Hour,
		RoleBindings: map[string]string{"ci": "contents:read on api"}, HTTPClient: http.DefaultClient}
	if b, err := NewGitHubAppBackend(base); err != nil || b.endpoint != "https://api.github.com" {
		t.Fatalf("defaults: %v", err)
	} else {
		b.Close()
	}
	for name, mutate := range map[string]func(*GitHubAppConfig){
		"plain http":       func(c *GitHubAppConfig) { c.Endpoint = "http://ghe.example/api/v3" },
		"no client":        func(c *GitHubAppConfig) { c.ClientID = "" },
		"no key":           func(c *GitHubAppConfig) { c.PrivateKey = nil },
		"bad installation": func(c *GitHubAppConfig) { c.InstallationID = "org-x" },
		"over an hour":     func(c *GitHubAppConfig) { c.MaxLifetime = 2 * time.Hour },
		"no roles":         func(c *GitHubAppConfig) { c.RoleBindings = nil },
	} {
		c := base
		mutate(&c)
		if b, err := NewGitHubAppBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}
