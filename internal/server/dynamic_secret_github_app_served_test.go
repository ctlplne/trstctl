// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// githubAPIStandIn follows GitHub's installation-token endpoints as its REST
// documentation describes them (the app JWT is verified against the app's
// public key), and lists an installation's repositories for a token that is
// still valid.
type githubAPIStandIn struct {
	mu     sync.Mutex
	jwks   crypto.JWKS
	tokens map[string]string // token -> permissions it was minted with
	minted int
}

func newGitHubAPIStandIn(t *testing.T, jwks crypto.JWKS) (*githubAPIStandIn, *httptest.Server) {
	t.Helper()
	gh := &githubAPIStandIn{jwks: jwks, tokens: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gh.mu.Lock()
		defer gh.mu.Unlock()
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/4242/access_tokens":
			if _, err := crypto.VerifyJWT(bearer, gh.jwks); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			gh.minted++
			token := "ghs_served" + strings.Repeat("y", 28) + strconv.Itoa(gh.minted)
			permissions, _ := json.Marshal(in.Permissions)
			gh.tokens[token] = string(permissions)
			var repos []map[string]string
			for _, name := range in.Repositories {
				repos = append(repos, map[string]string{"name": name})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"permissions": in.Permissions, "repository_selection": "selected", "repositories": repos})
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
			if _, ok := gh.tokens[bearer]; !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			delete(gh.tokens, bearer)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/installation/repositories":
			if _, ok := gh.tokens[bearer]; !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return gh, srv
}

// A239 GitHub App, against a stand-in of GitHub's API: a lease is an
// installation token narrowed to the role's permissions and repositories; it
// can't be extended; revoking the lease presents the retained token to end it,
// after which GitHub refuses it.
func TestServedDynamicGitHubAppTokenIsEndedAtRevocationA239(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(signer.Public(), "")
	signer.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	gh, srv := newGitHubAPIStandIn(t, crypto.JWKS{Keys: []crypto.JWK{jwk}})
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "github", Type: "github-app", Endpoint: srv.URL, ClientID: "Iv1.served",
		PrivateKeyRef: writeServedCredentialFile(t, "github-app-key", string(keyPEM)), InstallationID: "4242",
		AllowedRoles: []string{"ci"}, RoleBindings: map[string]string{"ci": "contents:read,metadata:read on api"},
		MaxTTL: "1h", AllowInsecureLoopback: true,
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239 GitHub App tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-github-lease-1",
		map[string]any{"provider": "github", "role": "ci", "ttl_seconds": 1800})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Token        string
		Permissions  map[string]string
		Repositories []string
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Token == "" ||
		credential.Permissions["contents"] != "read" || len(credential.Repositories) != 1 {
		t.Fatalf("credential: %+v %v", credential, err)
	}
	list := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/installation/repositories", nil)
		req.Header.Set("Authorization", "Bearer "+credential.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := list(); code != http.StatusOK {
		t.Fatalf("the token before revocation: %d", code)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusUnprocessableEntity {
		t.Fatalf("renewing an installation token: %d %s, want 422", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code := list(); code != http.StatusUnauthorized {
		t.Fatalf("the revoked token still works: %d", code)
	}
	gh.mu.Lock()
	live := len(gh.tokens)
	gh.mu.Unlock()
	if live != 0 {
		t.Fatalf("%d tokens still live upstream", live)
	}
}
