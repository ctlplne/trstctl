// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// oauthLabServer is an authorization server for one confidential client (token
// and RFC 7009 revocation endpoints) and a resource server that accepts its
// unrevoked, unexpired tokens carrying the scope it requires.
type oauthLabServer struct {
	mu      sync.Mutex
	tokens  map[string]oauthLabToken
	revoked map[string]bool
	// lifetime is how long a token it issues is valid; five minutes when
	// unset.
	lifetime time.Duration
}

// setLifetime sets how long the tokens it issues from now on are valid.
func (l *oauthLabServer) setLifetime(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lifetime = d
}

type oauthLabToken struct {
	scope   string
	expires time.Time
}

func newOAuthLabServer(t *testing.T) (*oauthLabServer, *httptest.Server) {
	t.Helper()
	lab := &oauthLabServer{tokens: map[string]oauthLabToken{}, revoked: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		if r.URL.Path == "/orders" {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			issued, known := lab.tokens[token]
			if !ok || !known || lab.revoked[token] || time.Now().After(issued.expires) || !strings.Contains(" "+issued.scope+" ", " orders.read ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"orders":[]}`))
			return
		}
		if id, secret, ok := r.BasicAuth(); !ok || id != "trstctl-leases" || secret != "lab-client-secret" { // #nosec G101 -- fabricated lab client secret (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/token":
			raw, err := crypto.RandomBytes(16)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			token := hex.EncodeToString(raw)
			lifetime := lab.lifetime
			if lifetime == 0 {
				lifetime = 5 * time.Minute
			}
			lab.tokens[token] = oauthLabToken{scope: r.PostForm.Get("scope"), expires: time.Now().Add(lifetime)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(lifetime.Seconds()), "scope": r.PostForm.Get("scope")})
		case "/revoke":
			lab.revoked[r.PostForm.Get("token")] = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func (l *oauthLabServer) isRevoked(token string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revoked[token]
}

// A239 OAuth client credentials, served: a lease is a new access token with the
// role's scopes that the resource server accepts; it can't be extended;
// revoking the lease revokes the token at the authorization server, after
// which the resource server refuses it. Without a revocation endpoint the
// revocation stays pending until the token's own expiry, which the lease shows.
func TestServedDynamicOAuthLeaseIsRevokedAtTheAuthorizationServerA239(t *testing.T) {
	lab, srv := newOAuthLabServer(t)
	secretRef := writeServedCredentialFile(t, "oauth-client", "lab-client-secret")
	provider := func(id string, revocation bool) config.DynamicSecretProviderConfig {
		c := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: id, Type: "oauth-client-credentials", Endpoint: srv.URL + "/token",
			ClientID: "trstctl-leases", ClientSecretRef: secretRef, AllowedRoles: []string{"reader"},
			RoleBindings: map[string]string{"reader": "orders.read"}, MaxTTL: "5m", AllowInsecureLoopback: true,
		}
		if revocation {
			c.RevocationEndpoint = srv.URL + "/revoke"
		}
		return c
	}
	configs := []config.DynamicSecretProviderConfig{provider("orders-api", true), provider("orders-api-ttl", false)}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239 OAuth tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	type leaseView struct {
		dynamicLeaseView
		NativeExpiresAt *time.Time `json:"native_expires_at"`
	}
	issue := func(provider, key string) (leaseView, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": provider, "role": "reader", "ttl_seconds": 60})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue %s: %d %s", provider, status, body)
		}
		var lease leaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the %s lease: %v %s", provider, err, body)
		}
		var credential struct {
			AccessToken string    `json:"access_token"`
			TokenType   string    `json:"token_type"`
			ExpiresAt   time.Time `json:"expires_at"`
			Scope       string    `json:"scope"`
		}
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.AccessToken == "" ||
			credential.TokenType != "Bearer" || credential.Scope != "orders.read" {
			t.Fatalf("the %s credential: %+v (%v)", provider, credential, err)
		}
		if lease.NativeExpiresAt == nil || !lease.NativeExpiresAt.Equal(credential.ExpiresAt) {
			t.Fatalf("the %s lease states native expiry %v, the token expires %s", provider, lease.NativeExpiresAt, credential.ExpiresAt)
		}
		return lease, credential.AccessToken
	}
	resource := func(token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orders", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// The catalog states each configured provider's own revocation.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", tok, nil)
	var catalog struct {
		ConfiguredProviders []struct {
			ID         string `json:"id"`
			Revocation string `json:"revocation"`
		} `json:"configured_providers"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil {
		t.Fatalf("provider catalog: %d %s", status, body)
	}
	stated := map[string]string{}
	for _, p := range catalog.ConfiguredProviders {
		stated[p.ID] = p.Revocation
	}
	if stated["orders-api"] != "confirmed" || stated["orders-api-ttl"] != "ttl_only" {
		t.Fatalf("configured revocation = %v, want orders-api confirmed and orders-api-ttl ttl_only", stated)
	}

	lease, token := issue("orders-api", "a239-oauth-lease-1")
	if code := resource(token); code != http.StatusOK {
		t.Fatalf("the resource server refused the leased token: %d", code)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 10})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "can't be extended") {
		t.Fatalf("an access token was extended: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	var revoked leaseView
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		if status == http.StatusOK && json.Unmarshal(body, &revoked) == nil && revoked.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !lab.isRevoked(token) {
		t.Fatal("the revocation completed without revoking the token at the authorization server")
	}
	if code := resource(token); code != http.StatusUnauthorized {
		t.Fatalf("the resource server still accepts the revoked token: %d", code)
	}
	var retained []byte
	if record, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, lease.ID); err != nil {
		t.Fatal(err)
	} else {
		retained = record.RevocationSealedCredential
	}
	if len(retained) != 0 {
		t.Fatal("the completed revocation kept the sealed token")
	}

	// TTL-only: the token stays valid until its expiry, and so does the
	// revocation's pending state; nothing is sent to the authorization server.
	ttlLease, ttlToken := issue("orders-api-ttl", "a239-oauth-lease-2")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+ttlLease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke the TTL-only lease: %d %s", status, body)
	}
	time.Sleep(2 * time.Second) // the dispatcher has had its turns
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+ttlLease.ID, tok, nil)
	var pending leaseView
	if status != http.StatusOK || json.Unmarshal(body, &pending) != nil || pending.RevocationStatus != "pending" || pending.NativeExpiresAt == nil {
		t.Fatalf("the TTL-only revocation: %d %s", status, body)
	}
	if lab.isRevoked(ttlToken) || resource(ttlToken) != http.StatusOK {
		t.Fatal("a TTL-only provider sent the token to a revocation endpoint")
	}
	t.Logf("A239_OAUTH_OK confirmed=%s ttl_only=%s native_expires_at=%s", lease.ID, ttlLease.ID, pending.NativeExpiresAt.Format(time.RFC3339))
}
