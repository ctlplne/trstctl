// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// entraStandIn is an Entra v2 token endpoint for one tenant: it accepts the
// client-credentials grant with a JWT-bearer client assertion and answers
// with an access token that names the assertion it was given.
type entraStandIn struct {
	srv       *httptest.Server
	mu        sync.Mutex
	exchanges []url.Values
	expiresIn int
}

func newEntraStandIn(t *testing.T, tenant string, expiresIn int) *entraStandIn {
	t.Helper()
	e := &entraStandIn{expiresIn: expiresIn}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/"+tenant+"/oauth2/v2.0/token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		e.mu.Lock()
		e.exchanges = append(e.exchanges, r.PostForm)
		e.mu.Unlock()
		if r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			r.PostForm.Get("client_assertion") == "" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "kv-token-for-" + r.PostForm.Get("client_assertion"),
			"token_type": "Bearer", "expires_in": e.expiresIn})
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *entraStandIn) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.exchanges)
}

const a169Tenant, a169Client = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000"

// A169: the token source exchanges the projected federated token for an
// Entra access token, reuses it until shortly before it expires, and re-reads
// the file at the next exchange so a rotated projection is used.
func TestAzureFederatedTokenSourceExchangesAndRefreshes(t *testing.T) {
	entra := newEntraStandIn(t, a169Tenant, 3600)
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("projected-jwt-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewAzureFederatedTokenSource(AzureFederatedTokenSourceConfig{TenantID: a169Tenant, ClientID: a169Client,
		FederatedTokenFile: tokenFile, AuthorityHost: entra.srv.URL, Scope: "https://vault.azure.net/.default", Doer: entra.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(source.Close)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		token, wipe, err := source.Token(ctx)
		if err != nil || string(token) != "kv-token-for-projected-jwt-1" {
			t.Fatalf("token %d = %q %v", i, token, err)
		}
		wipe()
	}
	if entra.count() != 1 {
		t.Fatalf("exchanges = %d, want one cached token for three requests", entra.count())
	}
	form := entra.exchanges[0]
	if form.Get("client_id") != a169Client || form.Get("scope") != "https://vault.azure.net/.default" || form.Get("client_assertion") != "projected-jwt-1" {
		t.Fatalf("exchange form = %v", form)
	}

	// A token inside the refresh window is replaced, from the rotated file.
	short := newEntraStandIn(t, a169Tenant, 3)
	refreshing, err := NewAzureFederatedTokenSource(AzureFederatedTokenSourceConfig{TenantID: a169Tenant, ClientID: a169Client,
		FederatedTokenFile: tokenFile, AuthorityHost: short.srv.URL, Scope: "https://vault.azure.net/.default", Doer: short.srv.Client(),
		RefreshBefore: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(refreshing.Close)
	if _, wipe, err := refreshing.Token(ctx); err != nil {
		t.Fatal(err)
	} else {
		wipe()
	}
	if err := os.WriteFile(tokenFile, []byte("projected-jwt-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond) // past expiry minus the refresh window
	token, wipe, err := refreshing.Token(ctx)
	if err != nil || string(token) != "kv-token-for-projected-jwt-2" || short.count() != 2 {
		t.Fatalf("refreshed token = %q %v after %d exchanges", token, err, short.count())
	}
	wipe()
}

func TestAzureFederatedTokenSourceRefusesBadConfiguration(t *testing.T) {
	entra := newEntraStandIn(t, a169Tenant, 3600)
	for name, cfg := range map[string]AzureFederatedTokenSourceConfig{
		"no tenant":     {ClientID: a169Client, FederatedTokenFile: "/x", Scope: "s", Doer: entra.srv.Client()},
		"no token file": {TenantID: a169Tenant, ClientID: a169Client, Scope: "s", Doer: entra.srv.Client()},
		"no client":     {TenantID: a169Tenant, ClientID: a169Client, FederatedTokenFile: "/x", Scope: "s"},
		"bad authority": {TenantID: a169Tenant, ClientID: a169Client, FederatedTokenFile: "/x", Scope: "s", AuthorityHost: "ftp://login", Doer: entra.srv.Client()},
	} {
		if _, err := NewAzureFederatedTokenSource(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	missing, err := NewAzureFederatedTokenSource(AzureFederatedTokenSourceConfig{TenantID: a169Tenant, ClientID: a169Client,
		FederatedTokenFile: filepath.Join(t.TempDir(), "absent"), AuthorityHost: entra.srv.URL, Scope: "s", Doer: entra.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, wipe, err := missing.Token(context.Background()); err == nil {
		wipe()
		t.Fatal("a missing projected token file produced a token")
	}
	if entra.count() != 0 {
		t.Fatalf("an exchange was attempted without a federated token (%d)", entra.count())
	}
}
