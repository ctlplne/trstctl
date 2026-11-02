// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAuth0 is a stand-in for an Auth0 tenant's token endpoint and the
// Management API's rotate-secret, from Auth0's API documentation: the client
// credentials grant returns a token for a known client and secret, refuses an
// authenticated client the Management API has not authorized (403
// access_denied), and refuses unknown credentials (401 invalid_client);
// rotate-secret replaces the application's secret at once.
type fakeAuth0 struct {
	mu        sync.Mutex
	secrets   map[string]string // client ID -> current secret
	mgmtToken string
	rotations int
}

func newFakeAuth0() *fakeAuth0 {
	return &fakeAuth0{secrets: map[string]string{"mgmtClient001": "mgmt-secret", "appClient0001": "app-secret-v1"}, mgmtToken: "mgmt-token"}
}

func (f *fakeAuth0) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
			var grant struct {
				GrantType, ClientID, ClientSecret, Audience string
			}
			var raw map[string]string
			_ = json.NewDecoder(r.Body).Decode(&raw)
			grant.GrantType, grant.ClientID, grant.ClientSecret, grant.Audience = raw["grant_type"], raw["client_id"], raw["client_secret"], raw["audience"]
			if grant.GrantType != "client_credentials" || !strings.HasSuffix(grant.Audience, "/api/v2/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if current, ok := f.secrets[grant.ClientID]; !ok || current != grant.ClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			if grant.ClientID != "mgmtClient001" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"Client is not authorized to access the Management API"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + f.mgmtToken + `","token_type":"Bearer"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/clients/") && strings.HasSuffix(r.URL.Path, "/rotate-secret"):
			if r.Header.Get("Authorization") != "Bearer "+f.mgmtToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/clients/"), "/rotate-secret")
			if _, ok := f.secrets[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.rotations++
			f.secrets[id] = "app-secret-v" + strings.Repeat("x", f.rotations+1)
			_ = json.NewEncoder(w).Encode(map[string]string{"client_id": id, "client_secret": f.secrets[id], "name": "orders"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (f *fakeAuth0) secret(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.secrets[id]
}

// A240: Auth0 rotates the bound application's client secret in one phase:
// the new secret authenticates, the old one stops at once, retirement has
// nothing left to do, and the provider issues no leases.
func TestAuth0RotatesTheBoundApplicationsClientSecret(t *testing.T) {
	ctx := context.Background()
	fake := newFakeAuth0()
	server := httptest.NewServer(fake.handler())
	defer server.Close()
	backend, err := NewAuth0Backend(Auth0Config{Endpoint: server.URL, ClientID: "mgmtClient001", ClientSecret: []byte("mgmt-secret"),
		RoleBindings: map[string]string{"auth0/orders": "appClient0001"}, AllowInsecureLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	old := []byte(`{"client_id":"appClient0001","client_secret":"app-secret-v1"}`)
	if err := backend.VerifyCredential(ctx, old); err != nil {
		t.Fatalf("the current secret should authenticate: %v", err)
	}
	if _, _, err := backend.CreateCredential(ctx, GenerateRequest{Role: "auth0/orders"}); err == nil || !strings.Contains(err.Error(), "not leased") {
		t.Fatalf("a lease was issued: %v", err)
	}
	ref, credential, err := backend.CreateCredential(ctx, GenerateRequest{Role: "auth0/orders", LeaseID: "cmd-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "appClient0001/cmd-1" || !strings.Contains(string(credential), fake.secret("appClient0001")) {
		t.Fatalf("rotation = %q %s", ref, credential)
	}
	if err := backend.VerifyCredential(ctx, credential); err != nil {
		t.Fatalf("the rotated secret does not authenticate: %v", err)
	}
	if err := backend.VerifyCredential(ctx, old); err == nil {
		t.Fatal("the previous secret still authenticates after a single-phase rotation")
	}
	if err := backend.Revoke(ctx, "appClient0001/cmd-0"); err != nil {
		t.Fatalf("retiring the invalidated predecessor: %v", err)
	}
	if err := backend.Revoke(ctx, "otherClient01/cmd-0"); err == nil {
		t.Fatal("a reference to an application this provider does not rotate was accepted")
	}
	if _, _, err := backend.CreateCredential(ctx, GenerateRequest{Role: "auth0/billing", Static: true}); err == nil {
		t.Fatal("an unbound role rotated something")
	}
	for name, cfg := range map[string]Auth0Config{
		"no client":     {Endpoint: server.URL, ClientSecret: []byte("s"), RoleBindings: map[string]string{"r": "appClient0001"}, AllowInsecureLoopback: true, HTTPClient: server.Client()},
		"bad binding":   {Endpoint: server.URL, ClientID: "mgmtClient001", ClientSecret: []byte("s"), RoleBindings: map[string]string{"r": "app client"}, AllowInsecureLoopback: true, HTTPClient: server.Client()},
		"plain http":    {Endpoint: "http://auth0.example.test", ClientID: "mgmtClient001", ClientSecret: []byte("s"), RoleBindings: map[string]string{"r": "appClient0001"}, HTTPClient: server.Client()},
		"no role bound": {Endpoint: server.URL, ClientID: "mgmtClient001", ClientSecret: []byte("s"), AllowInsecureLoopback: true, HTTPClient: server.Client()},
	} {
		if _, err := NewAuth0Backend(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
