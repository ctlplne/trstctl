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
)

// apiConnectPlatformStandIn follows the platform API's token and
// app-credential endpoints as IBM documents them, and plays the gateway: a
// call with a client ID and secret that exist is accepted.
type apiConnectPlatformStandIn struct {
	mu          sync.Mutex
	credentials map[string]string // client id -> secret
	names       map[string]string // name -> client id
	minted      int
}

func newAPIConnectPlatformStandIn(t *testing.T) (*apiConnectPlatformStandIn, *httptest.Server) {
	t.Helper()
	pl := &apiConnectPlatformStandIn{credentials: map[string]string{}, names: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pl.mu.Lock()
		defer pl.mu.Unlock()
		switch {
		case r.URL.Path == "/gateway/orders":
			if secret, ok := pl.credentials[r.Header.Get("X-IBM-Client-Id")]; !ok || secret != r.Header.Get("X-IBM-Client-Secret") {
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		case r.URL.Path == "/api/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "apic-served-token", "token_type": "Bearer"}) // #nosec G101 -- fabricated stand-in token (CWE-798)
			return
		case r.Header.Get("Authorization") != "Bearer apic-served-token":
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		collection := "/api/apps/acme/sandbox/partners/orders-app/credentials"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var in struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if _, exists := pl.names[in.Name]; exists {
				w.WriteHeader(http.StatusConflict)
				return
			}
			pl.minted++
			id, secret := "client-"+strconv.Itoa(pl.minted), "secret-"+strconv.Itoa(pl.minted)
			pl.names[in.Name], pl.credentials[id] = id, secret
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"name": in.Name, "client_id": id, "client_secret": secret})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, collection+"/"):
			name := strings.TrimPrefix(r.URL.Path, collection+"/")
			id, exists := pl.names[name]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(pl.names, name)
			delete(pl.credentials, id)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return pl, srv
}

// A239 IBM API Connect, against a stand-in of the platform API: a lease is a
// credential on the bound consumer app; the gateway accepts it; it renews
// within the maximum lifetime; revoking the lease deletes the credential, after
// which the gateway refuses it.
func TestServedDynamicAPIConnectCredentialIsDeletedAtRevocationA239(t *testing.T) {
	_, srv := newAPIConnectPlatformStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "apic", Type: "ibm-api-connect", Endpoint: srv.URL, ClientID: "toolkit",
		ClientSecretRef: writeServedCredentialFile(t, "apic-client", "toolkit-secret"), APIKeyRef: writeServedCredentialFile(t, "apic-key", "served-api-key"),
		AllowedRoles: []string{"partner"}, RoleBindings: map[string]string{"partner": "acme/sandbox/partners/orders-app"},
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
	registerServedTenant(t, h, "A239 API Connect tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-apic-lease-1",
		map[string]any{"provider": "apic", "role": "partner", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.ClientID == "" {
		t.Fatalf("credential: %v", err)
	}
	gateway := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/gateway/orders", nil)
		req.Header.Set("X-IBM-Client-Id", credential.ClientID)
		req.Header.Set("X-IBM-Client-Secret", credential.ClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := gateway(); code != http.StatusOK {
		t.Fatalf("the gateway before revocation: %d", code)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusOK {
		t.Fatalf("renew within the maximum lifetime: %d %s", status, body)
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
	if code := gateway(); code != http.StatusUnauthorized {
		t.Fatalf("the deleted credential still passes the gateway: %d", code)
	}
}
