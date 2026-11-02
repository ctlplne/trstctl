// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// tailscaleAPIStandIn follows the v2 API's auth-key endpoints as Tailscale's API
// documentation describes them, and registers a device with a key that exists
// and was not used before, as a tailnet's coordination server would.
type tailscaleAPIStandIn struct {
	mu      sync.Mutex
	keys    map[string]string // id -> key
	used    map[string]bool
	created []map[string]any
	next    int
}

func newTailscaleAPIStandIn(t *testing.T) (*tailscaleAPIStandIn, *httptest.Server) {
	t.Helper()
	api := &tailscaleAPIStandIn{keys: map[string]string{}, used: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		if r.URL.Path == "/register" {
			key := r.Header.Get("X-Auth-Key")
			for id, k := range api.keys {
				if k == key && !api.used[id] {
					api.used[id] = true
					w.WriteHeader(http.StatusOK)
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tskey-api-lab" { // #nosec G101 -- fabricated stand-in API token (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/-/keys":
			var request map[string]any
			_ = json.NewDecoder(r.Body).Decode(&request)
			api.created = append(api.created, request)
			api.next++
			id := fmt.Sprintf("k%dCNTRL", api.next)
			api.keys[id] = "tskey-auth-" + id + "-secret"
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "key": api.keys[id],
				"created": time.Now().UTC().Format(time.RFC3339), "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/tailnet/-/keys/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/v2/tailnet/-/keys/")
			if _, ok := api.keys[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(api.keys, id)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return api, srv
}

// A239 Tailscale, against a stand-in of the API: a lease is a single-use,
// ephemeral, preauthorized auth key with the role's tags; revoking the lease
// deletes the key, after which a registration with it is refused.
func TestServedDynamicTailscaleKeyIsDeletedAtRevocationA239(t *testing.T) {
	api, srv := newTailscaleAPIStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "tailnet", Type: "tailscale", Endpoint: srv.URL,
		BearerTokenRef: writeServedCredentialFile(t, "tailscale-api", "tskey-api-lab"),
		AllowedRoles:   []string{"ci"}, RoleBindings: map[string]string{"ci": "tag:ci"},
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
	registerServedTenant(t, h, "A239 Tailscale tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	issue := func(key string) (dynamicLeaseView, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": "tailnet", "role": "ci", "ttl_seconds": 600})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue: %d %s", status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
			t.Fatalf("decode the lease: %v %s", err, body)
		}
		var credential struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Key == "" {
			t.Fatalf("credential: %v", err)
		}
		return lease, credential.Key
	}
	register := func(key string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/register", nil)
		req.Header.Set("X-Auth-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	used, usedKey := issue("a239-tailscale-lease-1")
	if code := register(usedKey); code != http.StatusOK {
		t.Fatalf("a device could not register with the leased key: %d", code)
	}
	if code := register(usedKey); code != http.StatusUnauthorized {
		t.Fatalf("the single-use key registered a second device: %d", code)
	}
	api.mu.Lock()
	request, _ := json.Marshal(api.created[0]["capabilities"])
	api.mu.Unlock()
	if string(request) != `{"devices":{"create":{"ephemeral":true,"preauthorized":true,"reusable":false,"tags":["tag:ci"]}}}` {
		t.Fatalf("key capabilities %s", request)
	}
	unused, unusedKey := issue("a239-tailscale-lease-2")
	for _, lease := range []dynamicLeaseView{used, unused} {
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke: %d %s", status, body)
		}
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+unused.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code := register(unusedKey); code != http.StatusUnauthorized {
		t.Fatalf("a deleted key registered a device: %d", code)
	}
}
