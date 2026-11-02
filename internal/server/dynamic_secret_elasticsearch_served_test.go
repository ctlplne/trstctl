// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// elasticsearchFake keeps the API keys its administrator creates and answers a
// search of logs-lab for a valid key whose role descriptor reads logs-*, as
// Elasticsearch's security layer does.
type elasticsearchFake struct {
	mu   sync.Mutex
	keys map[string]*elasticsearchFakeKey
	next int
}

type elasticsearchFakeKey struct {
	name, secret string
	privileges   []string
	invalidated  bool
}

func newElasticsearchFake(t *testing.T) (*elasticsearchFake, *httptest.Server) {
	t.Helper()
	fake := &elasticsearchFake{keys: map[string]*elasticsearchFakeKey{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if encoded, ok := strings.CutPrefix(r.Header.Get("Authorization"), "ApiKey "); ok {
			raw, _ := base64.StdEncoding.DecodeString(encoded)
			id, secret, _ := strings.Cut(string(raw), ":")
			key := fake.keys[id]
			if key == nil || key.invalidated || key.secret != secret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodGet || r.URL.Path != "/logs-lab/_search" || !slices.Contains(key.privileges, "read") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"hits":{"total":{"value":1}}}`))
			return
		}
		if user, pass, ok := r.BasicAuth(); !ok || user != "elastic" || pass != "lab-elastic-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_security/api_key":
			found := []map[string]string{}
			for id, key := range fake.keys {
				if key.name == r.URL.Query().Get("name") && !key.invalidated {
					found = append(found, map[string]string{"id": id})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": found})
		case r.Method == http.MethodPost && r.URL.Path == "/_security/api_key":
			var request struct {
				Name            string `json:"name"`
				RoleDescriptors map[string]struct {
					Indices []struct {
						Privileges []string `json:"privileges"`
					} `json:"indices"`
				} `json:"role_descriptors"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			fake.next++
			id, secret := fmt.Sprintf("key%d", fake.next), fmt.Sprintf("secret%d", fake.next)
			key := &elasticsearchFakeKey{name: request.Name, secret: secret}
			for _, index := range request.RoleDescriptors["trstctl_lease"].Indices {
				key.privileges = append(key.privileges, index.Privileges...)
			}
			fake.keys[id] = key
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": request.Name, "api_key": secret,
				"encoded": base64.StdEncoding.EncodeToString([]byte(id + ":" + secret)), "expiration": time.Now().Add(time.Hour).UnixMilli()})
		case r.Method == http.MethodDelete && r.URL.Path == "/_security/api_key":
			var request struct {
				IDs []string `json:"ids"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			for _, id := range request.IDs {
				if key := fake.keys[id]; key != nil {
					key.invalidated = true
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"invalidated_api_keys": request.IDs, "error_count": 0})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return fake, srv
}

// A239 Elasticsearch, served: a lease is an API key that can search logs-lab
// but not write; it renews within the provider's maximum lifetime; revoking the
// lease invalidates the key, after which Elasticsearch refuses it.
func TestServedDynamicElasticsearchKeyIsInvalidatedAtRevocationA239(t *testing.T) {
	fake, srv := newElasticsearchFake(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "logs", Type: "elasticsearch", Endpoint: srv.URL, AdminUser: "elastic",
		PasswordRef:  writeServedCredentialFile(t, "elasticsearch-admin", "lab-elastic-password"),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on logs-*"},
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
	registerServedTenant(t, h, "A239 Elasticsearch tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-elasticsearch-lease-1",
		map[string]any{"provider": "logs", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Encoded string `json:"encoded"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Encoded == "" {
		t.Fatalf("credential: %v", err)
	}
	call := func(method, path string) int {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.Header.Set("Authorization", "ApiKey "+credential.Encoded)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := call(http.MethodGet, "/logs-lab/_search"); code != http.StatusOK {
		t.Fatalf("the leased key could not search logs-lab: %d", code)
	}
	if code := call(http.MethodPost, "/logs-lab/_doc"); code != http.StatusForbidden {
		t.Fatalf("the leased key could write: %d", code)
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
	if code := call(http.MethodGet, "/logs-lab/_search"); code != http.StatusUnauthorized {
		t.Fatalf("the invalidated key still searches: %d", code)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for id, key := range fake.keys {
		if !key.invalidated {
			t.Fatalf("key %s is still live", id)
		}
	}
}
