// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// milvusRESTStandIn follows the RESTful API v2 user endpoints as Milvus 2.6
// answers them (HTTP 200 with a result code), and answers a collection listing
// for a user that exists with its password.
type milvusRESTStandIn struct {
	mu    sync.Mutex
	users map[string]string
	roles map[string][]string
}

func newMilvusRESTStandIn(t *testing.T) (*milvusRESTStandIn, *httptest.Server) {
	t.Helper()
	mv := &milvusRESTStandIn{users: map[string]string{}, roles: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mv.mu.Lock()
		defer mv.mu.Unlock()
		reply := func(code int) { _ = json.NewEncoder(w).Encode(map[string]any{"code": code, "data": map[string]any{}}) }
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.URL.Path == "/v2/vectordb/collections/list" {
			user, pass, _ := strings.Cut(token, ":")
			if stored, ok := mv.users[user]; !ok || stored != pass {
				reply(1800)
				return
			}
			reply(0)
			return
		}
		if token != "root:lab-root-password" { // #nosec G101 -- fabricated stand-in administrator (CWE-798)
			reply(1800)
			return
		}
		var in struct{ UserName, Password, RoleName string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v2/vectordb/users/create":
			if _, exists := mv.users[in.UserName]; exists {
				reply(1100)
				return
			}
			mv.users[in.UserName] = in.Password
		case "/v2/vectordb/users/drop":
			delete(mv.users, in.UserName)
			delete(mv.roles, in.UserName)
		case "/v2/vectordb/users/grant_role":
			mv.roles[in.UserName] = append(mv.roles[in.UserName], in.RoleName)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		reply(0)
	}))
	t.Cleanup(srv.Close)
	return mv, srv
}

// A239 Milvus, against a stand-in of the RESTful API: a lease is a user with
// its role's Milvus roles; it renews within the maximum lifetime; revoking the
// lease drops the user, after which its requests are refused.
func TestServedDynamicMilvusUserIsDroppedAtRevocationA239(t *testing.T) {
	mv, srv := newMilvusRESTStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "milvus", Type: "milvus", Endpoint: srv.URL, AdminUser: "root",
		PasswordRef:  writeServedCredentialFile(t, "milvus-root", "lab-root-password"),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "orders_reader"},
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
	registerServedTenant(t, h, "A239 Milvus tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-milvus-lease-1",
		map[string]any{"provider": "milvus", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" {
		t.Fatalf("credential: %v", err)
	}
	list := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v2/vectordb/collections/list", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+credential.Username+":"+credential.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var result struct{ Code int }
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return result.Code
	}
	mv.mu.Lock()
	roles := strings.Join(mv.roles[credential.Username], ",")
	mv.mu.Unlock()
	if roles != "orders_reader" || list() != 0 {
		t.Fatalf("Milvus user roles %q, its request before revocation refused", roles)
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
	if code := list(); code != 1800 {
		t.Fatalf("the dropped user's request answered code %d, want 1800", code)
	}
}
