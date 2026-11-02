// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// rabbitmqManagementFake keeps the users, permissions and connections its
// administrator's management API calls create, list and delete.
type rabbitmqManagementFake struct {
	mu          sync.Mutex
	users       map[string]string
	permissions map[string]map[string]string
	connections []map[string]string
	closed      []string
}

func newRabbitMQManagementFake(t *testing.T) (*rabbitmqManagementFake, *httptest.Server) {
	t.Helper()
	fake := &rabbitmqManagementFake{users: map[string]string{}, permissions: map[string]map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "lab_admin" || pass != "lab-admin-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		path := r.URL.EscapedPath()
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/users/"):
			var request struct {
				Password string `json:"password"`
			}
			_ = json.Unmarshal(body, &request)
			fake.users[strings.TrimPrefix(path, "/api/users/")] = request.Password
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/permissions/"):
			var request map[string]string
			_ = json.Unmarshal(body, &request)
			fake.permissions[strings.TrimPrefix(path, "/api/permissions/")] = request
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/users/"):
			user := strings.TrimPrefix(path, "/api/users/")
			if _, ok := fake.users[user]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(fake.users, user)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && path == "/api/connections":
			_ = json.NewEncoder(w).Encode(fake.connections)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/connections/"):
			fake.closed = append(fake.closed, strings.TrimPrefix(path, "/api/connections/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return fake, srv
}

// A239 RabbitMQ, served: a lease is a RabbitMQ user with exactly its role's
// permissions in its virtual host; it renews within the provider's maximum
// lifetime; revoking the lease deletes the user and closes its open
// connections.
func TestServedDynamicRabbitMQUserIsDeletedAtRevocationA239(t *testing.T) {
	fake, srv := newRabbitMQManagementFake(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "broker", Type: "rabbitmq", Endpoint: srv.URL, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "rabbitmq-admin", "lab-admin-password"),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on orders in /"},
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
	registerServedTenant(t, h, "A239 RabbitMQ tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-rabbitmq-lease-1",
		map[string]any{"provider": "broker", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
		VHost    string `json:"vhost"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.VHost != "/" {
		t.Fatalf("credential: %+v %v", credential, err)
	}
	fake.mu.Lock()
	created := fake.users[credential.Username]
	perms := fake.permissions["%2F/"+credential.Username]
	fake.connections = []map[string]string{{"name": "client -> broker", "user": credential.Username}, {"name": "other", "user": "app"}}
	fake.mu.Unlock()
	if created != credential.Password || perms["read"] != "^(orders)$" || perms["write"] != "^$" || perms["configure"] != "^$" {
		t.Fatalf("broker state: password match %v, permissions %v", created == credential.Password, perms)
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
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.users[credential.Username]; ok {
		t.Fatal("the revoked user still exists")
	}
	if len(fake.closed) != 1 || fake.closed[0] != "client%20-%3E%20broker" {
		t.Fatalf("closed connections %v, want only the leased user's", fake.closed)
	}
}
