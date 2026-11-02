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

// couchbaseRESTStandIn follows the management REST API's local-user endpoints
// as Couchbase Server 8.0 answers them, and a query-service login check that
// accepts a user that exists with its password.
type couchbaseRESTStandIn struct {
	mu    sync.Mutex
	users map[string][2]string // password, roles
}

func newCouchbaseRESTStandIn(t *testing.T) (*couchbaseRESTStandIn, *httptest.Server) {
	t.Helper()
	cb := &couchbaseRESTStandIn{users: map[string][2]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb.mu.Lock()
		defer cb.mu.Unlock()
		user, pass, ok := r.BasicAuth()
		if r.URL.Path == "/query/service" {
			if stored, found := cb.users[user]; !ok || !found || stored[0] != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if !ok || user != "lab_admin" || pass != "lab-admin-password" { // #nosec G101 -- fabricated stand-in administrator (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name, found := strings.CutPrefix(r.URL.Path, "/settings/rbac/users/local/")
		switch {
		case !found:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPut && r.ParseForm() == nil:
			cb.users[name] = [2]string{r.PostForm.Get("password"), r.PostForm.Get("roles")}
			_, _ = w.Write([]byte(`""`))
		case r.Method == http.MethodDelete:
			if _, exists := cb.users[name]; !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(cb.users, name)
			_, _ = w.Write([]byte(`""`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return cb, srv
}

// A239 Couchbase, against a stand-in of the management REST API: a lease is a
// local user with its role's bucket roles; it renews within the maximum
// lifetime; revoking the lease deletes the user, after which its login is
// refused.
func TestServedDynamicCouchbaseUserIsDeletedAtRevocationA239(t *testing.T) {
	cb, srv := newCouchbaseRESTStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "couchbase", Type: "couchbase", Endpoint: srv.URL, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "couchbase-admin", "lab-admin-password"),
		AllowedRoles: []string{"orders"}, RoleBindings: map[string]string{"orders": "bucket_full_access on orders"},
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
	registerServedTenant(t, h, "A239 Couchbase tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-couchbase-lease-1",
		map[string]any{"provider": "couchbase", "role": "orders", "ttl_seconds": 600})
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
	login := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/query/service", nil)
		req.SetBasicAuth(credential.Username, credential.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	cb.mu.Lock()
	roles := cb.users[credential.Username][1]
	cb.mu.Unlock()
	if roles != "bucket_full_access[orders]" || login() != http.StatusOK {
		t.Fatalf("Couchbase user roles %q, login before revocation refused", roles)
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
	if code := login(); code != http.StatusUnauthorized {
		t.Fatalf("the deleted user still logs in: %d", code)
	}
}
