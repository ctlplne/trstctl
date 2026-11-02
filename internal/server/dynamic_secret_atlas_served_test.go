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

const atlasServedGroup = "5f1e2d3c4b5a69788796a5b4"

// atlasAdminStandIn follows the Admin API v2 database-user endpoints and the
// service account token endpoint as Atlas's documentation describes them, and
// answers a login check for a user that exists with its password.
type atlasAdminStandIn struct {
	mu    sync.Mutex
	users map[string]map[string]any
}

func newAtlasAdminStandIn(t *testing.T) (*atlasAdminStandIn, *httptest.Server) {
	t.Helper()
	atlas := &atlasAdminStandIn{users: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atlas.mu.Lock()
		defer atlas.mu.Unlock()
		switch r.URL.Path {
		case "/login":
			user, pass, ok := r.BasicAuth()
			if stored, found := atlas.users[user]; !ok || !found || stored["password"] != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		case "/api/oauth/token":
			if id, secret, ok := r.BasicAuth(); !ok || id != "mdb_sa_id_lab" || secret != "mdb_sa_sk_lab" { // #nosec G101 -- fabricated stand-in service account (CWE-798)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "atlas-lab-token", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer atlas-lab-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		users := "/api/atlas/v2/groups/" + atlasServedGroup + "/databaseUsers"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			var user map[string]any
			_ = json.NewDecoder(r.Body).Decode(&user)
			atlas.users[user["username"].(string)] = user
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, users+"/admin/"):
			delete(atlas.users, strings.TrimPrefix(r.URL.Path, users+"/admin/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return atlas, srv
}

// A239 MongoDB Atlas, against a stand-in of the Admin API: a lease is a
// database user with the role's built-in roles and an Atlas deleteAfterDate;
// it renews within the maximum lifetime; revoking the lease deletes the user,
// after which its login is refused.
func TestServedDynamicMongoDBAtlasUserIsDeletedAtRevocationA239(t *testing.T) {
	atlas, srv := newAtlasAdminStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "atlas", Type: "mongodb-atlas", Endpoint: srv.URL, Project: atlasServedGroup,
		ClientID: "mdb_sa_id_lab", ClientSecretRef: writeServedCredentialFile(t, "atlas-sa", "mdb_sa_sk_lab"),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on orders"},
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
	registerServedTenant(t, h, "A239 MongoDB Atlas tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-atlas-lease-1",
		map[string]any{"provider": "atlas", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Username        string    `json:"username"`
		Password        string    `json:"password"`
		DeleteAfterDate time.Time `json:"delete_after_date"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.DeleteAfterDate.IsZero() {
		t.Fatalf("credential: %+v %v", credential, err)
	}
	login := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/login", nil)
		req.SetBasicAuth(credential.Username, credential.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	atlas.mu.Lock()
	roles, _ := json.Marshal(atlas.users[credential.Username]["roles"])
	atlas.mu.Unlock()
	if string(roles) != `[{"databaseName":"orders","roleName":"read"}]` || login() != http.StatusOK {
		t.Fatalf("Atlas user roles %s, login before revocation refused", roles)
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
