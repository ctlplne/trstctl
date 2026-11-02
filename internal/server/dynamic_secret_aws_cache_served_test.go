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
	"trstctl.com/trstctl/internal/redisacl"
)

// elastiCacheStandIn follows the ElastiCache Query API for RBAC users (SigV4
// scoped to elasticache) and answers an AUTH check for a user that exists with
// its password and is in the user group.
type elastiCacheStandIn struct {
	mu    sync.Mutex
	users map[string][2]string // password, access
	group map[string]bool
}

func newElastiCacheStandIn(t *testing.T) (*elastiCacheStandIn, *httptest.Server) {
	t.Helper()
	ec := &elastiCacheStandIn{users: map[string][2]string{}, group: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ec.mu.Lock()
		defer ec.mu.Unlock()
		if r.URL.Path == "/auth" {
			user, pass, _ := r.BasicAuth()
			if stored, ok := ec.users[user]; !ok || stored[0] != pass || !ec.group[user] {
				w.WriteHeader(http.StatusUnauthorized) // WRONGPASS
				return
			}
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/elasticache/aws4_request") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		refuse := func(code string) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<ErrorResponse><Error><Code>" + code + "</Code></Error></ErrorResponse>"))
		}
		id := r.PostForm.Get("UserId")
		switch r.PostForm.Get("Action") {
		case "CreateUser":
			if _, ok := ec.users[id]; ok {
				refuse("UserAlreadyExists")
				return
			}
			ec.users[id] = [2]string{r.PostForm.Get("Passwords.member.1"), r.PostForm.Get("AccessString")}
		case "ModifyUser":
			ec.users[id] = [2]string{r.PostForm.Get("Passwords.member.1"), r.PostForm.Get("AccessString")}
		case "ModifyUserGroup":
			ec.group[r.PostForm.Get("UserIdsToAdd.member.1")] = true
		case "DeleteUser":
			if _, ok := ec.users[id]; !ok {
				refuse("UserNotFound")
				return
			}
			delete(ec.users, id)
			delete(ec.group, id)
		default:
			refuse("InvalidAction")
			return
		}
		_, _ = w.Write([]byte("<Response/>"))
	}))
	t.Cleanup(srv.Close)
	return ec, srv
}

// A239 ElastiCache, against a stand-in of its API: a lease is an RBAC user with
// the role's access string in the user group; it renews within the maximum
// lifetime; revoking the lease deletes the user, after which AUTH fails.
func TestServedDynamicElastiCacheUserIsDeletedAtRevocationA239(t *testing.T) {
	ec, srv := newElastiCacheStandIn(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "cache", Type: "aws-elasticache", Endpoint: srv.URL, Region: "us-east-1",
		AccessKeyID: "AKIASERVED", SecretAccessRef: writeServedCredentialFile(t, "elasticache-secret", "served-secret"),
		UserGroup: "orders-group", AllowedRoles: []string{"reader"}, MaxTTL: "1h", AllowInsecureLoopback: true,
		RedisACLRoles: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}},
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
	registerServedTenant(t, h, "A239 ElastiCache tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-elasticache-lease-1",
		map[string]any{"provider": "cache", "role": "reader", "ttl_seconds": 600})
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
	auth := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/auth", nil)
		req.SetBasicAuth(credential.Username, credential.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	ec.mu.Lock()
	access := ec.users[credential.Username][1]
	ec.mu.Unlock()
	if access != "on ~orders:* -@all +get +ping" || auth() != http.StatusOK {
		t.Fatalf("access string %q, AUTH before revocation refused", access)
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
	if code := auth(); code != http.StatusUnauthorized {
		t.Fatalf("the deleted user still authenticates: %d", code)
	}
}
