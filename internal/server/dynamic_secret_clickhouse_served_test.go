// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// clickHouseHTTPFake keeps the users and role grants its administrator's
// statements create, and answers a read of lab.orders for a user that exists
// and holds orders_reader, as ClickHouse's HTTP interface does.
type clickHouseHTTPFake struct {
	mu    sync.Mutex
	users map[string]string // user -> password
	roles map[string]string // user -> granted role
}

var (
	clickHouseCreate = regexp.MustCompile(`^CREATE USER OR REPLACE (\w+) IDENTIFIED WITH sha256_password BY '([0-9a-f]+)' VALID UNTIL '[0-9TZ:-]+'$`)
	clickHouseGrant  = regexp.MustCompile(`^GRANT (\w+) TO (\w+)$`)
	clickHouseDrop   = regexp.MustCompile(`^DROP USER IF EXISTS (\w+)$`)
)

func newClickHouseHTTPFake(t *testing.T) (*clickHouseHTTPFake, *httptest.Server) {
	t.Helper()
	fake := &clickHouseHTTPFake{users: map[string]string{}, roles: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		body, _ := io.ReadAll(r.Body)
		statement := string(body)
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if ok && user == "lab_admin" && pass == "lab-admin-password" { // #nosec G101 -- fabricated lab administrator password (CWE-798)
			switch {
			case clickHouseCreate.MatchString(statement):
				m := clickHouseCreate.FindStringSubmatch(statement)
				fake.users[m[1]] = m[2]
			case clickHouseGrant.MatchString(statement):
				m := clickHouseGrant.FindStringSubmatch(statement)
				fake.roles[m[2]] = m[1]
			case clickHouseDrop.MatchString(statement):
				m := clickHouseDrop.FindStringSubmatch(statement)
				delete(fake.users, m[1])
				delete(fake.roles, m[1])
			case strings.HasPrefix(statement, "SET DEFAULT ROLE "):
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}
		if !ok || fake.users[user] == "" || fake.users[user] != pass {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Code: 516. DB::Exception: Authentication failed. (AUTHENTICATION_FAILED)"))
			return
		}
		if statement != "SELECT count() FROM lab.orders" || fake.roles[user] != "orders_reader" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Code: 497. DB::Exception: Not enough privileges. (ACCESS_DENIED)"))
			return
		}
		_, _ = w.Write([]byte("2\n"))
	}))
	t.Cleanup(srv.Close)
	return fake, srv
}

func (f *clickHouseHTTPFake) userCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users)
}

// A239 ClickHouse, served: a lease is a ClickHouse user holding the bound role
// that can read the bound database; it renews within the provider's maximum
// lifetime; revoking the lease drops the user, after which the login fails.
func TestServedDynamicClickHouseLeaseIsDroppedAtRevocationA239(t *testing.T) {
	fake, srv := newClickHouseHTTPFake(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "warehouse", Type: "clickhouse", Endpoint: srv.URL, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "clickhouse-admin", "lab-admin-password"),
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
	registerServedTenant(t, h, "A239 ClickHouse tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-clickhouse-lease-1",
		map[string]any{"provider": "warehouse", "role": "reader", "ttl_seconds": 600})
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
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Password == "" {
		t.Fatalf("credential: %v", err)
	}
	query := func(statement string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(statement))
		req.SetBasicAuth(credential.Username, credential.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := query("SELECT count() FROM lab.orders"); code != http.StatusOK {
		t.Fatalf("the leased user could not read lab.orders: %d", code)
	}
	if code := query("INSERT INTO lab.orders VALUES (3)"); code == http.StatusOK {
		t.Fatal("the leased user could write")
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
	if code := query("SELECT count() FROM lab.orders"); code != http.StatusForbidden {
		t.Fatalf("the dropped user still logs in: %d", code)
	}
	if n := fake.userCount(); n != 0 {
		t.Fatalf("%d leased users left behind", n)
	}
}
