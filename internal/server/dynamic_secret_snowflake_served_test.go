// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
)

var (
	snowflakeServedCreate = regexp.MustCompile(`^CREATE USER IF NOT EXISTS "([A-Z0-9_]+)" .*RSA_PUBLIC_KEY = '([A-Za-z0-9+/=]+)'`)
	snowflakeServedAlter  = regexp.MustCompile(`^ALTER USER "([A-Z0-9_]+)" SET RSA_PUBLIC_KEY = '([A-Za-z0-9+/=]+)' DISABLED = FALSE`)
	snowflakeServedOff    = regexp.MustCompile(`^ALTER USER IF EXISTS "([A-Z0-9_]+)" SET DISABLED = TRUE$`)
	snowflakeServedDrop   = regexp.MustCompile(`^DROP USER IF EXISTS "([A-Z0-9_]+)"$`)
)

// snowflakeSQLAPIStandIn follows the SQL API's key-pair JWT authentication and
// the user statements the provider sends, as Snowflake's documentation
// describes them; a disabled or dropped user's JWT is refused.
type snowflakeSQLAPIStandIn struct {
	mu       sync.Mutex
	keys     map[string]string
	disabled map[string]bool
}

func newSnowflakeSQLAPIStandIn(t *testing.T, adminSPKI []byte) (*snowflakeSQLAPIStandIn, *httptest.Server) {
	t.Helper()
	sf := &snowflakeSQLAPIStandIn{keys: map[string]string{"TRSTCTL_ADMIN": base64.StdEncoding.EncodeToString(adminSPKI)}, disabled: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sf.mu.Lock()
		defer sf.mu.Unlock()
		reply := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": "stand-in"})
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		var claims struct{ Iss string }
		if len(parts) == 3 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(payload, &claims)
		}
		issuer := strings.SplitN(claims.Iss, ".", 3)
		if len(issuer) != 3 || issuer[0] != "SERVED-LAB" || sf.disabled[issuer[1]] {
			reply(http.StatusUnauthorized, "390144")
			return
		}
		spki, _ := base64.StdEncoding.DecodeString(sf.keys[issuer[1]])
		jwk, err := crypto.PublicJWK(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: spki}, "")
		if err != nil || issuer[2] != dynsecret.SnowflakeKeyFingerprint(spki) {
			reply(http.StatusUnauthorized, "390144")
			return
		}
		if _, err := crypto.VerifyJWT(token, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err != nil {
			reply(http.StatusUnauthorized, "390144")
			return
		}
		var in struct{ Statement string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if issuer[1] != "TRSTCTL_ADMIN" {
			reply(http.StatusOK, "090001") // the leased user's own query
			return
		}
		switch {
		case snowflakeServedCreate.MatchString(in.Statement):
			m := snowflakeServedCreate.FindStringSubmatch(in.Statement)
			if _, ok := sf.keys[m[1]]; !ok {
				sf.keys[m[1]] = m[2]
			}
		case snowflakeServedAlter.MatchString(in.Statement):
			m := snowflakeServedAlter.FindStringSubmatch(in.Statement)
			sf.keys[m[1]], sf.disabled[m[1]] = m[2], false
		case snowflakeServedOff.MatchString(in.Statement):
			sf.disabled[snowflakeServedOff.FindStringSubmatch(in.Statement)[1]] = true
		case snowflakeServedDrop.MatchString(in.Statement):
			delete(sf.keys, snowflakeServedDrop.FindStringSubmatch(in.Statement)[1])
		case strings.HasPrefix(in.Statement, `GRANT ROLE "ANALYST" TO USER "`):
		default:
			reply(http.StatusUnprocessableEntity, "001003")
			return
		}
		reply(http.StatusOK, "090001")
	}))
	t.Cleanup(srv.Close)
	return sf, srv
}

// A239 Snowflake, against a stand-in of the SQL API: a lease is a key-pair
// service user whose private key logs in; it renews within the maximum
// lifetime; revoking the lease disables and drops it, after which its key is
// refused.
func TestServedDynamicSnowflakeUserIsDroppedAtRevocationA239(t *testing.T) {
	admin, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	adminPEM, err := admin.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sf, srv := newSnowflakeSQLAPIStandIn(t, admin.Public().DER)
	admin.Destroy()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "snowflake", Type: "snowflake", Endpoint: srv.URL, Account: "served-lab", AdminUser: "trstctl_admin",
		PrivateKeyRef: writeServedCredentialFile(t, "snowflake-admin", string(adminPEM)),
		AllowedRoles:  []string{"analyst"}, RoleBindings: map[string]string{"analyst": "ANALYST"}, MaxTTL: "8h", AllowInsecureLoopback: true,
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
	registerServedTenant(t, h, "A239 Snowflake tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-snowflake-lease-1",
		map[string]any{"provider": "snowflake", "role": "analyst", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Account, User string
		PrivateKey    string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.User == "" || credential.PrivateKey == "" {
		t.Fatalf("credential: %v", err)
	}
	login := func() int {
		t.Helper()
		jwt, err := dynsecret.SnowflakeKeyPairJWT(credential.Account, credential.User, []byte(credential.PrivateKey), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v2/statements", strings.NewReader(`{"statement":"SELECT CURRENT_ROLE()"}`))
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := login(); code != http.StatusOK {
		t.Fatalf("the leased key before revocation: %d", code)
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
	sf.mu.Lock()
	_, exists := sf.keys[credential.User]
	sf.mu.Unlock()
	if code := login(); code != http.StatusUnauthorized || exists {
		t.Fatalf("the dropped user's key still logs in: %d (user exists: %t)", code, exists)
	}
}
