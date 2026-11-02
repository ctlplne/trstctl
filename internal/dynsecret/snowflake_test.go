// SPDX-License-Identifier: BUSL-1.1

package dynsecret

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

	"trstctl.com/trstctl/internal/crypto"
)

// snowflakeStandIn follows the SQL API (POST /api/v2/statements, key-pair JWT
// auth) as Snowflake's documentation describes it, for the statements the
// provider sends: a JWT verifies against the registered public key of the user
// its issuer names, whose fingerprint must match; a disabled or dropped user is
// refused (390144 / 390101).
type snowflakeStandIn struct {
	mu        sync.Mutex
	keys      map[string]string // user -> base64 SPKI
	disabled  map[string]bool
	grants    map[string][]string
	known     map[string]bool
	accepted  int // answer 202 for this many CREATE USER statements first
	pending   map[string]bool
	sqlByUser map[string][]string
}

var (
	sfCreate  = regexp.MustCompile(`^CREATE USER IF NOT EXISTS "([A-Z0-9_]+)" TYPE = SERVICE RSA_PUBLIC_KEY = '([A-Za-z0-9+/=]+)' DEFAULT_ROLE = "([A-Z0-9_$]+)" DAYS_TO_EXPIRY = ([0-9]+) COMMENT = 'trstctl dynamic secret'$`)
	sfAlter   = regexp.MustCompile(`^ALTER USER "([A-Z0-9_]+)" SET RSA_PUBLIC_KEY = '([A-Za-z0-9+/=]+)' DISABLED = FALSE DAYS_TO_EXPIRY = ([0-9]+)$`)
	sfGrant   = regexp.MustCompile(`^GRANT ROLE "([A-Z0-9_$]+)" TO USER "([A-Z0-9_]+)"$`)
	sfDisable = regexp.MustCompile(`^ALTER USER IF EXISTS "([A-Z0-9_]+)" SET DISABLED = TRUE$`)
	sfDrop    = regexp.MustCompile(`^DROP USER IF EXISTS "([A-Z0-9_]+)"$`)
)

func newSnowflakeStandIn(t *testing.T, adminSPKI []byte) (*snowflakeStandIn, *httptest.Server) {
	t.Helper()
	sf := &snowflakeStandIn{keys: map[string]string{"TRSTCTL_ADMIN": base64.StdEncoding.EncodeToString(adminSPKI)},
		disabled: map[string]bool{}, grants: map[string][]string{}, known: map[string]bool{"ANALYST": true, "REPORTER": true},
		pending: map[string]bool{}, sqlByUser: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sf.mu.Lock()
		defer sf.mu.Unlock()
		reply := func(status int, code, message string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "statementHandle": "0aa1b2c3-0000-1111-2222-333344445555"})
		}
		caller, ok := sf.authenticate(r)
		if !ok || r.Header.Get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT" {
			reply(http.StatusUnauthorized, "390144", "JWT token is invalid.")
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/statements/") {
			reply(http.StatusOK, "090001", "Statement executed successfully.")
			return
		}
		var in struct{ Statement string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		sf.sqlByUser[caller] = append(sf.sqlByUser[caller], in.Statement)
		if caller != "TRSTCTL_ADMIN" {
			reply(http.StatusOK, "090001", "Statement executed successfully.") // a leased user's own query
			return
		}
		switch {
		case sfCreate.MatchString(in.Statement):
			m := sfCreate.FindStringSubmatch(in.Statement)
			if _, exists := sf.keys[m[1]]; !exists {
				sf.keys[m[1]] = m[2]
			}
			if sf.accepted > 0 {
				sf.accepted--
				reply(http.StatusAccepted, "333334", "Asynchronous execution in progress.")
				return
			}
		case sfAlter.MatchString(in.Statement):
			m := sfAlter.FindStringSubmatch(in.Statement)
			sf.keys[m[1]], sf.disabled[m[1]] = m[2], false
		case sfGrant.MatchString(in.Statement):
			m := sfGrant.FindStringSubmatch(in.Statement)
			if !sf.known[m[1]] {
				reply(http.StatusUnprocessableEntity, "002003", "Role '"+m[1]+"' does not exist or not authorized.")
				return
			}
			for _, held := range sf.grants[m[2]] {
				if held == m[1] {
					reply(http.StatusOK, "090001", "Statement executed successfully.")
					return
				}
			}
			sf.grants[m[2]] = append(sf.grants[m[2]], m[1])
		case sfDisable.MatchString(in.Statement):
			sf.disabled[sfDisable.FindStringSubmatch(in.Statement)[1]] = true
		case sfDrop.MatchString(in.Statement):
			m := sfDrop.FindStringSubmatch(in.Statement)
			delete(sf.keys, m[1])
			delete(sf.grants, m[1])
		default:
			reply(http.StatusUnprocessableEntity, "001003", "SQL compilation error")
			return
		}
		reply(http.StatusOK, "090001", "Statement executed successfully.")
	}))
	t.Cleanup(srv.Close)
	return sf, srv
}

// authenticate verifies a key-pair JWT the way Snowflake does: the issuer
// names <ACCOUNT>.<USER>.SHA256:<fingerprint of the user's registered key>.
func (sf *snowflakeStandIn) authenticate(r *http.Request) (string, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iss, Sub string
		Exp      int64
	}
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	issuer := strings.SplitN(claims.Iss, ".", 3)
	if len(issuer) != 3 || issuer[0] != "LAB-ACCOUNT" || claims.Sub != issuer[0]+"."+issuer[1] {
		return "", false
	}
	user := issuer[1]
	registered, ok := sf.keys[user]
	if !ok || sf.disabled[user] {
		return "", false
	}
	spki, _ := base64.StdEncoding.DecodeString(registered)
	if issuer[2] != SnowflakeKeyFingerprint(spki) {
		return "", false
	}
	jwk, err := crypto.PublicJWK(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: spki}, "")
	if err != nil {
		return "", false
	}
	if _, err := crypto.VerifyJWT(token, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err != nil {
		return "", false
	}
	return user, true
}

func snowflakeTestKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	keyPEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, append([]byte(nil), signer.Public().DER...)
}

func newLabSnowflake(t *testing.T, srv *httptest.Server, adminKey []byte) *SnowflakeBackend {
	t.Helper()
	b, err := NewSnowflakeBackend(SnowflakeConfig{
		Endpoint: srv.URL, Account: "lab-account", AdminUser: "trstctl_admin", AdminPrivateKey: adminKey,
		RoleBindings: map[string]string{"analyst": "analyst, reporter", "broken": "no_such_role"}, MaxLifetime: 30 * time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestSnowflakeLeaseIsAKeyPairServiceUserA239(t *testing.T) {
	adminKey, adminSPKI := snowflakeTestKey(t)
	sf, srv := newSnowflakeStandIn(t, adminSPKI)
	sf.accepted = 1 // the first CREATE USER runs asynchronously
	b := newLabSnowflake(t, srv, adminKey)
	req := GenerateRequest{Role: "analyst", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Account, User, Role string
		PrivateKey          string    `json:"private_key"`
		UserExpiresAt       time.Time `json:"user_expires_at"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || got.User != user || got.Account != "LAB-ACCOUNT" || got.Role != "ANALYST" ||
		!strings.HasPrefix(got.PrivateKey, "-----BEGIN PRIVATE KEY-----") || got.UserExpiresAt.IsZero() {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	for _, statement := range sf.sqlByUser["TRSTCTL_ADMIN"] {
		if strings.Contains(statement, "PASSWORD") || strings.Contains(statement, "PRIVATE KEY") {
			t.Fatalf("a statement carries a secret: %q", statement)
		}
		if strings.Contains(statement, "DAYS_TO_EXPIRY") && !strings.Contains(statement, "DAYS_TO_EXPIRY = 2") {
			t.Fatalf("30h of maximum lifetime must expire the user in Snowflake after 2 days: %q", statement)
		}
	}
	if strings.Join(sf.grants[user], ",") != "ANALYST,REPORTER" {
		t.Fatalf("grants %v", sf.grants[user])
	}
	// The leased key authenticates as the user.
	login := func(keyPEM string) int {
		t.Helper()
		jwt, err := SnowflakeKeyPairJWT("lab-account", user, []byte(keyPEM), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v2/statements", strings.NewReader(`{"statement":"SELECT CURRENT_ROLE()"}`))
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := login(got.PrivateKey); code != http.StatusOK {
		t.Fatalf("the leased key did not authenticate: %d", code)
	}
	// A retry of the same lease installs a new key on the same user: the old one
	// stops working and no second user appears.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	var got2 struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(credential2, &got2)
	if err != nil || again != user || len(sf.keys) != 2 || login(got.PrivateKey) == http.StatusOK || login(got2.PrivateKey) != http.StatusOK {
		t.Fatalf("retry: %q (%v); users %d", again, err, len(sf.keys))
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, exists := sf.keys[user]; exists || login(got2.PrivateKey) == http.StatusOK {
		t.Fatal("the user survived revocation")
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a dropped user: %v", err)
	}
	for _, foreign := range []string{"TRSTCTL_ADMIN_X", "ACCOUNTADMIN", "trstctl_analyst_x", `TRSTCTL_"; DROP USER X; --`} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("dropped %q, a user this provider did not create", foreign)
		}
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "broken", LeaseID: "lease-0002"}); err == nil || len(sf.keys) != 1 {
		t.Fatalf("a failed grant: %v, users %d", err, len(sf.keys))
	}
}

func TestSnowflakeConfigA239(t *testing.T) {
	if roles, err := ParseSnowflakeRoles("analyst, Reporter_1"); err != nil || strings.Join(roles, ",") != "ANALYST,REPORTER_1" {
		t.Fatalf("roles %v (%v)", roles, err)
	}
	for _, bad := range []string{"", "analyst role", `"ANALYST"`, "1role", "a,,b"} {
		if _, err := ParseSnowflakeRoles(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	adminKey, _ := snowflakeTestKey(t)
	base := SnowflakeConfig{Endpoint: "https://org-acct.snowflakecomputing.com", Account: "org-acct", AdminUser: "trstctl_admin",
		AdminPrivateKey: adminKey, RoleBindings: map[string]string{"r": "analyst"}, MaxLifetime: time.Hour, HTTPClient: http.DefaultClient}
	if b, err := NewSnowflakeBackend(base); err != nil || b.expiryDays != 1 {
		t.Fatalf("base: %v", err)
	} else {
		b.Close()
	}
	for name, mutate := range map[string]func(*SnowflakeConfig){
		"plain http":    func(c *SnowflakeConfig) { c.Endpoint = "http://org-acct.snowflakecomputing.com" },
		"bad account":   func(c *SnowflakeConfig) { c.Account = "org acct" },
		"no admin":      func(c *SnowflakeConfig) { c.AdminUser = "" },
		"no key":        func(c *SnowflakeConfig) { c.AdminPrivateKey = nil },
		"not a key":     func(c *SnowflakeConfig) { c.AdminPrivateKey = []byte("not a key") },
		"no roles":      func(c *SnowflakeConfig) { c.RoleBindings = nil },
		"tiny lifetime": func(c *SnowflakeConfig) { c.MaxLifetime = time.Second },
	} {
		c := base
		mutate(&c)
		if b, err := NewSnowflakeBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIssuedPrincipalNameRequiresTheLeaseSuffixA239(t *testing.T) {
	for _, req := range []GenerateRequest{{Role: "reader", LeaseID: "lease-1"}, {Role: "Orders App", LeaseID: "lease-2"}, {Role: "x"}} {
		for _, prefix := range []string{"", "acme"} {
			name, err := scopedNameForRequest(prefix, req, 64, "_")
			if err != nil || !issuedPrincipalName(prefix, name) || !issuedPrincipalName(prefix, strings.ToUpper(name)) {
				t.Fatalf("an issued name %q (prefix %q) was refused: %v", name, prefix, err)
			}
		}
	}
	for _, foreign := range []string{"trstctl_admin", "TRSTCTL_ADMIN_X", "trstctl", "trstctl_", "trstctl_reader_01234567",
		"trstctl_reader_0123456789x", "trstctl_reader_01234567zz", "trstctl_reader-0123456789", "other_reader_0123456789", "trstctlx_reader_0123456789"} {
		if issuedPrincipalName("", foreign) {
			t.Errorf("%q was taken for an issued principal", foreign)
		}
	}
}
