// SPDX-License-Identifier: BUSL-1.1

package server

import (
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
	snowflakeKeySet   = regexp.MustCompile(`^ALTER USER "([A-Z0-9_]+)" SET (RSA_PUBLIC_KEY(?:_2)?) = '([A-Za-z0-9+/=]+)'$`)
	snowflakeKeyUnset = regexp.MustCompile(`^ALTER USER "([A-Z0-9_]+)" UNSET (RSA_PUBLIC_KEY(?:_2)?)$`)
	snowflakeDescUser = regexp.MustCompile(`^DESC USER "([A-Z0-9_]+)"$`)
)

// snowflakeKeySlotsStandIn follows the SQL API's key-pair JWT authentication
// with Snowflake's two key slots per user: a JWT is accepted when the
// fingerprint it names is in one of the user's slots and its signature
// verifies with that key; DESC USER reports each slot's fingerprint.
type snowflakeKeySlotsStandIn struct {
	mu    sync.Mutex
	slots map[string]map[string]string // user -> property -> base64 SPKI
}

func (sf *snowflakeKeySlotsStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	reply := func(status int, body map[string]any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var claims struct{ Iss string }
	if parts := strings.Split(token, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &claims)
	}
	issuer := strings.SplitN(claims.Iss, ".", 3)
	authenticated := false
	if len(issuer) == 3 && issuer[0] == "SERVED-LAB" {
		for _, encoded := range sf.slots[issuer[1]] {
			spki, _ := base64.StdEncoding.DecodeString(encoded)
			if encoded == "" || dynsecret.SnowflakeKeyFingerprint(spki) != issuer[2] {
				continue
			}
			jwk, err := crypto.PublicJWK(crypto.PublicKey{Algorithm: crypto.RSA2048, DER: spki}, "")
			if _, verr := crypto.VerifyJWT(token, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err == nil && verr == nil {
				authenticated = true
			}
		}
	}
	if !authenticated {
		reply(http.StatusUnauthorized, map[string]any{"code": "390144", "message": "JWT token is invalid"})
		return
	}
	var in struct{ Statement string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	if issuer[1] != "TRSTCTL_ADMIN" {
		reply(http.StatusOK, map[string]any{"code": "090001", "data": [][]string{{"1"}}})
		return
	}
	switch {
	case snowflakeDescUser.MatchString(in.Statement):
		user := snowflakeDescUser.FindStringSubmatch(in.Statement)[1]
		var rows [][]*string
		for _, property := range []string{"RSA_PUBLIC_KEY", "RSA_PUBLIC_KEY_2"} {
			name, value := property+"_FP", "null"
			if encoded := sf.slots[user][property]; encoded != "" {
				spki, _ := base64.StdEncoding.DecodeString(encoded)
				value = dynsecret.SnowflakeKeyFingerprint(spki)
			}
			rows = append(rows, []*string{&name, &value})
		}
		reply(http.StatusOK, map[string]any{"code": "090001", "data": rows})
		return
	case snowflakeKeySet.MatchString(in.Statement):
		m := snowflakeKeySet.FindStringSubmatch(in.Statement)
		sf.slots[m[1]][m[2]] = m[3]
	case snowflakeKeyUnset.MatchString(in.Statement):
		m := snowflakeKeyUnset.FindStringSubmatch(in.Statement)
		sf.slots[m[1]][m[2]] = ""
	default:
		reply(http.StatusUnprocessableEntity, map[string]any{"code": "001003", "message": "unexpected statement"})
		return
	}
	reply(http.StatusOK, map[string]any{"code": "090001"})
}

// A240 Snowflake key pairs, against a stand-in of the SQL API: a role bound to
// "user ETL_SVC" rotates that user's key pair through its two slots; the first
// rotation retires the user's original key, and each later one keeps both keys
// signing in until retirement unsets the predecessor's slot.
func TestServedSnowflakeKeyPairRotationA240(t *testing.T) {
	admin, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Destroy()
	adminPEM, err := admin.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	original, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Destroy()
	originalPEM, err := original.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	vendor := &snowflakeKeySlotsStandIn{slots: map[string]map[string]string{
		"TRSTCTL_ADMIN": {"RSA_PUBLIC_KEY": base64.StdEncoding.EncodeToString(admin.Public().DER)},
		"ETL_SVC":       {"RSA_PUBLIC_KEY": base64.StdEncoding.EncodeToString(original.Public().DER)},
	}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	signsIn := func(t *testing.T, privateKeyPEM string) bool {
		t.Helper()
		jwt, err := dynsecret.SnowflakeKeyPairJWT("served-lab", "ETL_SVC", []byte(privateKeyPEM), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, stand.URL+"/api/v2/statements", strings.NewReader(`{"statement":"SELECT 1"}`))
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	seed, _ := json.Marshal(map[string]string{"account": "SERVED-LAB", "user": "ETL_SVC", "private_key": string(originalPEM)})
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "snowflake-keys", Type: "snowflake", Endpoint: stand.URL, Account: "served-lab",
			AdminUser: "TRSTCTL_ADMIN", PrivateKeyRef: writeServedCredentialFile(t, "snowflake-admin.pem", string(adminPEM)),
			AllowedRoles: []string{"snowflake/etl"}, RoleBindings: map[string]string{"snowflake/etl": "user ETL_SVC"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "snowflake/etl", seed: string(seed),
		firstOldRef: "ETL_SVC/1/" + dynsecret.SnowflakeKeyFingerprint(original.Public().DER),
		keyOf:       hostedKeyOf("private_key"), authenticates: signsIn,
		newRefPrefix: "ETL_SVC/2/SHA256:", wantVerifyMode: "authenticated",
	}.run(t)
	if signsIn(t, string(originalPEM)) {
		t.Fatal("the user's original key still signs in after the first rotation retired it")
	}
}
