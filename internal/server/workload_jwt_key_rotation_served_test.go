// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
)

// N5-L3: rotating the workload JWT signing key keeps every verifier working.
// The next key is published at the rotation and signs only from its activation,
// so a cloud that cached the key set in between verifies the first tokens the
// new key signs; the key it replaces stays published for the retain window
// after the switch, so tokens it signed keep verifying; then it leaves the set.
// The exchange's tokens and the Workload API's JWT-SVIDs sign with the same
// active key, a second rotation waits for the first, and a rebuild from the
// log reaches the same keys.
func TestServedWorkloadJWTKeyRotationKeepsTheOldKeyPublishedN5L3(t *testing.T) {
	const issuerBase = "https://issuer.trstctl.example.test"
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5l3-exchange-tenant")).String()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "cluster-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const k8sIssuer = m4K8sIssuer + "/n5l3"
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{
		{Name: "kubernetes", TenantID: tenant, Issuer: k8sIssuer, Audience: "trstctl",
			JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: issuerBase,
	}}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, tenant, "N5-L3 rotation tenant")
	sp := h.srv.spiffeForExchange()
	if sp == nil || sp.jwtKeys == nil {
		t.Fatal("the SPIFFE protocol has no rotating JWT key")
	}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	sp.jwtKeys.setClock(func() time.Time { return time.Unix(0, clock.Load()) })
	advance := func(d time.Duration) { clock.Add(int64(d)) }

	reader := seedScopedToken(t, h.store, tenant, "certs:read")
	rotator := seedScopedToken(t, h.store, tenant, "issuers:write")
	type keyView struct {
		KeyID       string     `json:"key_id"`
		Generation  int        `json:"generation"`
		State       string     `json:"state"`
		ActivatesAt *time.Time `json:"activates_at"`
		RetiresAt   *time.Time `json:"retires_at"`
	}
	keys := func() map[string]keyView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/workloads/jwt-keys", reader, nil)
		var out struct {
			Keys []keyView `json:"keys"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("jwt keys: HTTP %d %s", status, body)
		}
		byID := map[string]keyView{}
		for _, k := range out.Keys {
			byID[k.KeyID] = k
		}
		return byID
	}
	states := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for id, k := range keys() {
			out[id] = k.State
		}
		return out
	}
	published := func() crypto.JWKS {
		t.Helper()
		resp, err := h.ts.Client().Get(h.ts.URL + "/oidc/" + tenant + "/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var set crypto.JWKS
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&set) != nil {
			t.Fatalf("jwks: HTTP %d", resp.StatusCode)
		}
		return set
	}
	kids := func(set crypto.JWKS) []string {
		out := []string{}
		for _, k := range set.Keys {
			out = append(out, k.Kid)
		}
		slices.Sort(out)
		return out
	}
	exchange := func() string {
		t.Helper()
		now := time.Now()
		subject, err := crypto.SignJWT(signer, "cluster-sa-key", map[string]any{
			"iss": k8sIssuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{"namespace": "payments",
				"serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
				"pod":            map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject},
			"subject_token_type": {tokenTypeJWT}, "audience": {"sts.amazonaws.com"}}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
			t.Fatalf("exchange: HTTP %d %s", resp.StatusCode, body)
		}
		return out.AccessToken
	}
	kidOf := func(token string) string {
		t.Helper()
		header, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		var h struct {
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(header, &h); err != nil {
			t.Fatal(err)
		}
		return h.Kid
	}
	verifies := func(token string, set crypto.JWKS) bool {
		_, err := crypto.VerifyJWT(token, set)
		return err == nil
	}
	rotate := func(key string, publishAhead, retain int64) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/jwt-keys/rotate", rotator, key,
			map[string]any{"publish_ahead_seconds": publishAhead, "retain_seconds": retain})
	}

	// Before any rotation: one key signs and is published.
	if got := states(); len(got) != 1 || got["spiffe-jwt"] != "active" {
		t.Fatalf("keys before rotation: %v", got)
	}
	before := published()
	oldToken := exchange()
	if kidOf(oldToken) != "spiffe-jwt" || !verifies(oldToken, before) {
		t.Fatalf("the first token names %q", kidOf(oldToken))
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/jwt-keys/rotate", reader, "n5l3-reader-rotate",
		map[string]any{}); status != http.StatusForbidden {
		t.Fatalf("a certs:read token rotated the key: HTTP %d %s", status, body)
	}
	if status, body := rotate("n5l3-rotate-short", 3600, 60); status != http.StatusBadRequest {
		t.Fatalf("a retain window shorter than an hour: HTTP %d %s", status, body)
	}

	// Rotate: the next key is published an hour ahead of signing, and the
	// current one is kept two hours after the switch.
	if status, body := rotate("n5l3-rotate-1", 3600, 7200); status != http.StatusOK || !strings.Contains(string(body), `"spiffe-jwt-g2"`) {
		t.Fatalf("rotate: HTTP %d %s", status, body)
	}
	if got := states(); got["spiffe-jwt"] != "active" || got["spiffe-jwt-g2"] != "next" {
		t.Fatalf("keys after the rotation: %v", got)
	}
	ahead := published()
	if got := kids(ahead); !slices.Equal(got, []string{"spiffe-jwt", "spiffe-jwt-g2"}) {
		t.Fatalf("published ahead of the switch: %v", got)
	}
	if token := exchange(); kidOf(token) != "spiffe-jwt" {
		t.Fatalf("the next key signed before its activation: %q", kidOf(token))
	}
	if status, body := rotate("n5l3-rotate-2", 0, 3600); status != http.StatusConflict {
		t.Fatalf("a second rotation while one waits: HTTP %d %s", status, body)
	}
	if status, body := rotate("n5l3-rotate-1", 3600, 7200); status != http.StatusOK {
		t.Fatalf("the rotation's retry with its key: HTTP %d %s", status, body)
	}

	// The switch: the new key signs; a cloud holding the set it cached ahead
	// of the switch verifies the new tokens, and the old key's tokens still
	// verify against what is published now.
	advance(time.Hour + time.Second)
	newToken := exchange()
	if kidOf(newToken) != "spiffe-jwt-g2" {
		t.Fatalf("after the activation the token names %q", kidOf(newToken))
	}
	if !verifies(newToken, ahead) {
		t.Fatal("a key set cached ahead of the switch does not verify the new key's token")
	}
	if verifies(newToken, before) {
		t.Fatal("the key set from before the rotation verified a token the new key signed")
	}
	now := published()
	if !verifies(oldToken, now) || !slices.Equal(kids(now), []string{"spiffe-jwt", "spiffe-jwt-g2"}) {
		t.Fatalf("after the switch the published set %v does not verify the old key's token", kids(now))
	}
	svid, err := sp.issuer.SignJWTSVID(t.Context(), "spiffe://served.test/workload", []string{"payments"}, time.Minute)
	if err != nil || kidOf(svid) != "spiffe-jwt-g2" || !verifies(svid, now) {
		t.Fatalf("the Workload API's JWT-SVID names %q: %v", kidOf(svid), err)
	}
	k := keys()
	if k["spiffe-jwt"].State != "retiring" || k["spiffe-jwt-g2"].State != "active" || k["spiffe-jwt"].RetiresAt == nil ||
		!k["spiffe-jwt"].RetiresAt.Equal(k["spiffe-jwt-g2"].ActivatesAt.Add(2*time.Hour)) {
		t.Fatalf("keys after the switch: %+v", k)
	}

	// Past the retain window the old key leaves the set.
	advance(2 * time.Hour)
	after := published()
	if got := kids(after); !slices.Equal(got, []string{"spiffe-jwt-g2"}) {
		t.Fatalf("published after the retain window: %v", got)
	}
	if verifies(oldToken, after) || !verifies(newToken, after) {
		t.Fatal("after the retain window the set still verifies the old key's token, or not the new one's")
	}
	if got := states(); got["spiffe-jwt"] != "retired" || got["spiffe-jwt-g2"] != "active" {
		t.Fatalf("keys after the retain window: %v", got)
	}

	// The rotation is an event: a rebuild from the log reaches the same keys.
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	sp.jwtKeys.invalidate()
	if got := states(); got["spiffe-jwt"] != "retired" || got["spiffe-jwt-g2"] != "active" {
		t.Fatalf("keys after a rebuild: %v", got)
	}
	if token := exchange(); kidOf(token) != "spiffe-jwt-g2" {
		t.Fatalf("after a rebuild the token names %q", kidOf(token))
	}
}
