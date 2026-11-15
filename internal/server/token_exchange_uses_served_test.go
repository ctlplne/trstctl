// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestServedTokenExchangeHonorsTheMethodsExchangeUsesM4L4 is M4-L4's
// Done-when (served): RFC 8693 does not require a subject token to be used
// once, and a pod that exchanges its kubelet-projected token more than once
// per rotation needs the same token to work again. A kubernetes method with
// exchange_uses 3 lets one pod token make three exchanges and refuses the
// fourth, naming the count; an oidc method left at the default refuses a
// CI token's second exchange as before; a refused exchange issues nothing;
// and the methods list names the count for the console.
func TestServedTokenExchangeHonorsTheMethodsExchangeUsesM4L4(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "m4l4-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const ciIssuer = "https://ci-m4l4.example.test"
	cfgs := []config.MachineAuthMethod{
		{Name: "oidc", TenantID: servedTestTenant, Issuer: ciIssuer, Audience: "trstctl", JWKSJSON: string(jwks), Scopes: []string{"secrets:read"}},
		{Name: "kubernetes", TenantID: servedTestTenant, Issuer: m4K8sIssuer, Audience: "trstctl", JWKSJSON: string(jwks),
			AllowedNamespaces: []string{"m4l4"}, Scopes: []string{"secrets:read"}, ExchangeUses: 3},
	}
	methods, err := machineAuthMethodsFromConfig(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	clearRecords := func(ctx context.Context) {
		if _, err := h.store.SystemPool().Exec(ctx, `DELETE FROM machine_credential_replays WHERE tenant_id = $1`, h.tenant); err != nil {
			t.Fatal(err)
		}
	}
	clearRecords(t.Context())
	t.Cleanup(func() { clearRecords(context.Background()) })
	mint := func(claims map[string]any) string {
		t.Helper()
		now := time.Now()
		claims["aud"], claims["iat"], claims["exp"], claims["jti"] = "trstctl", now.Unix(), now.Add(10*time.Minute).Unix(), uuid.NewString()
		tok, err := crypto.SignJWT(signer, "m4l4-key", claims)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exchange := func(subject string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject},
			"subject_token_type": {tokenTypeJWT}, "audience": {"https://m4l4.internal"}}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", h.tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out
	}

	pod := mint(map[string]any{"iss": m4K8sIssuer, "sub": "system:serviceaccount:m4l4:api",
		"kubernetes.io": map[string]any{"namespace": "m4l4", "serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()}}})
	issued := map[string]bool{}
	for i := 1; i <= 3; i++ {
		status, out := exchange(pod)
		token, _ := out["access_token"].(string)
		if status != http.StatusOK || token == "" || issued[token] {
			t.Fatalf("exchange %d of 3 with one pod token: HTTP %d %v", i, status, out["error_description"])
		}
		issued[token] = true
	}
	if status, out := exchange(pod); status != http.StatusBadRequest || out["error"] != "invalid_grant" ||
		!strings.Contains(out["error_description"].(string), "made its 3 exchanges") || out["access_token"] != nil {
		t.Fatalf("a fourth exchange with the pod token: HTTP %d %v; want invalid_grant naming its 3 exchanges", status, out)
	}

	ci := mint(map[string]any{"iss": ciIssuer, "sub": "repo:m4l4:ref:main"})
	if status, out := exchange(ci); status != http.StatusOK {
		t.Fatalf("a CI token's first exchange: HTTP %d %v", status, out)
	}
	if status, out := exchange(ci); status != http.StatusBadRequest || out["error_description"] != "the subject token was already used" {
		t.Fatalf("a CI token's second exchange: HTTP %d %v; want it refused as used", status, out)
	}

	var uses int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT uses FROM machine_credential_replays WHERE tenant_id = $1 AND method = 'kubernetes'`, h.tenant).Scan(&uses); err != nil || uses != 3 {
		t.Fatalf("the pod token's record counts %d uses (%v), want 3", uses, err)
	}
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "m4l4-reader", "secrets:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/auth-methods", reader, nil)
	var listed struct {
		Items []struct {
			Name         string `json:"name"`
			ExchangeUses int    `json:"exchange_uses"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &listed) != nil {
		t.Fatalf("auth methods: HTTP %d %s", status, raw)
	}
	counts := map[string]int{}
	for _, m := range listed.Items {
		counts[m.Name] = m.ExchangeUses
	}
	if counts["kubernetes"] != 3 || counts["oidc"] != 0 {
		t.Fatalf("the methods list names exchange uses %v; want kubernetes 3 and oidc absent", counts)
	}
	t.Log("M4L4_OK")
}
