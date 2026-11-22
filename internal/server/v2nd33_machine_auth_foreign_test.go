// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestV2ND33ServedMachineLoginForeignCloudTenant (S11-L17, served): a gcp and an
// azure machine-auth method with no issuer/project/tenant boundary must fail
// startup validation. The served verifier must also refuse a token from a
// foreign Google project or Entra tenant even if a caller bypasses startup
// validation and constructs the methods directly. One local key stands in for
// each provider's shared JWKS.
func TestV2ND33ServedMachineLoginForeignCloudTenant(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "provider-shared-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []config.MachineAuthMethod{
		{Name: "gcp", TenantID: servedTestTenant, Audience: "https://trstctl.example.test",
			JWKSJSON: string(jwks), Scopes: []string{"secrets:read"}},
		{Name: "azure", TenantID: servedTestTenant, Audience: "api://trstctl",
			JWKSJSON: string(jwks), Scopes: []string{"secrets:read"}},
	}
	c := config.Default()
	c.Secrets.MachineAuth = cfgs
	if err := c.Validate(); err == nil {
		t.Error("issuerless GCP and Azure machine auth passed startup validation")
	}
	methods, err := machineAuthMethodsFromConfig(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenant(t, h, "V2ND-33 foreign cloud tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "v2nd33-admin", "secrets:read", "secrets:write")
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", admin, "v2nd33-seed",
		map[string]any{"name": "v2nd33/prod/db-password", "value": "pw-v2nd33"}); status != http.StatusCreated {
		t.Fatalf("seed secret: HTTP %d %s", status, raw)
	}
	now := time.Now()
	foreign := map[string]map[string]any{
		"gcp": {
			"iss": "https://accounts.google.com", "aud": "https://trstctl.example.test", "sub": "109876543210",
			"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(),
			"google": map[string]any{"compute_engine": map[string]any{
				"project_id": "someone-elses-project", "instance_id": "4242", "zone": "us-central1-a", "instance_name": "attacker-vm",
			}},
		},
		"azure": {
			"iss": "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0", "aud": "api://trstctl",
			"tid": "99999999-9999-9999-9999-999999999999", "oid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			"sub": "attacker-app", "exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(),
		},
	}
	for _, method := range []string{"gcp", "azure"} {
		jwt, err := crypto.SignJWT(signer, "provider-shared-key", foreign[method])
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"method": method, "credential": jwt})
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("Idempotency-Key", "v2nd33-login-"+method)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Logf("%s: foreign token refused: HTTP %d", method, resp.StatusCode)
			continue
		}
		var out struct {
			Principal string   `json:"principal"`
			Scopes    []string `json:"scopes"`
			Token     string   `json:"token"`
		}
		_ = json.Unmarshal(raw, &out)
		readStatus, _ := secretsReqKey(t, h, http.MethodGet, "/api/v1/secrets/store/v2nd33/prod/db-password", out.Token, "", nil)
		t.Errorf("%s: token from a foreign project/tenant logged in (HTTP 200, principal %q, scopes %v) and read the tenant's secret (HTTP %d)",
			method, out.Principal, out.Scopes, readStatus)
	}
}
