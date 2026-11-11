// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestServedTOTPSeedIsReplacedThroughTheAPIA239L5 is A239-L5 over the served
// API and the CLI. A TOTP provider keeps its seed in the tenant secret store
// (secret://). Its leases' codes come from that seed until a replacement is
// brought with a current code from it:
//   - a code from another seed is refused (422) and nothing is written;
//   - a caller without secrets:write is refused, an unknown provider is 404,
//     and a provider whose seed is in a file is 409;
//   - with its code the replacement is the seed reference's next version, and
//     the next lease's code comes from it;
//   - the CLI replaces it again.
func TestServedTOTPSeedIsReplacedThroughTheAPIA239L5(t *testing.T) {
	const (
		seedA = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		seedB = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	)
	// The providers as an operator writes them.
	var configs []config.DynamicSecretProviderConfig
	if err := json.Unmarshal([]byte(`[{"tenant_id": "`+servedTestTenant+`", "id": "mfa", "type": "totp",
	    "seed_ref": "secret://ops/break-glass-mfa", "allowed_roles": ["operator"], "max_ttl": "30s"},
	  {"tenant_id": "`+servedTestTenant+`", "id": "mfa-file", "type": "totp",
	    "seed_ref": "`+writeServedCredentialFile(t, "a239l5-seed", seedA)+`", "allowed_roles": ["operator"], "max_ttl": "30s"}]`), &configs); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, d.Store, d.KEK, nil)
		if err != nil {
			t.Fatal(err)
		}
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239-L5 TOTP seed tenant")
	startServedExternalCADispatcher(t, h)
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a239l5-admin", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "a239l5-reader", "secrets:read")
	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	codeFor := func(seed string, at time.Time) string {
		t.Helper()
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
		if err != nil {
			t.Fatal(err)
		}
		code, err := crypto.HOTP(key, uint64(at.Unix()/30), 6, "SHA1") // #nosec G115 -- a positive clock step in a test (CWE-190)
		if err != nil {
			t.Fatal(err)
		}
		return string(code)
	}
	version := func() int {
		t.Helper()
		var meta struct {
			Version int `json:"version"`
		}
		_ = json.Unmarshal(call(admin, http.MethodGet, "/api/v1/secrets/store/ops/break-glass-mfa", "", nil, http.StatusOK), &meta)
		return meta.Version
	}
	leaseFrom := func(key, seed string) {
		t.Helper()
		var lease dynamicLeaseView
		if err := json.Unmarshal(call(admin, http.MethodPost, "/api/v1/secrets/leases", key,
			map[string]any{"provider": "mfa", "role": "operator", "ttl_seconds": 30}, http.StatusCreated), &lease); err != nil {
			t.Fatal(err)
		}
		var credential struct {
			Code       string    `json:"code"`
			ValidUntil time.Time `json:"valid_until"`
		}
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil {
			t.Fatal(err)
		}
		if want := codeFor(seed, credential.ValidUntil.Add(-time.Second)); credential.Code != want {
			t.Fatalf("lease %s: code %s, want %s from the seed %s…", key, credential.Code, want, seed[:4])
		}
	}
	const replace = "/api/v1/secrets/leases/providers/mfa/totp-seed"

	call(admin, http.MethodPost, "/api/v1/secrets/store", "a239l5-seed-a", map[string]any{"name": "ops/break-glass-mfa", "value": seedA}, http.StatusCreated)
	leaseFrom("a239l5-lease-a", seedA)

	// A code from another seed proves nothing: refused, nothing written.
	call(admin, http.MethodPost, replace, "a239l5-wrong-code", map[string]any{"seed": seedB, "code": codeFor(seedA, time.Now())}, http.StatusUnprocessableEntity)
	call(admin, http.MethodPost, replace, "a239l5-not-base32", map[string]any{"seed": "not a seed!", "code": "123456"}, http.StatusUnprocessableEntity)
	call(reader, http.MethodPost, replace, "a239l5-reader", map[string]any{"seed": seedB, "code": codeFor(seedB, time.Now())}, http.StatusForbidden)
	call(admin, http.MethodPost, "/api/v1/secrets/leases/providers/no-such-mfa/totp-seed", "a239l5-unknown", map[string]any{"seed": seedB, "code": codeFor(seedB, time.Now())}, http.StatusNotFound)
	call(admin, http.MethodPost, "/api/v1/secrets/leases/providers/mfa-file/totp-seed", "a239l5-file", map[string]any{"seed": seedB, "code": codeFor(seedB, time.Now())}, http.StatusConflict)
	if v := version(); v != 1 {
		t.Fatalf("the seed's version after refused replacements = %d, want 1", v)
	}

	// With a current code from it, the new seed is the next version.
	var meta struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(call(admin, http.MethodPost, replace, "a239l5-replace", map[string]any{"seed": seedB, "code": codeFor(seedB, time.Now())}, http.StatusOK), &meta); err != nil ||
		meta.Name != "ops/break-glass-mfa" || meta.Version != 2 {
		t.Fatalf("the replacement: %+v %v", meta, err)
	}
	leaseFrom("a239l5-lease-b", seedB)

	// The CLI replaces it again.
	body := filepath.Join(t.TempDir(), "seed.json")
	raw, _ := json.Marshal(map[string]any{"seed": seedA, "code": codeFor(seedA, time.Now())})
	if err := os.WriteFile(body, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", admin, "--tenant", h.tenant,
		"secrets", "leases", "totp-seed", "mfa", "-f", body}, cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl secrets leases totp-seed: %s%s", stdout.String(), stderr.String())
	}
	if v := version(); v != 3 {
		t.Fatalf("the seed's version after the CLI = %d, want 3", v)
	}
	leaseFrom("a239l5-lease-a-again", seedA)
	t.Log("A239L5_TOTP_SEED_REPLACED_OK")
}
