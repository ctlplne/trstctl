// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestServedDynamicProvidersInRestrictedEnvironmentsA235L2 is A235-L2's
// dynamic-secret, machine-auth and SDK-agent paths. An operator places one
// PostgreSQL provider in a restricted environment (vault236/prod), one in an
// open one (vault236/dev) and one in an environment the tenant does not have
// (vault236/qa), in the configuration file. Then:
//   - a caller not granted prod neither sees the prod provider (the catalog,
//     the Vault database role list) nor issues, reads, renews or revokes its
//     leases, through the native routes or the stock Vault CLI; its leases
//     and creds paths answer as missing;
//   - prod's viewer sees the provider and its leases but issues nothing
//     (403, Vault "permission denied");
//   - prod's developer issues, renews and revokes;
//   - the qa provider is closed to everyone;
//   - a machine session (a CI job's JWT) is refused until its principal is
//     granted prod;
//   - the agent's own client leases and fetches only as its token's grant
//     allows.
func TestServedDynamicProvidersInRestrictedEnvironmentsA235L2(t *testing.T) {
	vault := vaultCLIBinary(t)
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ref := writeServedCredentialFile(t, "pg-admin-dsn", dsn)
	// The placement reads from the configuration file as an operator writes it.
	const prodPlacement, devPlacement, qaPlacement = "vault236/prod", "vault236/dev", "vault236/qa"
	var providers []config.DynamicSecretProviderConfig
	raw := fmt.Sprintf(`[
	  {"tenant_id": %[1]q, "id": "pg-prod", "type": "postgresql", "admin_dsn_ref": %[2]q, "database": %[3]q,
	   "allowed_roles": ["prodreader"], "role_access": {"prodreader": "read"}, "max_ttl": "2h", "username_prefix": "trstctl_a235p",
	   "secret_environment": %[4]q},
	  {"tenant_id": %[1]q, "id": "pg-dev", "type": "postgresql", "admin_dsn_ref": %[2]q, "database": %[3]q,
	   "allowed_roles": ["readonly"], "role_access": {"readonly": "read"}, "max_ttl": "2h", "username_prefix": "trstctl_a235d",
	   "secret_environment": %[5]q},
	  {"tenant_id": %[1]q, "id": "pg-ghost", "type": "postgresql", "admin_dsn_ref": %[2]q, "database": %[3]q,
	   "allowed_roles": ["ghostreader"], "role_access": {"ghostreader": "read"}, "max_ttl": "2h", "username_prefix": "trstctl_a235g",
	   "secret_environment": %[6]q}]`, servedTestTenant, ref, parsed.Database, prodPlacement, devPlacement, qaPlacement)
	if err := json.Unmarshal([]byte(raw), &providers); err != nil {
		t.Fatal(err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "ci-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		// The generic JWT method, so its single-use records on the shared
		// served tenant stay apart from other tests' "oidc" logins.
		Name: "jwt", TenantID: servedTestTenant, Issuer: "https://ci.example.test", Audience: "trstctl",
		JWKSJSON: string(jwks), Scopes: []string{"secrets:read", "secrets:write"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenant(t, h, "A235-L2 dynamic providers tenant")
	startServedExternalCADispatcher(t, h)
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a235p-admin", "access:write", "secrets:read", "secrets:write")
	developer := seedScopedTokenSubject(t, h.store, h.tenant, "a235p-developer", "secrets:read", "secrets:write")
	viewer := seedScopedTokenSubject(t, h.store, h.tenant, "a235p-viewer", "secrets:read", "secrets:write")
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "a235p-outsider", "secrets:read", "secrets:write")

	call := func(tok, method, path string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, fmt.Sprintf("a235p-%d", time.Now().UnixNano()), body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "vault236", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/vault236/members/a235p-developer", map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/vault236/members/a235p-viewer", map[string]any{"role": "viewer", "environments": []string{"prod"}}, http.StatusOK)

	// The catalog names only what the caller may see.
	catalog := func(tok string) []string {
		t.Helper()
		var out struct {
			Configured []struct {
				ID          string `json:"id"`
				Environment string `json:"environment"`
			} `json:"configured_providers"`
		}
		if err := json.Unmarshal(call(tok, http.MethodGet, "/api/v1/secrets/leases/providers", nil, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, p := range out.Configured {
			ids = append(ids, p.ID+"@"+p.Environment)
		}
		slices.Sort(ids)
		return ids
	}
	for tok, want := range map[string][]string{
		outsider:  {"pg-dev@vault236/dev"},
		admin:     {"pg-dev@vault236/dev"},
		viewer:    {"pg-dev@vault236/dev", "pg-prod@vault236/prod"},
		developer: {"pg-dev@vault236/dev", "pg-prod@vault236/prod"},
	} {
		if got := catalog(tok); !slices.Equal(got, want) {
			t.Fatalf("catalog = %v, want %v", got, want)
		}
	}

	issue := func(tok, provider, role string) (int, string, string) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, fmt.Sprintf("a235p-issue-%d", time.Now().UnixNano()),
			map[string]any{"provider": provider, "role": role, "ttl_seconds": 600})
		var lease struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &lease)
		return status, lease.ID, string(raw)
	}
	if status, _, raw := issue(outsider, "pg-prod", "prodreader"); status != http.StatusUnprocessableEntity || !strings.Contains(raw, "not configured") {
		t.Fatalf("a non-member issued from the prod provider: HTTP %d %s", status, raw)
	}
	if status, _, raw := issue(viewer, "pg-prod", "prodreader"); status != http.StatusForbidden {
		t.Fatalf("prod's viewer issued: HTTP %d %s", status, raw)
	}
	for _, tok := range []string{admin, developer} {
		if status, _, raw := issue(tok, "pg-ghost", "ghostreader"); status != http.StatusUnprocessableEntity {
			t.Fatalf("a provider placed in an environment the tenant lacks issued: HTTP %d %s", status, raw)
		}
	}
	if status, _, raw := issue(outsider, "pg-dev", "readonly"); status != http.StatusCreated {
		t.Fatalf("the open environment's provider refused a non-member: HTTP %d %s", status, raw)
	}
	status, leaseID, raw := issue(developer, "pg-prod", "prodreader")
	if status != http.StatusCreated || leaseID == "" {
		t.Fatalf("prod's developer could not issue: HTTP %d %s", status, raw)
	}
	lease := "/api/v1/secrets/leases/" + leaseID
	call(outsider, http.MethodGet, lease, nil, http.StatusNotFound)
	call(viewer, http.MethodGet, lease, nil, http.StatusOK)
	call(developer, http.MethodGet, lease, nil, http.StatusOK)
	call(outsider, http.MethodPost, lease+"/renew", map[string]any{"extend_seconds": 60}, http.StatusNotFound)
	call(viewer, http.MethodPost, lease+"/renew", map[string]any{"extend_seconds": 60}, http.StatusForbidden)
	call(developer, http.MethodPost, lease+"/renew", map[string]any{"extend_seconds": 60}, http.StatusOK)
	call(outsider, http.MethodPost, lease+"/revoke", map[string]any{}, http.StatusNotFound)
	call(viewer, http.MethodPost, lease+"/revoke", map[string]any{}, http.StatusForbidden)
	call(developer, http.MethodPost, lease+"/revoke", map[string]any{}, http.StatusOK)

	// The stock Vault CLI: the engine mount lists only the roles the caller
	// may see; the prod creds path is the outsider's cubbyhole, the viewer's
	// "permission denied", the developer's lease.
	home := t.TempDir()
	roles := func(tok string) []string {
		t.Helper()
		var out []string
		if err := json.Unmarshal(runVault(t, vault, home, h.ts.URL, tok, "list", "-format=json", "database/roles"), &out); err != nil {
			t.Fatal(err)
		}
		slices.Sort(out)
		return out
	}
	if got := roles(outsider); !slices.Equal(got, []string{"readonly"}) {
		t.Fatalf("the outsider's database roles = %v", got)
	}
	if got := roles(developer); !slices.Equal(got, []string{"prodreader", "readonly"}) {
		t.Fatalf("the developer's database roles = %v", got)
	}
	if out := runVaultExpectingFailure(t, vault, home, h.ts.URL, outsider, "read", "pg-prod/creds/prodreader"); !strings.Contains(string(out), "No value found") {
		t.Fatalf("the outsider's vault read of the prod creds = %s", out)
	}
	if out := runVaultExpectingFailure(t, vault, home, h.ts.URL, viewer, "read", "pg-prod/creds/prodreader"); !strings.Contains(string(out), "permission denied") {
		t.Fatalf("the viewer's vault read of the prod creds = %s", out)
	}
	var creds struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.Unmarshal(runVault(t, vault, home, h.ts.URL, developer, "read", "-format=json", "pg-prod/creds/prodreader"), &creds); err != nil || creds.LeaseID == "" {
		t.Fatalf("the developer's vault read: %v", err)
	}
	if out := runVaultExpectingFailure(t, vault, home, h.ts.URL, outsider, "lease", "revoke", creds.LeaseID); !strings.Contains(string(out), "invalid lease") {
		t.Fatalf("the outsider revoked the developer's Vault lease: %s", out)
	}
	runVault(t, vault, home, h.ts.URL, developer, "lease", "revoke", creds.LeaseID)

	// Machine-auth: a CI session is refused prod until its principal is granted.
	jwt, err := crypto.SignJWT(signer, "ci-key", map[string]any{
		"iss": "https://ci.example.test", "aud": "trstctl", "sub": "repo:payments:ref:main",
		"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": "a235p-run-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"method": "jwt", "credential": jwt})
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("Idempotency-Key", "a235p-login")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	loginRaw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var session struct {
		Principal string `json:"principal"`
		Token     string `json:"token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(loginRaw, &session) != nil || session.Token == "" {
		t.Fatalf("machine login: HTTP %d %s", resp.StatusCode, loginRaw)
	}
	if status, _, raw := issue(session.Token, "pg-prod", "prodreader"); status != http.StatusUnprocessableEntity {
		t.Fatalf("an ungranted machine session issued from prod: HTTP %d %s", status, raw)
	}
	call(admin, http.MethodPut, "/api/v1/secrets/projects/vault236/members/"+session.Principal, map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	status, machineLease, raw := issue(session.Token, "pg-prod", "prodreader")
	if status != http.StatusCreated {
		t.Fatalf("the granted machine session: HTTP %d %s", status, raw)
	}
	call(session.Token, http.MethodPost, "/api/v1/secrets/leases/"+machineLease+"/revoke", map[string]any{}, http.StatusOK)

	// The SDK agent's own client leases and fetches as its token's grant allows.
	call(developer, http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "vault236/prod/app-config", "value": "prod-config-a235p"}, http.StatusCreated)
	agent := func(tok string) *secretrender.HTTPClient {
		t.Helper()
		client, err := secretrender.NewSessionHTTPClient(h.ts.URL, h.tenant, []byte(tok), h.ts.Client())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Wipe)
		return client
	}
	if _, err := agent(outsider).IssueLease(ctx, "pg-prod", "prodreader", 10*time.Minute, "a235p-agent-out"); err == nil {
		t.Fatal("the agent leased from prod on a non-member's token")
	}
	if _, _, err := agent(outsider).Fetch(ctx, "vault236/prod/app-config"); err == nil {
		t.Fatal("the agent fetched a prod secret on a non-member's token")
	}
	member := agent(developer)
	got, err := member.IssueLease(ctx, "pg-prod", "prodreader", 10*time.Minute, "a235p-agent-dev")
	if err != nil || got.ID == "" {
		t.Fatalf("the agent on the developer's token: %v", err)
	}
	if err := member.RevokeLease(ctx, got.ID, "a235p-agent-dev-revoke"); err != nil {
		t.Fatalf("the agent's revoke: %v", err)
	}
	value, _, err := member.Fetch(ctx, "vault236/prod/app-config")
	if err != nil || string(value) != "prod-config-a235p" {
		t.Fatalf("the agent's fetch on the developer's token: %v", err)
	}
	t.Log("A235L2_DYNAMIC_ENVIRONMENTS_OK native+vault+machine+agent")
}
