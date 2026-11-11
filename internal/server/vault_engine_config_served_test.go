// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// TestServedVaultEngineConfigPathsWithTheStockCLIA203L2 is A203-L2 with the
// stock Vault/OpenBao CLI against the served shim: it lists and reads the
// database engine's roles and connections at the engine mount and at the
// provider's own mount, never sees the connection's DSN, is refused (405) when
// it writes or deletes them, and a cubbyhole path named like them still
// belongs to the cubbyhole.
func TestServedVaultEngineConfigPathsWithTheStockCLIA203L2(t *testing.T) {
	vault := vaultCLIBinary(t)
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "app-postgres", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "pg-admin-dsn", dsn), Database: parsed.Database,
		AllowedRoles: []string{"readonly", "reporting"}, RoleAccess: map[string]string{"readonly": "read", "reporting": "read"},
		MaxTTL: "2h", UsernamePrefix: "trstctl_a203l2",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "Vault engine config tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	home := t.TempDir()
	data := func(raw []byte) map[string]any {
		t.Helper()
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return out.Data
	}
	keys := func(raw []byte) []string {
		t.Helper()
		var out []string
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode list %s: %v", raw, err)
		}
		return out
	}

	for _, mount := range []string{"database", "app-postgres"} {
		if got := keys(runVault(t, vault, home, h.ts.URL, token, "list", "-format=json", mount+"/roles")); !slices.Equal(got, []string{"readonly", "reporting"}) {
			t.Fatalf("vault list %s/roles = %v", mount, got)
		}
		role := data(runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", mount+"/roles/readonly"))
		if role["db_name"] != "app-postgres" || role["max_ttl"] != float64(7200) || role["default_ttl"] != float64(3600) || role["credential_type"] != "password" {
			t.Fatalf("vault read %s/roles/readonly = %v", mount, role)
		}
	}
	if got := keys(runVault(t, vault, home, h.ts.URL, token, "list", "-format=json", "database/config")); !slices.Equal(got, []string{"app-postgres"}) {
		t.Fatalf("vault list database/config = %v", got)
	}
	raw := runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "database/config/app-postgres")
	connection := data(raw)
	if connection["plugin_name"] != "postgresql-database-plugin" || connection["verify_connection"] != true {
		t.Fatalf("vault read database/config/app-postgres = %v", connection)
	}
	if roles, _ := connection["allowed_roles"].([]any); len(roles) != 2 {
		t.Fatalf("allowed_roles = %v", connection["allowed_roles"])
	}
	// The answer is the connection's plugin, roles and readiness and nothing
	// else: no DSN, scheme or address, and no connection details at all.
	for _, leak := range []string{dsn, "postgres://", "postgresql://", fmt.Sprintf("%s:%d", parsed.Host, parsed.Port)} {
		if strings.Contains(string(raw), leak) {
			t.Fatal("the connection read carries the provider's DSN or address")
		}
	}
	var fields []string
	for k := range connection {
		fields = append(fields, k)
	}
	slices.Sort(fields)
	if want := []string{"allowed_roles", "connection_details", "password_policy", "plugin_name", "root_credentials_rotate_statements",
		"trstctl_configuration_revision", "trstctl_ready", "verify_connection"}; !slices.Equal(fields, want) {
		t.Fatalf("connection fields = %v, want %v", fields, want)
	}
	if details, _ := connection["connection_details"].(map[string]any); len(details) != 0 {
		t.Fatalf("connection_details = %v, want empty", details)
	}

	for _, args := range [][]string{
		{"write", "database/roles/readonly", "db_name=app-postgres", "default_ttl=60"},
		{"write", "database/config/app-postgres", "plugin_name=postgresql-database-plugin"},
		{"delete", "database/roles/readonly"},
		{"delete", "database/config/app-postgres"},
	} {
		out := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, args...)
		if !strings.Contains(string(out), "405") || !strings.Contains(string(out), "configuration file") {
			t.Fatalf("vault %s = %s, want the read-only refusal", strings.Join(args, " "), out)
		}
	}
	if role := data(runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "database/roles/readonly")); role["default_ttl"] != float64(3600) {
		t.Fatalf("a refused write changed the role: %v", role)
	}
	if out := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "read", "database/roles/nope"); !strings.Contains(string(out), "No value found") {
		t.Fatalf("vault read of an unknown role = %s", out)
	}

	runVault(t, vault, home, h.ts.URL, token, "write", "cubbyhole/roles/note", "value=mine")
	if note := data(runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "cubbyhole/roles/note")); note["value"] != "mine" {
		t.Fatalf("cubbyhole/roles/note = %v", note)
	}
	t.Log("A203L2_ENGINE_CONFIG_OK")
}
