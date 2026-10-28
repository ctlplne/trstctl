// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// vaultLeaseOutput is what the stock CLI prints for a dynamic-credential read
// (-format=json).
type vaultLeaseOutput struct {
	LeaseID       string            `json:"lease_id"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	Data          map[string]string `json:"data"`
}

func decodeVaultLease(t *testing.T, raw []byte) vaultLeaseOutput {
	t.Helper()
	var out vaultLeaseOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode the stock CLI's lease output: %v\n%s", err, raw)
	}
	return out
}

// nativeLeaseID is the trstctl lease a Vault lease ID names.
func nativeLeaseID(t *testing.T, vaultLeaseID string) string {
	t.Helper()
	parts := strings.Split(vaultLeaseID, "/")
	if len(parts) != 4 || !strings.HasPrefix(parts[3], "lease-") {
		t.Fatalf("Vault lease ID %q does not name a native lease", vaultLeaseID)
	}
	return parts[3]
}

// TestServedVaultDatabaseCredentialsWithTheStockCLI is A203 for databases: the
// stock OpenBao CLI reads PostgreSQL credentials at database/creds/<role> from a
// provider configured as the binary configures it, the username and password
// log in, sys/leases looks the lease up and renews it, and `lease revoke -sync`
// returns only once the role is gone: PostgreSQL itself no longer lists it and
// the password no longer logs in. Each read opens its own lease, a provider ID
// is a mount, and a creds path on the cubbyhole still reaches the cubbyhole.
func TestServedVaultDatabaseCredentialsWithTheStockCLI(t *testing.T) {
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
		AllowedRoles: []string{"readonly"}, MaxTTL: "2h", UsernamePrefix: "trstctl_a203",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "Vault dynamic credentials tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	home := t.TempDir()

	first := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "database/creds/readonly"))
	if !strings.HasPrefix(first.LeaseID, "database/creds/readonly/lease-") || !first.Renewable ||
		first.LeaseDuration < 3590 || first.LeaseDuration > 3600 || first.Data["username"] == "" || first.Data["password"] == "" {
		t.Fatalf("database/creds read = %+v", first)
	}
	user, password := first.Data["username"], first.Data["password"]
	login := func(user, password string) error {
		cfg := parsed.Copy()
		cfg.User, cfg.Password = user, password
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close(ctx) }()
		var one int
		return conn.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	if err := login(user, password); err != nil {
		t.Fatalf("the Vault-path credential does not log in: %v", err)
	}
	roleExists := func(name string) bool {
		var n int
		if err := h.store.SystemPool().QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname = $1", name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !roleExists(user) {
		t.Fatalf("PostgreSQL does not list the leased role %s", user)
	}

	// A second read is a second lease, and the provider's own ID is a mount.
	second := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "app-postgres/creds/readonly"))
	if second.LeaseID == first.LeaseID || second.Data["username"] == user || !strings.HasPrefix(second.LeaseID, "app-postgres/creds/readonly/") {
		t.Fatalf("second read = %+v, want a new lease at the provider mount", second)
	}
	if err := login(second.Data["username"], second.Data["password"]); err != nil {
		t.Fatalf("the provider-mount credential does not log in: %v", err)
	}

	// Lookup and renewal through sys/leases.
	var lookup struct {
		Data struct {
			ID         string `json:"id"`
			ExpireTime string `json:"expire_time"`
			Renewable  bool   `json:"renewable"`
			TTL        int    `json:"ttl"`
		} `json:"data"`
	}
	raw := runVault(t, vault, home, h.ts.URL, token, "lease", "lookup", "-format=json", first.LeaseID)
	if err := json.Unmarshal(raw, &lookup); err != nil || lookup.Data.ID != first.LeaseID || !lookup.Data.Renewable || lookup.Data.TTL < 3500 {
		t.Fatalf("lease lookup = %+v %v\n%s", lookup.Data, err, raw)
	}
	renewed := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token, "lease", "renew", "-format=json", "-increment=5400", first.LeaseID))
	if renewed.LeaseID != first.LeaseID || renewed.LeaseDuration < 5390 || renewed.LeaseDuration > 5400 {
		t.Fatalf("lease renew = %+v, want 5400 s", renewed)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+nativeLeaseID(t, first.LeaseID), token, nil)
	var native dynamicLeaseView
	if status != http.StatusOK || json.Unmarshal(body, &native) != nil || time.Until(native.ExpiresAt) < 89*time.Minute {
		t.Fatalf("the native lease after a Vault renew = %d %s", status, body)
	}

	// Synchronous revocation returns once PostgreSQL no longer has the role.
	out := runVault(t, vault, home, h.ts.URL, token, "lease", "revoke", "-sync", first.LeaseID)
	if !strings.Contains(string(out), "Success! Revoked lease") {
		t.Fatalf("lease revoke -sync = %s", out)
	}
	if roleExists(user) {
		t.Fatalf("PostgreSQL still lists the revoked role %s", user)
	}
	if err := login(user, password); err == nil {
		t.Fatal("the revoked credential still logs in")
	}
	if err := login(second.Data["username"], second.Data["password"]); err != nil {
		t.Fatalf("revoking one lease ended the other: %v", err)
	}
	failure := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "lookup", first.LeaseID)
	if !strings.Contains(string(failure), "invalid lease") {
		t.Fatalf("lookup of a revoked lease = %s", failure)
	}
	// Revoking again is idempotent; an unknown lease is refused.
	if out := runVault(t, vault, home, h.ts.URL, token, "lease", "revoke", "-sync", first.LeaseID); !strings.Contains(string(out), "Success! Revoked lease") {
		t.Fatalf("second revoke = %s", out)
	}
	failure = runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "revoke", "database/creds/readonly/lease-00000000-0000-0000-0000-000000000000")
	if !strings.Contains(string(failure), "invalid lease") {
		t.Fatalf("revoke of an unknown lease = %s", failure)
	}

	// Asynchronous revocation (the CLI's default) is queued and completes.
	if out := runVault(t, vault, home, h.ts.URL, token, "lease", "revoke", second.LeaseID); !strings.Contains(string(out), "queued successfully") {
		t.Fatalf("lease revoke = %s", out)
	}
	deadline := time.Now().Add(30 * time.Second)
	for roleExists(second.Data["username"]) {
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL still lists %s after the queued revocation", second.Data["username"])
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Refusals in Vault's shape: an unknown role, an unknown engine path, and a
	// write to database creds.
	failure = runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "read", "database/creds/writer")
	if !strings.Contains(string(failure), "unknown role: writer") {
		t.Fatalf("unknown role = %s", failure)
	}
	failure = runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "write", "database/creds/readonly", "ttl=1h")
	if !strings.Contains(string(failure), "unsupported operation") {
		t.Fatalf("write to database creds = %s", failure)
	}
	// The cubbyhole keeps its creds/ paths.
	runVault(t, vault, home, h.ts.URL, token, "write", "cubbyhole/creds/note", "value=mine")
	var note struct {
		Data map[string]string `json:"data"`
	}
	raw = runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "cubbyhole/creds/note")
	if err := json.Unmarshal(raw, &note); err != nil || note.Data["value"] != "mine" {
		t.Fatalf("cubbyhole/creds/note = %s", raw)
	}

	if h.logContains(t, password) || h.logContains(t, second.Data["password"]) {
		t.Fatal("a Vault-path credential reached the event log")
	}
	t.Logf("A203_DATABASE_OK first=%s second=%s user=%s", first.LeaseID, second.LeaseID, user)
}
