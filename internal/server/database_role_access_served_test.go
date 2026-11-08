// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDatabaseLeasesGetTheirRolesAccessClass is A239-L1 against the
// server tests' own PostgreSQL, through a provider configured as the binary
// configures one. Read back without trstctl, a lease of a role given read
// cannot write a row and one given readwrite can, whatever the role is called;
// a role named readwrite is read-write, not read-only; and a role with no
// class is refused at startup instead of being granted every table.
func TestServedDatabaseLeasesGetTheirRolesAccessClass(t *testing.T) {
	ctx := context.Background()
	dsn := serverTestPostgresDSN(t)
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, err := admin.Exec(ctx, `DROP TABLE IF EXISTS public.a239l1_rows; CREATE TABLE public.a239l1_rows (id int PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP TABLE IF EXISTS public.a239l1_rows`) })

	providers := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pg-classes", Type: "postgresql",
		AdminDSNRef: writeServedCredentialFile(t, "pg-classes-admin-dsn", dsn), Database: parsed.Database,
		AllowedRoles: []string{"viewer", "etl", "readwrite"}, RoleAccess: map[string]string{"viewer": "read", "etl": "readwrite"},
		MaxTTL: "1h", UsernamePrefix: "trstctl_a239l1",
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: providers}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	unclassed := providers[0]
	unclassed.AllowedRoles, unclassed.RoleAccess = []string{"reporting"}, nil
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{unclassed}}, true); err == nil ||
		!strings.Contains(err.Error(), `role "reporting" needs role_access["reporting"]`) {
		t.Fatalf("a role with no class was accepted: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "database role access tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	for i, tc := range []struct {
		role   string
		writes bool
	}{{"viewer", false}, {"etl", true}, {"readwrite", true}} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239l1-"+tc.role,
			map[string]any{"provider": "pg-classes", "role": tc.role, "ttl_seconds": 600})
		if status != http.StatusCreated {
			t.Fatalf("issue a %s lease: %d %s", tc.role, status, body)
		}
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the %s lease: %v %s", tc.role, err, body)
		}
		conn, err := pgx.Connect(ctx, lease.Credential)
		if err != nil {
			t.Fatalf("the %s lease does not log in: %v", tc.role, err)
		}
		var rows int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.a239l1_rows`).Scan(&rows); err != nil {
			t.Fatalf("the %s lease cannot read: %v", tc.role, err)
		}
		_, insertErr := conn.Exec(ctx, `INSERT INTO public.a239l1_rows (id) VALUES ($1)`, i)
		_ = conn.Close(ctx)
		if tc.writes && insertErr != nil {
			t.Fatalf("the %s lease (readwrite) cannot write: %v", tc.role, insertErr)
		}
		if !tc.writes && (insertErr == nil || !strings.Contains(insertErr.Error(), "permission denied")) {
			t.Fatalf("the %s lease (read) wrote a row: %v", tc.role, insertErr)
		}
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke the %s lease: %d %s", tc.role, status, body)
		}
	}
	t.Logf("A239L1_ACCESS_CLASS_OK read=viewer readwrite=etl,readwrite")
}
