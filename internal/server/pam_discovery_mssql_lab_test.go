// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// TestServedPrivilegedAccountDiscoverySQLServerA260: on the A239 lab's SQL
// Server, discovery stages the logins that belong to a fixed server role that
// administers the server or hold CONTROL SERVER — sa (sysadmin), a
// securityadmin member, a CONTROL SERVER grantee — and not a plain login or
// the lab's database readers; the scan changes no login or membership; and a
// re-scan after one login is dropped shows it removed. The runner
// (scripts/ci/a239-mssql-lab.sh, an x86 host) starts SQL Server.
func TestServedPrivilegedAccountDiscoverySQLServerA260(t *testing.T) {
	lab := requireMSSQLLab(t)
	dsn := strings.TrimSpace(string(mustReadMSSQLDSN(t, lab.dsnFile)))
	admin, err := sql.Open("sqlserver", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	ctx := context.Background()
	run := func(statement string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	run("CREATE LOGIN a260_secadmin WITH PASSWORD = 'A260-secadmin-Pw-1!'")
	run("ALTER SERVER ROLE securityadmin ADD MEMBER a260_secadmin")
	run("CREATE LOGIN a260_control WITH PASSWORD = 'A260-control-Pw-1!'")
	run("GRANT CONTROL SERVER TO a260_control")
	run("CREATE LOGIN a260_plain WITH PASSWORD = 'A260-plain-Pw-1!'")
	t.Cleanup(func() {
		for _, login := range []string{"a260_secadmin", "a260_control", "a260_plain"} {
			_, _ = admin.ExecContext(ctx, "IF SUSER_ID('"+login+"') IS NOT NULL DROP LOGIN "+login)
		}
	})
	logins := func() string {
		t.Helper()
		var digest string
		if err := admin.QueryRowContext(ctx, `WITH memberships AS (
            SELECT m.member_principal_id,
              STRING_AGG(CONVERT(varchar(max), r.name), ',') WITHIN GROUP (ORDER BY r.name) AS roles
            FROM sys.server_role_members m
            JOIN sys.server_principals r ON r.principal_id = m.role_principal_id
            GROUP BY m.member_principal_id
          )
          SELECT CONVERT(varchar(64), HASHBYTES('SHA2_256', COALESCE((
            SELECT STRING_AGG(CONCAT(p.name, ':', p.type, ':', p.is_disabled, ':',
              CONVERT(varchar(max), LOGINPROPERTY(p.name, 'PasswordHash'), 1), ':', memberships.roles), ';')
              WITHIN GROUP (ORDER BY p.name)
            FROM sys.server_principals p
            LEFT JOIN memberships ON memberships.member_principal_id = p.principal_id), '')), 2)`).Scan(&digest); err != nil {
			t.Fatalf("hash the logins: %v", err)
		}
		return digest
	}

	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "a260-mssql", Type: "mssql", AdminDSNRef: writeServedCredentialFile(t, "a260-mssql-dsn", dsn),
		Database: "orders", AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "db_datareader"}, MaxTTL: "1h",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a260-mssql-operator", "access:read", "access:targets.write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260-mssql", operator,
		"a260-mssql-save", map[string]any{"interval_seconds": 0}); status != http.StatusOK {
		t.Fatalf("save the source = %d %s", status, body)
	}
	scan := func(key string) (int, int) {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/a260-mssql/runs", operator, key, nil)
		var r struct {
			Status  string `json:"status"`
			Failure string `json:"failure"`
			Added   int    `json:"added"`
			Removed int    `json:"removed"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &r) != nil || r.Status != "completed" {
			t.Fatalf("scan = %d %s", status, body)
		}
		return r.Added, r.Removed
	}
	accounts := func() map[string]string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=a260-mssql", operator, nil)
		var page struct {
			Items []struct {
				Name       string   `json:"name"`
				Kind       string   `json:"kind"`
				Privileges []string `json:"privileges"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list accounts = %d %s", status, body)
		}
		out := map[string]string{}
		for _, a := range page.Items {
			out[a.Name] = a.Kind + " " + strings.Join(a.Privileges, " ")
		}
		return out
	}

	before := logins()
	if added, _ := scan("a260-mssql-scan-1"); added == 0 {
		t.Fatal("the first scan staged nothing")
	}
	found := accounts()
	for name, want := range map[string]string{"a260_secadmin": "sql_login securityadmin", "a260_control": "sql_login control_server"} {
		if found[name] != want {
			t.Fatalf("%s = %q, want %q (all: %v)", name, found[name], want, found)
		}
	}
	if !strings.Contains(found["sa"], "sysadmin") {
		t.Fatalf("sa = %q (all: %v)", found["sa"], found)
	}
	for _, plain := range []string{"a260_plain", "orders_app_a", "orders_app_b"} {
		if _, ok := found[plain]; ok {
			t.Fatalf("%s was staged as privileged: %v", plain, found)
		}
	}
	if after := logins(); after != before {
		t.Fatalf("the scan changed SQL Server's logins: %s → %s", before, after)
	}
	run("DROP LOGIN a260_secadmin")
	if _, removed := scan("a260-mssql-scan-2"); removed != 1 {
		t.Fatalf("the re-scan removed %d logins, want the dropped one", removed)
	}
	if _, ok := accounts()["a260_secadmin"]; ok {
		t.Fatal("the dropped login is still staged")
	}
}
