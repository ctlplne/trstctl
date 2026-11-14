// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/config"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// startJSONLogPostgres is a stock PostgreSQL 16 (the embedded-postgres
// binaries) that writes its log as jsonlog through the logging collector.
func startJSONLogPostgres(t *testing.T) string {
	t.Helper()
	port := freePAMPort(t)
	dir, err := os.MkdirTemp("", "trstctl-decoy-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin, runtime, data := filepath.Join(dir, "bin"), filepath.Join(dir, "runtime"), filepath.Join(dir, "data")
	for _, path := range []string{bin, runtime, data} {
		if err := os.MkdirAll(path, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin). // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		StartParameters(map[string]string{"logging_collector": "on", "log_destination": "jsonlog"}))
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		t.Skip("embedded postgres unavailable: ", err)
	}
	t.Cleanup(func() { _ = db.Stop(); _ = os.RemoveAll(dir) })
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port)
}

// TestServedDecoyRefusedSignInAlertsQ6L6 is Q6-L6's Done-when (served, stock
// PostgreSQL 16 writing jsonlog): a sign-in with a decoy login's name and a
// wrong password establishes no session, so the decoy database's session
// counter never moves; with decoy_auth_log the watcher reads the server's own
// record of the refusal (SQLSTATE 28P01) through the admin connection and
// triggers the decoy once — method FAILED_LOGIN, the database and client in
// its path — raising one alert. Another role's refused sign-in triggers
// nothing, and reading again raises no second alert.
func TestServedDecoyRefusedSignInAlertsQ6L6(t *testing.T) {
	pgDSN := startJSONLogPostgres(t)
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		cfg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "q6l6-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: "postgres", Schema: "public",
			UsernamePrefix: "trstctl", AllowedRoles: []string{"readonly", "decoy"}, MaxTTL: time.Hour.String(), DecoyAuthLog: true,
		}
		if errs := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); errs != nil {
			t.Fatalf("the provider as configured: %v", errs)
		}
		provider := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true, "decoy": true}, time.Hour,
			integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
		d.DecoyLoginWatchInterval = time.Hour // the test drives each check itself
	})
	startServedExternalCADispatcher(t, h)
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "q6l6-planter", "secrets:read", "secrets:write")
	ctx := t.Context()
	alerts := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	watch := func() {
		t.Helper()
		if err := h.srv.WatchDecoyLoginsOnce(ctx); err != nil {
			t.Fatalf("decoy login watch: %v", err)
		}
	}
	before := alerts()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, "q6l6-plant",
		map[string]any{"provider": "q6l6-pg", "name": "orders db bait", "placement": "ops wiki runbook", "ttl_seconds": 1800})
	var planted struct {
		ID       string `json:"id"`
		DBRole   string `json:"db_role"`
		Database string `json:"database"`
		DSN      string `json:"dsn"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &planted) != nil || planted.DSN == "" {
		t.Fatalf("plant decoy login: HTTP %d %s", status, body)
	}
	watch()
	if n := alerts() - before; n != 0 {
		t.Fatalf("planting and watching raised %d alerts", n)
	}

	refused := func(dsn string) {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		var pgErr *pgconn.PgError
		if err == nil {
			_ = conn.Close(ctx)
			t.Fatal("a wrong password signed in")
		}
		if !errors.As(err, &pgErr) || pgErr.Code != "28P01" {
			t.Fatalf("the wrong password was refused with %v, want SQLSTATE 28P01", err)
		}
	}
	wrongPassword := func(dsn string) string {
		t.Helper()
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword(u.User.Username(), "not-the-"+"decoy-password")
		return u.String()
	}
	// Another role's wrong password is not a decoy's.
	refused(wrongPassword(pgDSN))
	// The bait with a wrong password: refused, no session.
	refused(wrongPassword(planted.DSN))

	deadline := time.Now().Add(15 * time.Second)
	for alerts()-before == 0 && time.Now().Before(deadline) {
		watch()
		time.Sleep(300 * time.Millisecond)
	}
	if n := alerts() - before; n != 1 {
		t.Fatalf("a refused sign-in with the bait raised %d alerts, want 1", n)
	}
	var sessions int64
	admin, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT sessions FROM pg_stat_database WHERE datname = $1`, planted.Database).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("the decoy database counted %d sessions (%v); the refused sign-in must have opened none", sessions, err)
	}
	_ = admin.Close(ctx)
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/databases", planter, nil)
	var listed struct {
		Items []struct {
			ID            string `json:"id"`
			State         string `json:"state"`
			TriggerMethod string `json:"trigger_method"`
			TriggerPath   string `json:"trigger_path"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
		t.Fatalf("list decoy logins: HTTP %d %s", status, body)
	}
	var found bool
	for _, item := range listed.Items {
		if item.ID == planted.ID {
			found = true
			if item.State != "triggered" || item.TriggerMethod != "FAILED_LOGIN" || !strings.HasPrefix(item.TriggerPath, "postgres/"+planted.Database) {
				t.Fatalf("the decoy reads %+v; want triggered by FAILED_LOGIN at postgres/%s", item, planted.Database)
			}
		}
	}
	if !found {
		t.Fatalf("the decoy is not listed: %s", body)
	}
	watch()
	watch()
	if n := alerts() - before; n != 1 {
		t.Fatalf("reading the log again raised %d alerts, want still 1", n)
	}
	t.Logf("Q6L6_OK decoy=%s role=%s", planted.ID, planted.DBRole)
}
