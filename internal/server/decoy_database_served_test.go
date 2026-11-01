// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// Q6: a decoy PostgreSQL login minted by the tenant's dynamic-secret provider
// raises one critical alert when it is used, and nothing else does: not the
// provider's own administration, not a port or TLS probe, not the watcher. The
// bait looks like any generated application login, reaches nothing but its own
// empty database, and cannot be minted, read or revoked through the ordinary
// lease routes.
func TestServedDecoyDatabaseLoginAlertsOnUseQ6(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		cfg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "warehouse-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: "postgres", Schema: "public",
			UsernamePrefix: "trstctl", AllowedRoles: []string{"readonly", "decoy"}, MaxTTL: time.Hour.String(),
		}
		provider := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true, "decoy": true}, time.Hour,
			integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
		d.DecoyLoginWatchInterval = time.Hour // the test drives each check itself
	})
	startServedExternalCADispatcher(t, h)
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "decoy-planter", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "secret-reader", "secrets:read")
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

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", planter, "q6b-ordinary",
		map[string]any{"provider": "warehouse-pg", "role": "decoy", "ttl_seconds": 600}); status != http.StatusUnprocessableEntity {
		t.Fatalf("an ordinary lease minted the decoy role: HTTP %d %s", status, body)
	}
	plant := map[string]any{"provider": "warehouse-pg", "name": "warehouse db bait", "placement": "ops wiki runbook", "ttl_seconds": 1800}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", reader, "q6b-reader", plant); status != http.StatusForbidden {
		t.Fatalf("a secrets:read caller planted a decoy login: HTTP %d", status)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, "q6b-plant", plant)
	if status != http.StatusCreated {
		t.Fatalf("plant decoy login: HTTP %d %s", status, body)
	}
	var planted struct {
		ID        string `json:"id"`
		Kind      string `json:"kind"`
		State     string `json:"state"`
		DBRole    string `json:"db_role"`
		DBLeaseID string `json:"db_lease_id"`
		Database  string `json:"database"`
		DSN       string `json:"dsn"`
	}
	if err := json.Unmarshal(body, &planted); err != nil || planted.Kind != "database" || planted.State != "active" || planted.DSN == "" {
		t.Fatalf("planted decoy login = %+v (%v)", planted, err)
	}
	if strings.Contains(strings.ToLower(planted.DSN), "decoy") || planted.Database != planted.DBRole+"_db" ||
		!strings.Contains(planted.DSN, "/"+planted.Database) {
		t.Fatalf("the bait gives itself away or points elsewhere: role %q database %q", planted.DBRole, planted.Database)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, "q6b-plant", plant); status != http.StatusCreated || string(replay) != string(body) {
		t.Fatalf("plant replay changed the decoy: HTTP %d", status)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+planted.DBLeaseID, planter, nil); status != http.StatusNotFound {
		t.Fatalf("the ordinary lease route shows the decoy lease: HTTP %d", status)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/databases", reader, nil); status != http.StatusForbidden {
		t.Fatalf("a secrets:read caller listed decoy logins: HTTP %d", status)
	}
	if status, catalog := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", reader, nil); status != http.StatusOK ||
		strings.Contains(string(catalog), `"decoy"`) || !strings.Contains(string(catalog), `"readonly"`) {
		t.Fatalf("the provider catalog offers the decoy role: HTTP %d %s", status, catalog)
	}
	// Q1: the access graph does not list the decoy login either, so a graph
	// reader cannot tell decoys from real logins and a generated access review
	// never offers the bait for revocation.
	graphReader := seedScopedTokenSubject(t, h.store, h.tenant, "graph-reader", "graph:read")
	if status, g := secretsReq(t, h, http.MethodGet, "/api/v1/graph", graphReader, nil); status != http.StatusOK ||
		strings.Contains(string(g), planted.DBLeaseID) || strings.Contains(string(g), "decoy@") {
		t.Fatalf("the access graph lists the decoy login: HTTP %d", status)
	}

	// No false alarms: the provider's own administration, a port probe and a
	// TLS probe establish no session on the decoy database, and the watcher
	// itself reads from the admin database.
	admin, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT count(*) FROM public.pam_smoke`); err != nil {
		t.Fatal(err)
	}
	_ = admin.Close(ctx)
	parsed, err := url.Parse(pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", parsed.Host, 2*time.Second); err == nil {
		_ = conn.Close()
	}
	if conn, err := pgx.Connect(ctx, strings.Replace(planted.DSN, "sslmode=disable", "sslmode=require", 1)); err == nil {
		_ = conn.Close(ctx)
	}
	watch()
	watch()
	if n := alerts(); n != 0 {
		t.Fatalf("administration, probes or the watcher raised %d alerts", n)
	}

	// The bait reaches nothing but its own empty database.
	baitOnPostgres, err := pgx.Connect(ctx, strings.Replace(planted.DSN, "/"+planted.Database, "/postgres", 1))
	if err == nil {
		_, readErr := baitOnPostgres.Exec(ctx, `SELECT count(*) FROM public.pam_smoke`)
		_ = baitOnPostgres.Close(ctx)
		if readErr == nil {
			t.Fatal("the decoy login read the provider's real table")
		}
	}
	// Using the bait as found raises exactly one critical alert.
	bait, err := pgx.Connect(ctx, planted.DSN)
	if err != nil {
		t.Fatalf("the decoy DSN does not log in: %v", err)
	}
	if _, err := bait.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	_ = bait.Close(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for alerts() == 0 && time.Now().Before(deadline) {
		watch()
		time.Sleep(200 * time.Millisecond)
	}
	if n := alerts(); n != 1 {
		t.Fatalf("one use of the bait raised %d alerts, want 1", n)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/databases", planter, nil)
	var listed struct {
		Items []struct {
			ID            string `json:"id"`
			State         string `json:"state"`
			TriggerMethod string `json:"trigger_method"`
			TriggerPath   string `json:"trigger_path"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); status != http.StatusOK || err != nil || len(listed.Items) != 1 ||
		listed.Items[0].State != "triggered" || listed.Items[0].TriggerMethod != "LOGIN" ||
		listed.Items[0].TriggerPath != "postgres/"+planted.Database {
		t.Fatalf("decoy logins = %s (HTTP %d)", body, status)
	}
	again, err := pgx.Connect(ctx, planted.DSN)
	if err == nil {
		_ = again.Close(ctx)
	}
	watch()
	if n := alerts(); n != 1 {
		t.Fatalf("a second use re-alerted: %d alerts", n)
	}

	// Retired, the lease's revocation removes the role and its database.
	if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases/"+planted.ID+"/retire", planter, "q6b-retire", nil); status != http.StatusOK {
		t.Fatalf("retire decoy login: HTTP %d %s", status, out)
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !decoyLoginObjectsExist(t, ctx, pgDSN, planted.DBRole, planted.Database) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("retiring left the decoy role %q or its database", planted.DBRole)
}

func decoyLoginObjectsExist(t *testing.T, ctx context.Context, adminDSN, role, database string) bool {
	t.Helper()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
		OR EXISTS (SELECT 1 FROM pg_database WHERE datname = $2)`, role, database).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}
