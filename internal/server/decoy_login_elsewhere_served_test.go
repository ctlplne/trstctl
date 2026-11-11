// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// plantServedDecoyLogin serves a tenant PostgreSQL provider that mints decoy
// logins against a real PostgreSQL and plants one, returning the harness, the
// planted decoy and the admin DSN.
func plantServedDecoyLogin(t *testing.T, key string) (*servedHarness, servedDecoyLogin, string) {
	t.Helper()
	pgDSN, stopPG := startPAMPostgres(t)
	t.Cleanup(stopPG)
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
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, key,
		map[string]any{"provider": "warehouse-pg", "name": "warehouse db bait", "placement": "ops wiki runbook", "ttl_seconds": 1800})
	if status != http.StatusCreated {
		t.Fatalf("plant decoy login: HTTP %d %s", status, body)
	}
	var planted servedDecoyLogin
	if err := json.Unmarshal(body, &planted); err != nil || planted.DSN == "" {
		t.Fatalf("planted decoy login = %+v (%v)", planted, err)
	}
	return h, planted, pgDSN
}

type servedDecoyLogin struct {
	ID        string `json:"id"`
	DBRole    string `json:"db_role"`
	DBLeaseID string `json:"db_lease_id"`
	Database  string `json:"database"`
	DSN       string `json:"dsn"`
}

func servedDecoyState(t *testing.T, h *servedHarness, id string) (state, path string) {
	t.Helper()
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT state, COALESCE(trigger_path, '') FROM honey_tokens WHERE tenant_id = $1 AND id = $2`, h.tenant, id).Scan(&state, &path); err != nil {
		t.Fatal(err)
	}
	return state, path
}

// Q6-L8: the decoy login has CONNECT only on its own database, but PUBLIC
// keeps CONNECT on databases such as postgres. A session the bait opens there
// does not count on its own database; the watcher reads the server's live
// sessions for the role and raises the decoy's alert, naming that database.
func TestServedDecoyLoginInAnotherDatabaseAlertsQ6L8(t *testing.T) {
	h, planted, _ := plantServedDecoyLogin(t, "q6l8-plant")
	ctx := t.Context()
	if err := h.srv.WatchDecoyLoginsOnce(ctx); err != nil {
		t.Fatalf("decoy login watch: %v", err)
	}
	if state, _ := servedDecoyState(t, h, planted.ID); state != "active" {
		t.Fatalf("an unused decoy reads %q", state)
	}
	bait, err := pgx.Connect(ctx, strings.Replace(planted.DSN, "/"+planted.Database, "/postgres", 1))
	if err != nil {
		t.Fatalf("the bait could not log in to postgres, which PUBLIC can connect to: %v", err)
	}
	defer func() { _ = bait.Close(ctx) }()
	if _, err := bait.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.WatchDecoyLoginsOnce(ctx); err != nil {
		t.Fatalf("decoy login watch: %v", err)
	}
	state, path := servedDecoyState(t, h, planted.ID)
	if state != "triggered" || path != "postgres/postgres" {
		t.Fatalf("the bait's session in postgres left the decoy %q (%q), want triggered naming postgres/postgres", state, path)
	}
	var alerts int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("%d alerts, want the decoy's one", alerts)
	}
}
