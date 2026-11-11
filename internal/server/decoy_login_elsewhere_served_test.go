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

// servedDecoyLab is a served tenant PostgreSQL provider minting decoy logins
// against a real PostgreSQL, with one decoy planted.
type servedDecoyLab struct {
	h        *servedHarness
	planted  servedDecoyLogin
	planter  string
	adminDSN string
}

// plantServedDecoyLogin serves the lab and plants one decoy; opts adjust the
// server's dependencies.
func plantServedDecoyLogin(t *testing.T, key string, opts ...func(*Deps)) servedDecoyLab {
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
		for _, opt := range opts {
			opt(d)
		}
	})
	startServedExternalCADispatcher(t, h)
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "decoy-planter", "secrets:read", "secrets:write")
	return servedDecoyLab{h: h, planted: plantAnotherServedDecoyLogin(t, h, planter, key), planter: planter, adminDSN: pgDSN}
}

func plantAnotherServedDecoyLogin(t *testing.T, h *servedHarness, planter, key string) servedDecoyLogin {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, key,
		map[string]any{"provider": "warehouse-pg", "name": "warehouse db bait " + key, "placement": "ops wiki runbook", "ttl_seconds": 1800})
	if status != http.StatusCreated {
		t.Fatalf("plant decoy login: HTTP %d %s", status, body)
	}
	var planted servedDecoyLogin
	if err := json.Unmarshal(body, &planted); err != nil || planted.DSN == "" {
		t.Fatalf("planted decoy login = %+v (%v)", planted, err)
	}
	return planted
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
	lab := plantServedDecoyLogin(t, "q6l8-plant")
	h, planted := lab.h, lab.planted
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

// Q6-L9: a decoy lives as long as its lease. When the lease ends, an unused
// decoy retires instead of staying active with nothing to watch, and a decoy
// the bait used before the end still raises its alert first.
func TestServedDecoyLoginRetiresWhenItsLeaseEndsQ6L9(t *testing.T) {
	lab := plantServedDecoyLogin(t, "q6l9-unused")
	h, unused := lab.h, lab.planted
	used := plantAnotherServedDecoyLogin(t, h, lab.planter, "q6l9-used")
	ctx := t.Context()
	watch := func() {
		t.Helper()
		if err := h.srv.WatchDecoyLoginsOnce(ctx); err != nil {
			t.Fatalf("decoy login watch: %v", err)
		}
	}
	watch()
	for _, decoy := range []servedDecoyLogin{unused, used} {
		if state, _ := servedDecoyState(t, h, decoy.ID); state != "active" {
			t.Fatalf("decoy %s reads %q before its lease ends", decoy.ID, state)
		}
	}
	bait, err := pgx.Connect(ctx, used.DSN)
	if err != nil {
		t.Fatalf("the decoy DSN does not log in: %v", err)
	}
	if _, err := bait.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	_ = bait.Close(ctx)
	for _, decoy := range []servedDecoyLogin{unused, used} {
		if _, err := h.store.SystemPool().Exec(ctx,
			`UPDATE dynamic_secret_leases SET expires_at = now() - interval '1 minute', hard_expires_at = now() - interval '1 minute'
			  WHERE tenant_id = $1 AND id = $2`,
			h.tenant, decoy.DBLeaseID); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		watch()
		usedState, _ := servedDecoyState(t, h, used.ID)
		unusedState, _ := servedDecoyState(t, h, unused.ID)
		if usedState != "active" && unusedState != "active" {
			if unusedState != "revoked" || usedState != "triggered" {
				t.Fatalf("after the leases ended: unused decoy %q, used decoy %q; want revoked and triggered", unusedState, usedState)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("decoys still active after their leases ended: unused %q, used %q", unusedState, usedState)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var alerts int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("%d alerts, want the used decoy's one", alerts)
	}
}

// Q6-L10: a decoy login the watcher cannot read past the grace records a
// monitoring gap on the decoy, since when and why, with one warning through
// the outbox; reading it again closes the gap.
func TestServedDecoyLoginWatchGapIsRecordedAndClosesQ6L10(t *testing.T) {
	lab := plantServedDecoyLogin(t, "q6l10-plant", func(d *Deps) { d.DecoyLoginWatchGapGrace = time.Nanosecond })
	h, planted := lab.h, lab.planted
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, lab.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	database := pgx.Identifier{planted.Database}.Sanitize()
	if _, err := admin.Exec(ctx, "DROP DATABASE "+database+" WITH (FORCE)"); err != nil {
		t.Fatal(err)
	}
	gap := func() (since *time.Time, reason string) {
		t.Helper()
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT watch_gap_since, COALESCE(watch_gap_reason, '') FROM honey_tokens WHERE tenant_id = $1 AND id = $2`,
			h.tenant, planted.ID).Scan(&since, &reason); err != nil {
			t.Fatal(err)
		}
		return since, reason
	}
	gapAlerts := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
			    AND convert_from(payload, 'UTF8')::jsonb->>'kind' = 'honeytoken.watch_gap'`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for range 3 {
		if err := h.srv.WatchDecoyLoginsOnce(ctx); err == nil {
			t.Fatal("the watch reported no error for a decoy it cannot read")
		}
		time.Sleep(10 * time.Millisecond)
	}
	since, reason := gap()
	if since == nil || !strings.Contains(reason, "its database is gone while its lease is active") {
		t.Fatalf("monitoring gap = %v %q, want one recorded with its reason", since, reason)
	}
	if n := gapAlerts(); n != 1 {
		t.Fatalf("%d monitoring-gap alerts after three failed checks, want 1", n)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/databases", lab.planter, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"watch_gap_reason"`) {
		t.Fatalf("the decoy list does not show the gap: HTTP %d %s", status, body)
	}

	role := pgx.Identifier{planted.DBRole}.Sanitize()
	for _, stmt := range []string{
		"CREATE DATABASE " + database,
		"REVOKE CONNECT, TEMPORARY ON DATABASE " + database + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + database + " TO " + role,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.srv.WatchDecoyLoginsOnce(ctx); err != nil {
		t.Fatalf("decoy login watch after the database is back: %v", err)
	}
	if since, _ := gap(); since != nil {
		t.Fatalf("the monitoring gap is still open after the decoy was read again (since %v)", since)
	}
	if state, _ := servedDecoyState(t, h, planted.ID); state != "active" {
		t.Fatalf("the decoy reads %q after its gap closed", state)
	}
	if n := gapAlerts(); n != 1 {
		t.Fatalf("%d monitoring-gap alerts, want the one", n)
	}
}
