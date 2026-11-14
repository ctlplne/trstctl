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

// TestServedDecoyStatisticsResetRecordsAGapQ6L7 is Q6-L7's Done-when
// (served, stock PostgreSQL 16): a statistics reset of a decoy login's
// database zeroes the session counter the watcher reads, so a use before it
// would go uncounted. The watcher reads pg_stat_database.stats_reset beside
// the counter: after pg_stat_reset() in the decoy's database the next check
// records a monitoring gap naming the reset and raises one warning alert; the
// following check closes the gap, and no later check records that reset
// again. A use after the reset still triggers the decoy.
func TestServedDecoyStatisticsResetRecordsAGapQ6L7(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		cfg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "q6l7-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: "postgres", Schema: "public",
			UsernamePrefix: "trstctl", AllowedRoles: []string{"readonly", "decoy"}, MaxTTL: time.Hour.String(),
		}
		provider := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true, "decoy": true}, time.Hour,
			integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
		d.DecoyLoginWatchInterval = time.Hour // the test drives each check itself
	})
	startServedExternalCADispatcher(t, h)
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "q6l7-planter", "secrets:read", "secrets:write")
	ctx := t.Context()
	count := func(kind string) int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
			AND convert_from(payload, 'UTF8')::jsonb->>'kind' = $2`, h.tenant, kind).Scan(&n); err != nil {
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
	type decoyView struct {
		ID             string     `json:"id"`
		State          string     `json:"state"`
		WatchGapSince  *time.Time `json:"watch_gap_since"`
		WatchGapReason string     `json:"watch_gap_reason"`
	}
	read := func(id string) decoyView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/databases", planter, nil)
		var listed struct {
			Items []decoyView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("list decoy logins: HTTP %d %s", status, body)
		}
		for _, item := range listed.Items {
			if item.ID == id {
				return item
			}
		}
		t.Fatalf("decoy %s is not listed: %s", id, body)
		return decoyView{}
	}
	gapsBefore, triggersBefore := count("honeytoken.watch_gap"), count("honeytoken.triggered")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/databases", planter, "q6l7-plant",
		map[string]any{"provider": "q6l7-pg", "name": "reports db bait", "placement": "ops wiki runbook", "ttl_seconds": 1800})
	var planted struct {
		ID       string `json:"id"`
		Database string `json:"database"`
		DSN      string `json:"dsn"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &planted) != nil || planted.DSN == "" {
		t.Fatalf("plant decoy login: HTTP %d %s", status, body)
	}
	watch()
	if count("honeytoken.watch_gap") != gapsBefore {
		t.Fatal("a decoy whose statistics were never reset recorded a gap")
	}

	// The server's statistics for the decoy's database are reset.
	reset, err := pgx.Connect(ctx, strings.Replace(pgDSN, "/postgres?", "/"+planted.Database+"?", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reset.Exec(ctx, `SELECT pg_stat_reset()`); err != nil {
		t.Fatal(err)
	}
	_ = reset.Close(ctx)
	watch()
	if n := count("honeytoken.watch_gap") - gapsBefore; n != 1 {
		t.Fatalf("a statistics reset raised %d gap alerts, want 1", n)
	}
	if view := read(planted.ID); view.WatchGapSince == nil || !strings.Contains(view.WatchGapReason, "statistics for the decoy's database were reset") {
		t.Fatalf("the decoy reads %+v; want an open gap naming the reset", view)
	}
	watch()
	if view := read(planted.ID); view.WatchGapSince != nil {
		t.Fatalf("the next read did not close the gap: %+v", view)
	}
	watch()
	watch()
	if n := count("honeytoken.watch_gap") - gapsBefore; n != 1 {
		t.Fatalf("the same reset was recorded again: %d gap alerts", n)
	}

	// A use after the reset still triggers the decoy.
	bait, err := pgx.Connect(ctx, planted.DSN)
	if err != nil {
		t.Fatalf("the decoy DSN does not log in: %v", err)
	}
	if _, err := bait.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	_ = bait.Close(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for count("honeytoken.triggered") == triggersBefore && time.Now().Before(deadline) {
		watch()
		time.Sleep(200 * time.Millisecond)
	}
	if n := count("honeytoken.triggered") - triggersBefore; n != 1 {
		t.Fatalf("a use after the reset raised %d alerts, want 1", n)
	}
	t.Logf("Q6L7_OK decoy=%s", planted.ID)
}
