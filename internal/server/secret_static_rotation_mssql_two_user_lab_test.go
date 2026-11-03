// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

const (
	mssqlTwoUserRole     = "orders-app"
	mssqlTwoUserProvider = "mssql-two-user"
	mssqlTwoUserAccountA = "orders_app_a"
	mssqlTwoUserAccountB = "orders_app_b"
)

// mssqlConnects reports whether user/password logs in at the administrator
// DSN's address, in orders, and runs SELECT 1, as an application's driver
// would.
func mssqlConnects(adminDSN, user, password string) bool {
	target, err := url.Parse(adminDSN)
	if err != nil {
		return false
	}
	target.User = url.UserPassword(user, password)
	query := target.Query()
	query.Set("database", "orders")
	target.RawQuery = query.Encode()
	db, err := sql.Open("sqlserver", target.String())
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var one int
	return db.QueryRowContext(ctx, "SELECT 1").Scan(&one) == nil && one == 1
}

// sqlAdmin runs a query with the stock sqlcmd as the lab's administrator.
func (lab mssqlLab) sqlAdmin(t *testing.T, adminDSN, database, query string) string {
	t.Helper()
	parsed, err := url.Parse(adminDSN)
	if err != nil || parsed.User == nil {
		t.Fatalf("the lab admin DSN: %v", err)
	}
	password, _ := parsed.User.Password()
	return lab.run(t, parsed.User.Username(), password, database, query)
}

// A240 on SQL Server 2022: a two-user static rotation alternates a role
// between two existing logins whose users in orders are db_datareader members
// (scripts/ci/a239-mssql-lab.sh's orders_app_a and orders_app_b). Three unattended
// scheduled cycles run while an application connects with whatever credential
// it last read and reports each version it used; each cycle sets a new
// password on the login the application is not using, proves it by
// connecting, and, once the application reports, retires the other by
// setting a password nobody holds and ending its sessions. Both logins stay
// enabled with their role memberships, and nothing is created or dropped. A paused database times
// the retirement out and leaves the predecessor connecting until it resumes.
func TestServedSQLServerTwoUserStaticRotationKeepsGrantsA240(t *testing.T) {
	lab := requireMSSQLLab(t)
	initialPassword := strings.TrimSpace(os.Getenv("TRSTCTL_A240_MSSQL_INITIAL_PASSWORD"))
	if initialPassword == "" {
		t.Skip("lab test: scripts/ci/a239-mssql-lab.sh sets TRSTCTL_A240_MSSQL_INITIAL_PASSWORD for orders_app_a")
	}
	adminDSN := strings.TrimSpace(string(mustReadMSSQLDSN(t, lab.dsnFile)))
	connects := func(user, password string) bool { return mssqlConnects(adminDSN, user, password) }
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: mssqlTwoUserProvider, Type: "mssql",
		AdminDSNRef: writeServedCredentialFile(t, "mssql-two-user-admin-dsn", adminDSN), Database: "orders",
		AllowedRoles: []string{mssqlTwoUserRole}, MaxTTL: "1h", AllowStaticRotation: true,
		RotationAccounts: map[string][]string{mssqlTwoUserRole: {mssqlTwoUserAccountA, mssqlTwoUserAccountB}},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig}}, true); err != nil {
		t.Fatalf("two-user SQL Server provider: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{providerConfig}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.OutboxDeliveryTimeout = 5 * time.Second // the paused server waits out one delivery deadline
	})
	registerServedTenant(t, h, "A240 SQL Server two-user tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()
	seed, _ := json.Marshal(map[string]string{"username": mssqlTwoUserAccountA, "password": initialPassword, "database": "orders"})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-mssql-orders",
		map[string]any{"name": mssqlTwoUserRole, "value": string(seed)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "mssql-orders-schedule",
		map[string]any{"name": "mssql-orders", "provider": mssqlTwoUserProvider, "key": mssqlTwoUserRole, "old_ref": mssqlTwoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"consumers": []string{"orders-app"}, "retire_after_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)
	app := &twoUserApp{secret: mssqlTwoUserRole, connects: connects, base: h.ts.URL, token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
		client: &http.Client{Timeout: 5 * time.Second}, logins: map[string]int{}}
	appCtx, stopApp := context.WithCancel(ctx)
	appDone := make(chan struct{})
	go app.run(appCtx, appDone)
	defer func() { stopApp(); <-appDone }()
	awaitLogins := func(user string) {
		t.Helper()
		start, _ := app.snapshot()
		for deadline := time.Now().Add(90 * time.Second); ; {
			logins, failures := app.snapshot()
			if logins[user] > start[user] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the application never connected as %s: logins=%v failures=%v", user, logins, failures)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	awaitLogins(mssqlTwoUserAccountA)
	command := func(id string) staticRotationCommandView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
		var view staticRotationCommandView
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("read command %s: %d %s", id, status, body)
		}
		return view
	}
	await := func(id, phase string) staticRotationCommandView {
		t.Helper()
		for deadline := time.Now().Add(180 * time.Second); ; {
			h.srv.dispatchOnce(ctx)
			view := command(id)
			if view.Phase == phase || (phase == "" && view.Terminal) {
				return view
			}
			if view.Terminal || time.Now().After(deadline) {
				t.Fatalf("command %s: want phase %q, have %+v", id, phase, view)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	tick := func(n int) staticRotationCommandView {
		t.Helper()
		for {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules/"+schedule.ID, tok, nil)
			var view struct {
				NextRunAt time.Time `json:"next_run_at"`
			}
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read schedule: %d %s", status, body)
			}
			if wait := time.Until(view.NextRunAt); wait > 0 {
				time.Sleep(wait + 10*time.Millisecond)
				continue
			}
			break
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("mssql-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+url.QueryEscape(mssqlTwoUserRole), tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	readCredential := func() userPassword {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+mssqlTwoUserRole, tok, nil)
		var out struct {
			Value string `json:"value"`
		}
		var credential userPassword
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil || json.Unmarshal([]byte(out.Value), &credential) != nil {
			t.Fatalf("read the secret: %d", status)
		}
		return credential
	}
	keepGrants := func() {
		t.Helper()
		out := lab.sqlAdmin(t, adminDSN, "orders", "SET NOCOUNT ON; SELECT CONCAT(dp.name, '=', IS_ROLEMEMBER('db_datareader', dp.name), '/', sp.is_disabled) "+
			"FROM sys.database_principals dp JOIN sys.server_principals sp ON sp.sid = dp.sid WHERE dp.name IN ('"+mssqlTwoUserAccountA+"', '"+mssqlTwoUserAccountB+"') ORDER BY dp.name; "+
			"SELECT CONCAT('logins=', COUNT(*)) FROM sys.server_principals WHERE name LIKE 'orders[_]app[_]%'")
		if !strings.Contains(out, mssqlTwoUserAccountA+"=1/0") || !strings.Contains(out, mssqlTwoUserAccountB+"=1/0") || !strings.Contains(out, "logins=2") {
			t.Fatalf("the server's logins after a rotation:\n%s", out)
		}
	}

	live := userPassword{Username: mssqlTwoUserAccountA, Password: initialPassword}
	for _, step := range []struct {
		n    int
		user string
	}{{1, mssqlTwoUserAccountB}, {2, mssqlTwoUserAccountA}, {3, mssqlTwoUserAccountB}} {
		cmd := tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.NewRef != step.user || final.OldRef != live.Username ||
			final.VerifyMode != "connected" || final.ConsumerAdoption != "adopted" {
			t.Fatalf("cycle %d: %+v", step.n, final)
		}
		next := readCredential()
		if next.Username != step.user || !connects(next.Username, next.Password) {
			t.Fatalf("cycle %d: the published credential for %s does not connect", step.n, step.user)
		}
		if connects(live.Username, live.Password) {
			t.Fatalf("cycle %d: the retired password of %s still connects", step.n, live.Username)
		}
		keepGrants()
		awaitLogins(step.user)
		live = next
	}

	// A paused server: retirement times out, the command stays verified, and
	// the predecessor connects until the database resumes and retirement
	// completes.
	app.quiet.Store(true)
	cmd := tick(4)
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	successor := readCredential()
	awaitLogins(mssqlTwoUserAccountA)
	app.paused.Store(true)
	if out, err := exec.Command("docker", "pause", lab.container).CombinedOutput(); err != nil { // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		t.Fatalf("pause the server: %v %s", err, out)
	}
	if err := app.report(ctx, verified.ResultVersion); err != nil {
		t.Fatalf("report the successor: %v", err)
	}
	app.mu.Lock()
	app.reported = verified.ResultVersion
	app.mu.Unlock()
	app.quiet.Store(false)
	for deadline := time.Now().Add(90 * time.Second); ; {
		h.srv.dispatchOnce(ctx)
		var lastError string
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id DESC LIMIT 1`,
			h.tenant, store.SecretStaticRotationDestination).Scan(&lastError)
		if lastError == "external_delivery_failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the retirement against a paused database left no retry evidence (last_error %q)", lastError)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if view := command(cmd.ID); view.Phase != store.SecretStaticRotationVerified {
		t.Fatalf("retirement passed a paused database: %+v", view)
	}
	if out, err := exec.Command("docker", "unpause", lab.container).CombinedOutput(); err != nil { // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		t.Fatalf("unpause the server: %v %s", err, out)
	}
	app.paused.Store(false)
	if !connects(live.Username, live.Password) {
		t.Fatal("a timed-out retirement left the predecessor unable to connect")
	}
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("cycle 4 after the database resumed: %+v", final)
	}
	if connects(live.Username, live.Password) || !connects(successor.Username, successor.Password) {
		t.Fatal("after the resumed retirement only the successor may connect")
	}
	keepGrants()

	stopApp()
	<-appDone
	logins, failures := app.snapshot()
	if logins[mssqlTwoUserAccountA] == 0 || logins[mssqlTwoUserAccountB] == 0 {
		t.Fatalf("application connections per user: %v", logins)
	}
	for _, failure := range failures {
		if !strings.HasPrefix(failure, "paused: ") {
			t.Fatalf("the application failed outside the paused window: %s", failure)
		}
	}
	t.Logf("A240_MSSQL_OK application connections %v; %d failures, all while the database was paused", logins, len(failures))
}
