// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

const (
	twoUserRole     = "db/orders"
	twoUserProvider = "orders-pg"
	twoUserAccountA = "orders_app_a"
	twoUserAccountB = "orders_app_b"
)

// twoUserTarget is the database a two-user rotation serves: its owner made
// the orders table and two login accounts with the same grants.
type twoUserTarget struct {
	t        *testing.T
	adminDSN string
}

func provisionTwoUserTarget(t *testing.T, adminDSN string) (*twoUserTarget, string) {
	t.Helper()
	target := &twoUserTarget{t: t, adminDSN: adminDSN}
	initial, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(initial)
	target.exec(`CREATE ROLE orders_owner NOLOGIN`,
		`CREATE SCHEMA app AUTHORIZATION orders_owner`,
		`CREATE TABLE app.orders (id bigserial PRIMARY KEY, note text NOT NULL)`,
		`ALTER TABLE app.orders OWNER TO orders_owner`,
		`CREATE ROLE `+twoUserAccountA+` LOGIN PASSWORD '`+password+`'`,
		`CREATE ROLE `+twoUserAccountB+` LOGIN`,
		`GRANT USAGE ON SCHEMA app TO `+twoUserAccountA+`, `+twoUserAccountB,
		`GRANT SELECT, INSERT ON app.orders TO `+twoUserAccountA+`, `+twoUserAccountB,
		`GRANT USAGE ON SEQUENCE app.orders_id_seq TO `+twoUserAccountA+`, `+twoUserAccountB)
	return target, target.dsn(twoUserAccountA, password)
}

func (x *twoUserTarget) dsn(account, password string) string {
	u, err := url.Parse(x.adminDSN)
	if err != nil {
		x.t.Fatal(err)
	}
	u.User = url.UserPassword(account, password)
	return u.String()
}

func (x *twoUserTarget) exec(statements ...string) {
	x.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, x.adminDSN)
	if err != nil {
		x.t.Fatalf("connect target: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, statement := range statements {
		if _, err := conn.Exec(ctx, statement); err != nil {
			x.t.Fatalf("target %q: %v", statement, err)
		}
	}
}

// write logs in with dsn and writes one order, as the application does.
func (x *twoUserTarget) write(dsn string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()
	var user string
	err = conn.QueryRow(ctx, `INSERT INTO app.orders (note) VALUES ('check') RETURNING current_user`).Scan(&user)
	return user, err
}

// grants reports whether account still holds every grant its owner gave it.
func (x *twoUserTarget) grants(account string) bool {
	x.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, x.adminDSN)
	if err != nil {
		x.t.Fatalf("connect target: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT has_schema_privilege($1, 'app', 'USAGE')
		AND has_table_privilege($1, 'app.orders', 'SELECT') AND has_table_privilege($1, 'app.orders', 'INSERT')
		AND has_sequence_privilege($1, 'app.orders_id_seq', 'USAGE')`, account).Scan(&ok); err != nil {
		x.t.Fatalf("read %s grants: %v", account, err)
	}
	return ok
}

// roles lists the target's login roles.
func (x *twoUserTarget) roles() []string {
	x.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, x.adminDSN)
	if err != nil {
		x.t.Fatalf("connect target: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
	if err != nil {
		x.t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		x.t.Fatal(err)
	}
	return names
}

// twoUserOrdersApp is the application the rotation serves: it reads its
// database credential from trstctl, keeps one session with the credential it
// last read, writes an order every tick, and reads the secret again when the
// session fails.
type twoUserOrdersApp struct {
	base   atomic.Pointer[string]
	token  string
	client *http.Client

	mu        sync.Mutex
	version   int
	conn      *pgx.Conn
	writes    map[string]int
	failures  []string
	lastWrite time.Time
	maxGap    time.Duration
}

func (app *twoUserOrdersApp) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if app.conn != nil {
				_ = app.conn.Close(context.Background())
			}
			return
		case <-ticker.C:
		}
		app.tick(ctx)
	}
}

func (app *twoUserOrdersApp) tick(ctx context.Context) {
	if value, version, err := app.read(ctx); err == nil && version != app.version {
		conn, err := pgx.Connect(ctx, value)
		if err != nil {
			app.fail(fmt.Sprintf("connect with version %d: %v", version, err))
		} else {
			if app.conn != nil {
				_ = app.conn.Close(ctx)
			}
			app.conn, app.version = conn, version
		}
	}
	if app.conn == nil {
		return
	}
	var user string
	if err := app.conn.QueryRow(ctx, `INSERT INTO app.orders (note) VALUES ('order') RETURNING current_user`).Scan(&user); err != nil {
		if ctx.Err() != nil {
			return
		}
		app.fail(fmt.Sprintf("write with version %d: %v", app.version, err))
		_ = app.conn.Close(ctx)
		app.conn, app.version = nil, 0
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	now := time.Now()
	if !app.lastWrite.IsZero() && now.Sub(app.lastWrite) > app.maxGap {
		app.maxGap = now.Sub(app.lastWrite)
	}
	app.lastWrite = now
	app.writes[user]++
}

func (app *twoUserOrdersApp) read(ctx context.Context) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *app.base.Load()+"/api/v1/secrets/store/"+twoUserRole, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	resp, err := app.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("read secret: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	return out.Value, out.Version, nil
}

func (app *twoUserOrdersApp) fail(reason string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.failures = append(app.failures, reason)
}

func (app *twoUserOrdersApp) snapshot() (writes map[string]int, failures []string, maxGap time.Duration) {
	app.mu.Lock()
	defer app.mu.Unlock()
	writes = map[string]int{}
	for user, n := range app.writes {
		writes[user] = n
	}
	return writes, append([]string(nil), app.failures...), app.maxGap
}

// A240: a two-user static rotation alternates a role between two accounts the
// database's owner provisioned with its grants. Scheduled cycles run against a
// real PostgreSQL target while an application keeps writing with whatever
// credential it last read: each cycle sets a new password on the account the
// application is not using, publishes it, proves it, and retires the other by
// replacing its password, so no account is created or dropped and both keep
// their grants. A blocked target (the delivery deadline) and a server restart
// mid-cycle leave both credentials working until retirement resumes; a
// successor the target refuses rolls back to the predecessor; nothing outside
// the pair is ever created.
func TestServedTwoUserStaticRotationKeepsGrantsA240(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	target, dsnA := provisionTwoUserTarget(t, pgDSN)
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: twoUserProvider, Type: "postgresql",
		AdminDSNRef: adminRef, Database: "postgres", Schema: "app",
		UsernamePrefix: "trstctl", AllowedRoles: []string{twoUserRole}, MaxTTL: time.Hour.String(),
		AllowStaticRotation: true,
		RotationAccounts:    map[string][]string{twoUserRole: {twoUserAccountA, twoUserAccountB}},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{
		DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig},
	}, true); err != nil {
		t.Fatalf("two-user provider configuration: %v", err)
	}
	wire := func(d *Deps) {
		d.EnableSecretsAPI = true
		// The target-timeout case waits out one delivery deadline.
		d.OutboxDeliveryTimeout = 3 * time.Second
		provider := newConfiguredDynamicProvider(providerConfig, map[string]bool{twoUserRole: true}, time.Hour,
			integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	}
	h := newOperatingServedHarness(t, config.Protocols{}, wire)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-orders",
		map[string]any{"name": twoUserRole, "value": dsnA}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}

	// The plan names the account it will set and the one it will retire, and
	// a rotation that does not name the account in use is refused.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations/preview", tok,
		map[string]any{"provider": twoUserProvider, "key": twoUserRole, "old_ref": twoUserAccountA})
	if status != http.StatusOK || !strings.Contains(string(body), "set a new password on account "+twoUserAccountB) ||
		!strings.Contains(string(body), "retire account "+twoUserAccountA) || !strings.Contains(string(body), `"ready":true`) {
		t.Fatalf("two-user preview: %d %s", status, body)
	}
	for _, oldRef := range []string{"none", "orders_someone_else"} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
			map[string]any{"provider": twoUserProvider, "key": twoUserRole, "old_ref": oldRef})
		if status != http.StatusBadRequest || !strings.Contains(string(body), "must name the account its consumers use now") {
			t.Fatalf("rotation with old_ref %q: %d %s", oldRef, status, body)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
			map[string]any{"name": "orders-bad-" + oldRef, "provider": twoUserProvider, "key": twoUserRole, "old_ref": oldRef, "interval_seconds": 1})
		if status != http.StatusBadRequest {
			t.Fatalf("schedule with old_ref %q: %d %s", oldRef, status, body)
		}
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "orders-schedule",
		map[string]any{"name": "orders-every-second", "provider": twoUserProvider, "key": twoUserRole, "old_ref": twoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)

	app := &twoUserOrdersApp{token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
		client: &http.Client{Timeout: 5 * time.Second}, writes: map[string]int{}}
	base := h.ts.URL
	app.base.Store(&base)
	appCtx, stopApp := context.WithCancel(ctx)
	appDone := make(chan struct{})
	go app.run(appCtx, appDone)
	defer func() { stopApp(); <-appDone }()
	awaitWrites := func(account string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		start, _, _ := app.snapshot()
		for {
			writes, failures, _ := app.snapshot()
			if writes[account] > start[account] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the application wrote nothing as %s: writes=%v failures=%v", account, writes, failures)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	awaitWrites(twoUserAccountA)

	readSecret := func() (string, int) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+twoUserRole, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read secret: %d %s", status, body)
		}
		var out struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		_ = json.Unmarshal(body, &out)
		return out.Value, out.Version
	}
	command := func(id string) staticRotationCommandView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read command %s: %d %s", id, status, body)
		}
		var view staticRotationCommandView
		_ = json.Unmarshal(body, &view)
		return view
	}
	outbox := func() string {
		var lastError string
		var attempts int
		_ = h.store.SystemPool().QueryRow(ctx,
			`SELECT coalesce(last_error, ''), attempts FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id DESC LIMIT 1`,
			h.tenant, store.SecretStaticRotationDestination).Scan(&lastError, &attempts)
		return fmt.Sprintf("attempts=%d last_error=%q", attempts, lastError)
	}
	// await drives the outbox until the command reaches phase (or any terminal
	// phase when phase is empty).
	await := func(id, phase string) staticRotationCommandView {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			h.srv.dispatchOnce(ctx)
			view := command(id)
			if view.Phase == phase || (phase == "" && view.Terminal) {
				return view
			}
			if view.Terminal || time.Now().After(deadline) {
				t.Fatalf("command %s: want phase %q, have %+v (%s)", id, phase, view, outbox())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// tick is the external scheduler: it waits for the schedule's due time
	// and runs the due edge, which queues one command.
	tick := func(n int) staticRotationCommandView {
		t.Helper()
		for {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules/"+schedule.ID, tok, nil)
			if status != http.StatusOK {
				t.Fatalf("read schedule: %d %s", status, body)
			}
			var view struct {
				NextRunAt time.Time `json:"next_run_at"`
			}
			_ = json.Unmarshal(body, &view)
			if wait := time.Until(view.NextRunAt); wait > 0 {
				time.Sleep(wait + 10*time.Millisecond)
				continue
			}
			break
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("orders-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+url.QueryEscape(twoUserRole), tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n || list.Items[0].ScheduleID != schedule.ID {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	works := func(dsn, account string) {
		t.Helper()
		if user, err := target.write(dsn); err != nil || user != account {
			t.Fatalf("credential for %s: user=%q err=%v", account, user, err)
		}
	}
	refused := func(dsn, account string) {
		t.Helper()
		if _, err := target.write(dsn); err == nil {
			t.Fatalf("the retired credential for %s still logs in", account)
		}
	}
	bothKeepGrants := func() {
		t.Helper()
		if !target.grants(twoUserAccountA) || !target.grants(twoUserAccountB) {
			t.Fatal("a rotation changed an account's grants")
		}
	}

	// Cycle 1, A -> B. The target holds the predecessor's row, so retirement
	// waits out the delivery deadline after the successor is published and
	// proven: both credentials work and keep their grants. The server then
	// restarts mid-cycle, the target recovers, and retirement completes.
	blocker, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blockerTx.Exec(ctx, `ALTER ROLE `+twoUserAccountA+` CONNECTION LIMIT 50`); err != nil {
		t.Fatal(err)
	}
	cmd := tick(1)
	if cmd.OldRef != twoUserAccountA {
		t.Fatalf("cycle 1 predecessor: %+v", cmd)
	}
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	if verified.NewRef != twoUserAccountB || verified.VerifyMode != "connected" {
		t.Fatalf("cycle 1 successor: %+v", verified)
	}
	// Retirement meets the blocked target and fails at the delivery deadline;
	// the command stays verified with the failure recorded for a retry.
	for deadline := time.Now().Add(60 * time.Second); !strings.Contains(outbox(), `last_error="external_delivery_failed"`); {
		if time.Now().After(deadline) {
			t.Fatalf("the blocked retirement left no retry evidence: %s", outbox())
		}
		h.srv.dispatchOnce(ctx)
		time.Sleep(100 * time.Millisecond)
	}
	if view := command(cmd.ID); view.Phase != store.SecretStaticRotationVerified {
		t.Fatalf("retirement passed a blocked target: %+v (%s)", view, outbox())
	}
	dsnB, version := readSecret()
	if version != 2 {
		t.Fatalf("cycle 1 published version %d", version)
	}
	works(dsnA, twoUserAccountA)
	works(dsnB, twoUserAccountB)
	bothKeepGrants()
	awaitWrites(twoUserAccountB)

	h.ts.Close()
	restarted, err := Build(ctx, func() Deps {
		d := Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile,
			KEK: h.kek, Protocols: config.Protocols{}, APIOptions: []api.Option{
				api.WithKubernetesCSRPosture(h.store), api.WithKubernetesTrustBundlePosture(h.store), api.WithKubernetesTrustRollouts(h.store)}}
		wire(&d)
		return d
	}())
	if err != nil {
		t.Fatalf("restart server: %v", err)
	}
	cleanupServedServer(t, restarted)
	restartedTS := httptest.NewServer(restarted.Handler())
	t.Cleanup(restartedTS.Close)
	h.srv, h.ts = restarted, restartedTS
	base = restartedTS.URL
	app.base.Store(&base)
	if err := blockerTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	_ = blocker.Close(ctx)
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted || final.ResultVersion != 2 {
		t.Fatalf("cycle 1 after restart: %+v (%s)", final, outbox())
	}
	refused(dsnA, twoUserAccountA)
	works(dsnB, twoUserAccountB)
	bothKeepGrants()

	// Cycles 2 and 3 alternate back and forth, unattended.
	live, liveAccount := dsnB, twoUserAccountB
	for _, step := range []struct {
		n       int
		account string
	}{{2, twoUserAccountA}, {3, twoUserAccountB}} {
		cmd = tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.OldRef != liveAccount || final.NewRef != step.account {
			t.Fatalf("cycle %d: %+v (%s)", step.n, final, outbox())
		}
		next, version := readSecret()
		if version != step.n+1 {
			t.Fatalf("cycle %d published version %d", step.n, version)
		}
		works(next, step.account)
		refused(live, liveAccount)
		bothKeepGrants()
		awaitWrites(step.account)
		live, liveAccount = next, step.account
	}

	// Cycle 4: the target refuses the successor's logins. Verification fails,
	// the predecessor's value comes back as the next version, and the
	// successor's password is replaced again: only the predecessor works.
	target.exec(`ALTER ROLE ` + twoUserAccountA + ` CONNECTION LIMIT 0`)
	cmd = tick(4)
	final := await(cmd.ID, "")
	if final.Phase != store.SecretStaticRotationRolledBack || final.NewRef != twoUserAccountA || final.RestoredVersion != 6 {
		t.Fatalf("cycle 4 with a refused successor: %+v (%s)", final, outbox())
	}
	restored, version := readSecret()
	if version != 6 || restored != live {
		t.Fatalf("the rollback restored version %d (same value: %v)", version, restored == live)
	}
	works(live, liveAccount)
	target.exec(`ALTER ROLE ` + twoUserAccountA + ` CONNECTION LIMIT -1`)
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/history/"+twoUserRole+"?version=5", tok, nil)
	var rejected struct {
		Value string `json:"value"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &rejected) != nil || rejected.Value == "" {
		t.Fatalf("read the rolled-back version: %d", status)
	}
	refused(rejected.Value, twoUserAccountA) // its password was replaced at rollback
	bothKeepGrants()

	// Cycle 5 starts from the restored predecessor and completes.
	cmd = tick(5)
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted || final.OldRef != twoUserAccountB || final.NewRef != twoUserAccountA {
		t.Fatalf("cycle 5: %+v (%s)", final, outbox())
	}
	next, _ := readSecret()
	works(next, twoUserAccountA)
	refused(live, twoUserAccountB)
	awaitWrites(twoUserAccountA)
	bothKeepGrants()

	// Nothing outside the pair was ever created, and the application wrote
	// through every cycle with both accounts.
	if roles := strings.Join(target.roles(), ","); roles != "orders_app_a,orders_app_b,postgres" {
		t.Fatalf("login roles after the rotations: %s", roles)
	}
	stopApp()
	<-appDone
	writes, failures, maxGap := app.snapshot()
	if writes[twoUserAccountA] == 0 || writes[twoUserAccountB] == 0 {
		t.Fatalf("application writes per account: %v", writes)
	}
	if maxGap > 5*time.Second {
		t.Fatalf("the application went %s without a write (failures: %v)", maxGap, failures)
	}
	// The application only ever failed to adopt the refused successor
	// (version 5), or lost a session at a retirement and read again.
	sessionsLost := 0
	for _, failure := range failures {
		switch {
		case strings.HasPrefix(failure, "connect with version 5:"):
		case strings.HasPrefix(failure, "write with version "):
			sessionsLost++
		default:
			t.Fatalf("unexpected application failure: %s", failure)
		}
	}
	if sessionsLost > 4 {
		t.Fatalf("the application lost %d sessions in four retirements: %v", sessionsLost, failures)
	}
	t.Logf("application writes %v, longest gap %s, %d refused adoptions of the rejected successor, %d sessions ended at retirement",
		writes, maxGap, len(failures)-sessionsLost, sessionsLost)
}
