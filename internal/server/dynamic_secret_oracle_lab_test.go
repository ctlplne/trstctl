// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	go_ora "github.com/sijms/go-ora/v2"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// labOracle is the A239 runner's Oracle Database Free: the pluggable
// database's address and service, the administrator's URL, and the
// container (for the stock sqlplus, and to pause it).
type labOracle struct {
	addr, service, adminDSN, container, systemPassword string
}

func oracleLab(t *testing.T) labOracle {
	t.Helper()
	lab := labOracle{addr: os.Getenv("TRSTCTL_A239_ORACLE_ADDR"), service: os.Getenv("TRSTCTL_A239_ORACLE_SERVICE"),
		container: os.Getenv("TRSTCTL_A239_ORACLE_CONTAINER")}
	dsnFile, systemFile := os.Getenv("TRSTCTL_A239_ORACLE_ADMIN_DSN_FILE"), os.Getenv("TRSTCTL_A239_ORACLE_SYSTEM_PASSWORD_FILE")
	if lab.addr == "" || lab.service == "" || lab.container == "" || dsnFile == "" || systemFile == "" {
		t.Skip("lab test: the A239 runner starts Oracle Database Free and sets TRSTCTL_A239_ORACLE_ADDR, _SERVICE, _CONTAINER, _ADMIN_DSN_FILE and _SYSTEM_PASSWORD_FILE")
	}
	for path, out := range map[string]*string{dsnFile: &lab.adminDSN, systemFile: &lab.systemPassword} {
		raw, err := os.ReadFile(path) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		*out = strings.TrimSpace(string(raw))
	}
	return lab
}

// sqlplus runs a script in the stock sqlplus inside the container; the
// script carries the CONNECT, so no password is on a command line.
func (lab labOracle) sqlplus(script string) string {
	cmd := exec.Command("docker", "exec", "-i", lab.container, "sqlplus", "-s", "-l", "/nolog") // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
	cmd.Stdin = strings.NewReader("WHENEVER SQLERROR CONTINUE\nSET HEADING OFF FEEDBACK OFF PAGESIZE 0\n" + script + "\nEXIT\n")
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func (lab labOracle) connectLine(user, password string) string {
	return fmt.Sprintf("CONNECT %s/\"%s\"@//localhost:1521/%s", user, password, lab.service)
}

func (lab labOracle) asSystem(statements string) string {
	return lab.sqlplus(lab.connectLine("system", lab.systemPassword) + "\n" + statements)
}

// connects reports whether user/password opens a session at the lab's
// address and queries DUAL, as an application's driver would.
func (lab labOracle) connects(user, password string) bool {
	host, portText, err := net.SplitHostPort(lab.addr)
	if err != nil {
		return false
	}
	port, _ := strconv.Atoi(portText)
	db, err := sql.Open("oracle", go_ora.BuildUrl(host, port, lab.service, user, password, nil))
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var one int
	return db.QueryRowContext(ctx, "SELECT 1 FROM DUAL").Scan(&one) == nil && one == 1
}

type oracleCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// A239 against stock Oracle Database Free (26ai), configured by the A239
// runner: in pluggable database FREEPDB1, administrator LAB_ADMIN (CREATE,
// ALTER and DROP USER, ALTER SYSTEM, SELECT on V$SESSION, and ORDERS_READER
// with ADMIN OPTION; not a DBA), role ORDERS_READER (CREATE SESSION and
// SELECT on ORDERS.ITEMS), and tables ORDERS.ITEMS and BILLING.INVOICES with
// one row each. A lease is a user the stock sqlplus reads ORDERS.ITEMS with
// and is refused an insert and BILLING.INVOICES; revoking the lease kills a
// session still open and drops the user, after which its login fails.
func TestServedDynamicOracleUserAgainstOracleA239(t *testing.T) {
	lab := oracleLab(t)
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "oracle-lab", Type: "oracle",
		AdminDSNRef:  writeServedCredentialFile(t, "oracle-lab-admin-dsn", lab.adminDSN),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "ORDERS_READER"}, MaxTTL: "1h",
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239 Oracle lab tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-oracle-lab-1",
		map[string]any{"provider": "oracle-lab", "role": "reader", "ttl_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential oracleCredential
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential.Username == "" || credential.Password == "" {
		t.Fatalf("credential: %v", err)
	}
	as := lab.connectLine(credential.Username, credential.Password)
	if out := lab.sqlplus(as + "\nSELECT id FROM orders.items;"); !strings.Contains(out, "order-1") {
		t.Fatalf("the leased user did not read ORDERS.ITEMS:\n%s", out)
	}
	// 23ai names the missing privilege (ORA-41900); earlier releases say
	// ORA-01031 (insufficient privileges).
	if out := lab.sqlplus(as + "\nINSERT INTO orders.items (id) VALUES ('from-the-lease');"); !strings.Contains(out, "ORA-41900") && !strings.Contains(out, "ORA-01031") {
		t.Fatalf("the database did not refuse the leased user's insert:\n%s", out)
	}
	if out := lab.sqlplus(as + "\nSELECT id FROM billing.invoices;"); (!strings.Contains(out, "ORA-00942") && !strings.Contains(out, "ORA-41900")) || strings.Contains(out, "invoice-1") {
		t.Fatalf("the database did not refuse the leased user BILLING.INVOICES:\n%s", out)
	}

	// A stock sqlplus that stays connected as the leased user.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	live := exec.CommandContext(ctx, "docker", "exec", "-i", lab.container, "sqlplus", "-s", "-l", "/nolog") // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
	stdin, err := live.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	live.Stdout, live.Stderr = writer, writer
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	lines := make(chan string, 256)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	go func() { _ = live.Wait(); _ = writer.Close() }()
	var liveOutput []string
	await := func(match func(string) bool, within time.Duration) bool {
		t.Helper()
		timer := time.NewTimer(within)
		defer timer.Stop()
		for {
			select {
			case line, open := <-lines:
				if !open {
					return false
				}
				liveOutput = append(liveOutput, line)
				if match(line) {
					return true
				}
			case <-timer.C:
				return false
			}
		}
	}
	if _, err := io.WriteString(stdin, "SET HEADING OFF FEEDBACK OFF PAGESIZE 0\n"+as+"\nSELECT id FROM orders.items;\n"); err != nil {
		t.Fatal(err)
	}
	if !await(func(line string) bool { return strings.Contains(line, "order-1") }, 90*time.Second) {
		t.Fatalf("the live session did not read order-1:\n%s", strings.Join(liveOutput, "\n"))
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 600}); status != http.StatusOK {
		t.Fatalf("renew within the maximum lifetime: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(90 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var refusal string
	_, _ = io.WriteString(stdin, "SELECT id FROM orders.items;\n")
	if !await(func(line string) bool {
		refusal = line
		for _, code := range []string{"ORA-00028", "ORA-03113", "ORA-03114", "ORA-03135", "ORA-01012", "SP2-0640"} {
			if strings.Contains(line, code) {
				return true
			}
		}
		return false
	}, 60*time.Second) {
		t.Fatalf("the live session was not ended by the revocation:\n%s", strings.Join(liveOutput, "\n"))
	}
	if out := lab.sqlplus(as + "\nSELECT id FROM orders.items;"); !strings.Contains(out, "ORA-01017") || strings.Contains(out, "order-1") {
		t.Fatalf("Oracle still accepts the revoked user's login:\n%s", out)
	}
	if left := strings.TrimSpace(lab.asSystem("SELECT COUNT(*) FROM all_users WHERE username = '" + credential.Username + "';")); left != "0" {
		t.Fatalf("the revoked user is still there: %q", left)
	}
	t.Logf("A239_ORACLE_OK lease=%s user=%s open_session_refusal=%q", lease.ID, credential.Username, refusal)
}

const (
	oracleTwoUserRole     = "orders-app"
	oracleTwoUserProvider = "oracle-two-user"
	oracleTwoUserAccountA = "ORDERS_APP_A"
	oracleTwoUserAccountB = "ORDERS_APP_B"
)

// oracleOrdersApp connects with whatever credential it last read, every
// tick, and reports a version verified once it connected with it.
type oracleOrdersApp struct {
	lab    labOracle
	base   string
	token  string
	client *http.Client
	paused atomic.Bool
	quiet  atomic.Bool

	mu         sync.Mutex
	version    int
	credential oracleCredential
	reported   int
	logins     map[string]int
	failures   []string
}

func (app *oracleOrdersApp) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		app.tick(ctx)
	}
}

func (app *oracleOrdersApp) tick(ctx context.Context) {
	var read struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	readOK := false
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.base+"/api/v1/secrets/store/"+oracleTwoUserRole, nil); err == nil {
		req.Header.Set("Authorization", "Bearer "+app.token)
		if resp, err := app.client.Do(req); err == nil {
			readOK = resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&read) == nil
			_ = resp.Body.Close()
		}
	}
	app.mu.Lock()
	current, credential := app.version, app.credential
	app.mu.Unlock()
	if readOK && read.Version != current {
		var next oracleCredential
		if json.Unmarshal([]byte(read.Value), &next) != nil || !app.lab.connects(next.Username, next.Password) {
			app.fail(fmt.Sprintf("adopt version %d", read.Version))
		} else {
			app.mu.Lock()
			app.version, app.credential = read.Version, next
			app.mu.Unlock()
			current, credential = read.Version, next
		}
	}
	if current == 0 {
		return
	}
	if !app.lab.connects(credential.Username, credential.Password) {
		if ctx.Err() == nil {
			app.fail(fmt.Sprintf("connect with version %d", current))
		}
		return
	}
	app.mu.Lock()
	app.logins[credential.Username]++
	reported := app.reported
	app.mu.Unlock()
	if current != reported && !app.quiet.Load() && app.report(ctx, current) == nil {
		app.mu.Lock()
		app.reported = current
		app.mu.Unlock()
	}
}

func (app *oracleOrdersApp) fail(message string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.paused.Load() {
		message = "paused: " + message
	}
	app.failures = append(app.failures, message)
}

func (app *oracleOrdersApp) report(ctx context.Context, version int) error {
	body, _ := json.Marshal(map[string]any{"consumer": "orders-app", "state": "verified",
		"secrets": []map[string]any{{"name": oracleTwoUserRole, "version": version}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.base+"/api/v1/secrets/deliveries", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("oracle-orders-app-verified-%d", version))
	resp, err := app.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("report version %d: HTTP %d", version, resp.StatusCode)
	}
	return nil
}

func (app *oracleOrdersApp) snapshot() (map[string]int, []string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	logins := map[string]int{}
	for user, n := range app.logins {
		logins[user] = n
	}
	return logins, append([]string(nil), app.failures...)
}

// A240 on a real Oracle Database: a two-user static rotation alternates a
// role between two existing users that hold its grants (the runner's
// ORDERS_APP_A and ORDERS_APP_B, granted ORDERS_READER). Three unattended
// scheduled cycles run while an application connects with whatever credential
// it last read and reports each version it used; each cycle sets a new
// password on the user the application is not using, proves it by
// connecting, and, once the application reports, retires the other by
// setting a password nobody holds and ending its sessions. Both users keep
// their grants and nothing is created or dropped. A paused database times
// the retirement out and leaves the predecessor connecting until it resumes.
func TestServedOracleTwoUserStaticRotationKeepsGrantsA240(t *testing.T) {
	lab := oracleLab(t)
	initialPassword := strings.TrimSpace(os.Getenv("TRSTCTL_A240_ORACLE_INITIAL_PASSWORD"))
	if initialPassword == "" {
		t.Skip("lab test: the A239 runner sets TRSTCTL_A240_ORACLE_INITIAL_PASSWORD for ORDERS_APP_A")
	}
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: oracleTwoUserProvider, Type: "oracle",
		AdminDSNRef:  writeServedCredentialFile(t, "oracle-two-user-admin-dsn", lab.adminDSN),
		AllowedRoles: []string{oracleTwoUserRole}, MaxTTL: "1h", AllowStaticRotation: true,
		RotationAccounts: map[string][]string{oracleTwoUserRole: {oracleTwoUserAccountA, oracleTwoUserAccountB}},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig}}, true); err != nil {
		t.Fatalf("two-user Oracle provider: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{providerConfig}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.OutboxDeliveryTimeout = 5 * time.Second // the paused database waits out one delivery deadline
	})
	registerServedTenant(t, h, "A240 Oracle two-user tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()
	seed, _ := json.Marshal(oracleCredential{Username: oracleTwoUserAccountA, Password: initialPassword}) // #nosec G117 -- the lab's own initial password, seeded into the test tenant's secret store (CWE-200)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-oracle-orders",
		map[string]any{"name": oracleTwoUserRole, "value": string(seed)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "oracle-orders-schedule",
		map[string]any{"name": "oracle-orders", "provider": oracleTwoUserProvider, "key": oracleTwoUserRole, "old_ref": oracleTwoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"consumers": []string{"orders-app"}, "retire_after_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)
	app := &oracleOrdersApp{lab: lab, base: h.ts.URL, token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
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
	awaitLogins(oracleTwoUserAccountA)
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
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("oracle-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+url.QueryEscape(oracleTwoUserRole), tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	readCredential := func() oracleCredential {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+oracleTwoUserRole, tok, nil)
		var out struct {
			Value string `json:"value"`
		}
		var credential oracleCredential
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil || json.Unmarshal([]byte(out.Value), &credential) != nil {
			t.Fatalf("read the secret: %d", status)
		}
		return credential
	}
	keepGrants := func() {
		t.Helper()
		out := lab.asSystem("SELECT grantee || '=' || granted_role FROM dba_role_privs WHERE grantee IN ('" + oracleTwoUserAccountA + "', '" +
			oracleTwoUserAccountB + "') ORDER BY grantee;\nSELECT 'users=' || COUNT(*) FROM all_users WHERE username LIKE 'ORDERS\\_APP\\_%' ESCAPE '\\';")
		if !strings.Contains(out, oracleTwoUserAccountA+"=ORDERS_READER") || !strings.Contains(out, oracleTwoUserAccountB+"=ORDERS_READER") ||
			!strings.Contains(out, "users=2") {
			t.Fatalf("the database's users after a rotation:\n%s", out)
		}
	}

	live := oracleCredential{Username: oracleTwoUserAccountA, Password: initialPassword}
	for _, step := range []struct {
		n    int
		user string
	}{{1, oracleTwoUserAccountB}, {2, oracleTwoUserAccountA}, {3, oracleTwoUserAccountB}} {
		cmd := tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.NewRef != step.user || final.OldRef != live.Username ||
			final.VerifyMode != "connected" || final.ConsumerAdoption != "adopted" {
			t.Fatalf("cycle %d: %+v", step.n, final)
		}
		next := readCredential()
		if next.Username != step.user || !lab.connects(next.Username, next.Password) {
			t.Fatalf("cycle %d: the published credential for %s does not connect", step.n, step.user)
		}
		if lab.connects(live.Username, live.Password) {
			t.Fatalf("cycle %d: the retired password of %s still connects", step.n, live.Username)
		}
		keepGrants()
		awaitLogins(step.user)
		live = next
	}

	// A paused database: retirement times out, the command stays verified, and
	// the predecessor connects until the database resumes and retirement
	// completes.
	app.quiet.Store(true)
	cmd := tick(4)
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	successor := readCredential()
	awaitLogins(oracleTwoUserAccountA)
	app.paused.Store(true)
	if out, err := exec.Command("docker", "pause", lab.container).CombinedOutput(); err != nil { // #nosec G204,G702 -- fixed tool in the runner's lab container (CWE-78)
		t.Fatalf("pause the database: %v %s", err, out)
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
		t.Fatalf("unpause the database: %v %s", err, out)
	}
	app.paused.Store(false)
	if !lab.connects(live.Username, live.Password) {
		t.Fatal("a timed-out retirement left the predecessor unable to connect")
	}
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("cycle 4 after the database resumed: %+v", final)
	}
	if lab.connects(live.Username, live.Password) || !lab.connects(successor.Username, successor.Password) {
		t.Fatal("after the resumed retirement only the successor may connect")
	}
	keepGrants()

	stopApp()
	<-appDone
	logins, failures := app.snapshot()
	if logins[oracleTwoUserAccountA] == 0 || logins[oracleTwoUserAccountB] == 0 {
		t.Fatalf("application connections per user: %v", logins)
	}
	for _, failure := range failures {
		if !strings.HasPrefix(failure, "paused: ") {
			t.Fatalf("the application failed outside the paused window: %s", failure)
		}
	}
	t.Logf("A240_ORACLE_OK application connections %v; %d failures, all while the database was paused", logins, len(failures))
}
