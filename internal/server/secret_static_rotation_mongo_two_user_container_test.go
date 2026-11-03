// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

const (
	mongoTwoUserImage    = "mongo@sha256:04582c3a144d088f841c446abfc19f79adcefa8bd00ad4a7fb18e27b9585c5d6" // the census's pinned MongoDB 7.0
	mongoTwoUserProvider = "orders-mongo"
	mongoTwoUserRole     = "mongo/orders"
	mongoTwoUserAccountA = "orders_app_a"
	mongoTwoUserAccountB = "orders_app_b"
)

// labMongo is a running MongoDB with authorization on.
type labMongo struct {
	id, addr, rootPassword string
}

func startLabMongo(t *testing.T) labMongo {
	t.Helper()
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", mongoTwoUserImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", mongoTwoUserImage, err, out)
	}
	random, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	lab := labMongo{rootPassword: hex.EncodeToString(random)}
	created, err := exec.Command("docker", "run", "-d", "-p", "127.0.0.1::27017", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD="+lab.rootPassword, mongoTwoUserImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, created)
	}
	lab.id = strings.TrimSpace(string(created))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", lab.id).Run() }) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	a201Await(t, "MongoDB with authorization", func() bool {
		out, err := lab.eval("db.adminCommand({ping:1}).ok")
		return err == nil && strings.TrimSpace(out) == "1"
	})
	mapped, err := exec.Command("docker", "port", lab.id, "27017/tcp").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	lab.addr = strings.TrimSpace(strings.Split(string(mapped), "\n")[0])
	return lab
}

// eval runs a mongosh expression as root.
func (lab labMongo) eval(expression string) (string, error) {
	return a201Exec(lab.id, "mongosh", "--quiet", "--username", "root", "--password", lab.rootPassword,
		"--authenticationDatabase", "admin", "--eval", expression)
}

func (lab labMongo) uri(user, password string) string {
	return (&url.URL{Scheme: "mongodb", User: url.UserPassword(user, password), Host: lab.addr, Path: "/orders",
		RawQuery: "authSource=orders&directConnection=true"}).String()
}

func (lab labMongo) logsIn(uri string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return dynsecret.VerifyMongoCredential(ctx, []byte(uri)) == nil
}

// mongoOrdersApp connects with whatever credential it last read, every tick,
// and reports a version verified once it connected with it.
type mongoOrdersApp struct {
	lab    labMongo
	base   string
	token  string
	client *http.Client
	paused atomic.Bool
	quiet  atomic.Bool

	mu       sync.Mutex
	version  int
	uri      string
	reported int
	logins   map[string]int
	failures []string
}

func (app *mongoOrdersApp) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(100 * time.Millisecond)
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

func (app *mongoOrdersApp) tick(ctx context.Context) {
	var read struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	readOK := false
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.base+"/api/v1/secrets/store/"+mongoTwoUserRole, nil); err == nil {
		req.Header.Set("Authorization", "Bearer "+app.token)
		if resp, err := app.client.Do(req); err == nil {
			readOK = resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&read) == nil
			_ = resp.Body.Close()
		}
	}
	app.mu.Lock()
	current, uri := app.version, app.uri
	app.mu.Unlock()
	if readOK && read.Version != current {
		if !app.lab.logsIn(read.Value) {
			app.fail(fmt.Sprintf("adopt version %d", read.Version))
		} else {
			app.mu.Lock()
			app.version, app.uri = read.Version, read.Value
			app.mu.Unlock()
			current, uri = read.Version, read.Value
		}
	}
	if current == 0 {
		return
	}
	if !app.lab.logsIn(uri) {
		if ctx.Err() == nil {
			app.fail(fmt.Sprintf("connect with version %d", current))
		}
		return
	}
	user := ""
	if parsed, err := url.Parse(uri); err == nil {
		user = parsed.User.Username()
	}
	app.mu.Lock()
	app.logins[user]++
	reported := app.reported
	app.mu.Unlock()
	if current != reported && !app.quiet.Load() && app.report(ctx, current) == nil {
		app.mu.Lock()
		app.reported = current
		app.mu.Unlock()
	}
}

func (app *mongoOrdersApp) fail(message string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.paused.Load() {
		message = "paused: " + message
	}
	app.failures = append(app.failures, message)
}

func (app *mongoOrdersApp) report(ctx context.Context, version int) error {
	body, _ := json.Marshal(map[string]any{"consumer": "orders-app", "state": "verified",
		"secrets": []map[string]any{{"name": mongoTwoUserRole, "version": version}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.base+"/api/v1/secrets/deliveries", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("mongo-orders-app-verified-%d", version))
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

func (app *mongoOrdersApp) snapshot() (map[string]int, []string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	logins := map[string]int{}
	for user, n := range app.logins {
		logins[user] = n
	}
	return logins, append([]string(nil), app.failures...)
}

// A240 on a real MongoDB: a two-user static rotation alternates a role
// between two existing database users that hold its roles. Three unattended
// scheduled cycles run while an application connects with whatever credential
// it last read and reports each version it used; each cycle sets a new
// password on the user the application is not using, proves it by connecting,
// and, once the application reports, retires the other by setting a password
// nobody holds. Both users keep their roles and nothing is created or
// dropped. A paused database times the retirement out and leaves the
// predecessor connecting until it resumes.
func TestServedMongoTwoUserStaticRotationKeepsRolesA240(t *testing.T) {
	lab := startLabMongo(t)
	const initialPassword = "orders-app-a-initial" // #nosec G101 -- fabricated lab password the first rotation retires (CWE-798)
	for _, statement := range []string{
		`db.getSiblingDB("orders").createUser({user: "` + mongoTwoUserAccountA + `", pwd: "` + initialPassword + `", roles: [{role: "readWrite", db: "orders"}]})`,
		`db.getSiblingDB("orders").createUser({user: "` + mongoTwoUserAccountB + `", pwd: "not-yet-staged-0000", roles: [{role: "readWrite", db: "orders"}]})`,
	} {
		if out, err := lab.eval(statement); err != nil {
			t.Fatalf("provision the pair: %v %s", err, out)
		}
	}
	adminURI := (&url.URL{Scheme: "mongodb", User: url.UserPassword("root", lab.rootPassword), Host: lab.addr, Path: "/orders",
		RawQuery: "authSource=admin&directConnection=true"}).String()
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: mongoTwoUserProvider, Type: "mongodb",
		AdminDSNRef: writeServedCredentialFile(t, "mongo-two-user-admin", adminURI), Database: "orders",
		AllowedRoles: []string{mongoTwoUserRole}, MaxTTL: "1h", UsernamePrefix: "trstctl", AllowStaticRotation: true,
		RotationAccounts: map[string][]string{mongoTwoUserRole: {mongoTwoUserAccountA, mongoTwoUserAccountB}},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig}}, true); err != nil {
		t.Fatalf("two-user MongoDB provider: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{providerConfig}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.OutboxDeliveryTimeout = 3 * time.Second // the paused database waits out one delivery deadline
	})
	registerServedTenant(t, h, "A240 MongoDB two-user tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-mongo-orders",
		map[string]any{"name": mongoTwoUserRole, "value": lab.uri(mongoTwoUserAccountA, initialPassword)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "mongo-orders-schedule",
		map[string]any{"name": "mongo-orders", "provider": mongoTwoUserProvider, "key": mongoTwoUserRole, "old_ref": mongoTwoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"consumers": []string{"orders-app"}, "retire_after_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)
	app := &mongoOrdersApp{lab: lab, base: h.ts.URL, token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
		client: &http.Client{Timeout: 5 * time.Second}, logins: map[string]int{}}
	appCtx, stopApp := context.WithCancel(ctx)
	appDone := make(chan struct{})
	go app.run(appCtx, appDone)
	defer func() { stopApp(); <-appDone }()
	awaitLogins := func(user string) {
		t.Helper()
		start, _ := app.snapshot()
		for deadline := time.Now().Add(60 * time.Second); ; {
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
	awaitLogins(mongoTwoUserAccountA)
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
		for deadline := time.Now().Add(120 * time.Second); ; {
			h.srv.dispatchOnce(ctx)
			view := command(id)
			if view.Phase == phase || (phase == "" && view.Terminal) {
				return view
			}
			if view.Terminal || time.Now().After(deadline) {
				t.Fatalf("command %s: want phase %q, have %+v", id, phase, view)
			}
			time.Sleep(50 * time.Millisecond)
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
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("mongo-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+url.QueryEscape(mongoTwoUserRole), tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	readURI := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+mongoTwoUserRole, tok, nil)
		var out struct {
			Value string `json:"value"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read the secret: %d", status)
		}
		return out.Value
	}
	keepRoles := func() {
		t.Helper()
		out, err := lab.eval(`JSON.stringify(db.getSiblingDB("orders").getUsers().users.map(u => [u.user, u.roles.map(r => r.role + "@" + r.db).join(",")]))`)
		if err != nil || !strings.Contains(out, `["`+mongoTwoUserAccountA+`","readWrite@orders"]`) || !strings.Contains(out, `["`+mongoTwoUserAccountB+`","readWrite@orders"]`) ||
			strings.Count(out, `["`) != 2 {
			t.Fatalf("the database's users after a rotation: %v %s", err, out)
		}
	}

	live := lab.uri(mongoTwoUserAccountA, initialPassword)
	liveUser := mongoTwoUserAccountA
	for _, step := range []struct {
		n    int
		user string
	}{{1, mongoTwoUserAccountB}, {2, mongoTwoUserAccountA}, {3, mongoTwoUserAccountB}} {
		cmd := tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.NewRef != step.user || final.OldRef != liveUser ||
			final.VerifyMode != "connected" || final.ConsumerAdoption != "adopted" {
			t.Fatalf("cycle %d: %+v", step.n, final)
		}
		next := readURI()
		if !lab.logsIn(next) || !strings.Contains(next, "//"+step.user+":") {
			t.Fatalf("cycle %d: the published credential for %s does not connect", step.n, step.user)
		}
		if lab.logsIn(live) {
			t.Fatalf("cycle %d: the retired password of %s still connects", step.n, liveUser)
		}
		keepRoles()
		awaitLogins(step.user)
		live, liveUser = next, step.user
	}

	// A paused database: retirement times out, the command stays verified, and
	// the predecessor connects until the database resumes and retirement
	// completes.
	app.quiet.Store(true)
	cmd := tick(4)
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	successor := readURI()
	awaitLogins(mongoTwoUserAccountA)
	app.paused.Store(true)
	if out, err := exec.Command("docker", "pause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("pause the database: %v %s", err, out)
	}
	if err := app.report(ctx, verified.ResultVersion); err != nil {
		t.Fatalf("report the successor: %v", err)
	}
	app.mu.Lock()
	app.reported = verified.ResultVersion
	app.mu.Unlock()
	app.quiet.Store(false)
	for deadline := time.Now().Add(60 * time.Second); ; {
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
	if out, err := exec.Command("docker", "unpause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("unpause the database: %v %s", err, out)
	}
	app.paused.Store(false)
	if !lab.logsIn(live) {
		t.Fatal("a timed-out retirement left the predecessor unable to connect")
	}
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("cycle 4 after the database resumed: %+v", final)
	}
	if lab.logsIn(live) || !lab.logsIn(successor) {
		t.Fatal("after the resumed retirement only the successor may connect")
	}
	keepRoles()

	stopApp()
	<-appDone
	logins, failures := app.snapshot()
	if logins[mongoTwoUserAccountA] == 0 || logins[mongoTwoUserAccountB] == 0 {
		t.Fatalf("application connections per user: %v", logins)
	}
	for _, failure := range failures {
		if !strings.HasPrefix(failure, "paused: ") {
			t.Fatalf("the application failed outside the paused window: %s", failure)
		}
	}
	t.Logf("application connections %v; %d failures, all while the database was paused", logins, len(failures))
}
