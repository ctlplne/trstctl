// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

const (
	ldapTwoUserProvider = "directory-services"
	ldapTwoUserRole     = "directory/orders"
	ldapTwoUserGroup    = "cn=orders-readers,ou=groups,dc=lab,dc=test"
	ldapTwoUserAccountA = "uid=orders-svc-a,ou=services,dc=lab,dc=test"
	ldapTwoUserAccountB = "uid=orders-svc-b,ou=services,dc=lab,dc=test"
)

// ldapOrdersApp binds and reads its group with whatever credential it last
// read, every tick, and reports a version verified once it bound with it.
type ldapOrdersApp struct {
	lab    labOpenLDAP
	base   string
	token  string
	client *http.Client
	paused atomic.Bool // the directory is paused on purpose; failures then are expected
	quiet  atomic.Bool // the application switches but does not report

	mu         sync.Mutex
	version    int
	credential ldapTestCredential
	reported   int
	binds      map[string]int
	failures   []string
	readErrors int
}

type ldapTestCredential struct {
	BindDN   string `json:"bind_dn"`
	Password string `json:"password"`
}

// bind binds as credential over verified LDAPS and reads its own entry, as
// the application would (the directory's ACL lets an entry read itself; group
// membership is checked as the administrator).
func (lab labOpenLDAP) bind(credential ldapTestCredential) error {
	ctx, cancel := contextLDAP()
	defer cancel()
	raw, err := mtls.DialVerifiedTCP(ctx, lab.addr, "ldap.lab.test", lab.trustPEM)
	if err != nil {
		return err
	}
	conn := ldap.NewConn(raw, true)
	conn.Start()
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(5 * time.Second)
	if err := conn.Bind(credential.BindDN, credential.Password); err != nil {
		return err
	}
	result, err := conn.Search(ldap.NewSearchRequest(credential.BindDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 5, false,
		"(objectClass=inetOrgPerson)", []string{"uid"}, nil))
	if err != nil {
		return err
	}
	if len(result.Entries) != 1 {
		return fmt.Errorf("%s cannot read its own entry", credential.BindDN)
	}
	return nil
}

func (app *ldapOrdersApp) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(50 * time.Millisecond)
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

func (app *ldapOrdersApp) tick(ctx context.Context) {
	value, version, err := app.read(ctx)
	app.mu.Lock()
	current, credential := app.version, app.credential
	app.mu.Unlock()
	if err != nil && ctx.Err() == nil {
		app.mu.Lock()
		app.readErrors++
		app.mu.Unlock()
	}
	if err == nil && version != current {
		var next ldapTestCredential
		if json.Unmarshal([]byte(value), &next) == nil {
			if bindErr := app.lab.bind(next); bindErr != nil {
				app.fail(fmt.Sprintf("adopt version %d: %v", version, bindErr))
			} else {
				app.mu.Lock()
				app.version, app.credential = version, next
				app.mu.Unlock()
				current, credential = version, next
			}
		}
	}
	if current == 0 {
		return
	}
	if err := app.lab.bind(credential); err != nil {
		if ctx.Err() == nil {
			app.fail(fmt.Sprintf("bind with version %d: %v", current, err))
		}
		return
	}
	app.mu.Lock()
	app.binds[credential.BindDN]++
	reported := app.reported
	app.mu.Unlock()
	if current != reported && !app.quiet.Load() && app.report(ctx, current) == nil {
		app.mu.Lock()
		app.reported = current
		app.mu.Unlock()
	}
}

func (app *ldapOrdersApp) fail(message string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.paused.Load() {
		message = "paused: " + message
	}
	app.failures = append(app.failures, message)
}

func (app *ldapOrdersApp) read(ctx context.Context) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.base+"/api/v1/secrets/store/"+ldapTwoUserRole, nil)
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

func (app *ldapOrdersApp) report(ctx context.Context, version int) error {
	body, err := json.Marshal(map[string]any{"consumer": "orders-app", "state": "verified",
		"secrets": []map[string]any{{"name": ldapTwoUserRole, "version": version}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.base+"/api/v1/secrets/deliveries", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("ldap-orders-app-verified-%d", version))
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

func (app *ldapOrdersApp) snapshot() (binds map[string]int, failures []string, readErrors int) {
	app.mu.Lock()
	defer app.mu.Unlock()
	binds = map[string]int{}
	for dn, n := range app.binds {
		binds[dn] = n
	}
	return binds, append([]string(nil), app.failures...), app.readErrors
}

// A240 on a real directory: a two-user static rotation alternates a role
// between two service entries the directory's owner placed in the role's
// group. Scheduled cycles run against OpenLDAP while an application binds and
// reads its group with whatever credential it last read: each cycle sets a new
// password on the entry the application is not using, publishes it, proves it
// by binding, and, once the application reports the new version, retires the
// other by setting a password nobody holds; both entries stay in the group and
// nothing else is created. A directory paused during retirement times the
// retirement out and leaves the predecessor binding until it resumes.
func TestServedLDAPTwoUserStaticRotationKeepsGroupsA240(t *testing.T) {
	lab := startLabOpenLDAP(t)
	lab.seed(t, `dn: ou=services,dc=lab,dc=test
objectClass: organizationalUnit
ou: services

dn: ou=groups,dc=lab,dc=test
objectClass: organizationalUnit
ou: groups

dn: `+ldapTwoUserAccountA+`
objectClass: inetOrgPerson
uid: orders-svc-a
cn: orders-svc-a
sn: orders-svc-a

dn: `+ldapTwoUserAccountB+`
objectClass: inetOrgPerson
uid: orders-svc-b
cn: orders-svc-b
sn: orders-svc-b

dn: `+ldapTwoUserGroup+`
objectClass: groupOfNames
cn: orders-readers
member: `+ldapTwoUserAccountA+`
member: `+ldapTwoUserAccountB+`
`)
	const initialPassword = "orders-svc-a-initial" // #nosec G101 -- fabricated lab password the first rotation retires (CWE-798)
	if out, err := lab.tool("ldappasswd", "-D", lab.admin, "-w", lab.adminPassword, "-s", initialPassword, ldapTwoUserAccountA); err != nil {
		t.Fatalf("set the first entry's password: %v %s", err, out)
	}
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: ldapTwoUserProvider, Type: "ldap", Addr: lab.addr,
		TLSServerName: "ldap.lab.test", TLSCARef: writeServedCredentialFile(t, "ldap-two-user-ca.pem", string(lab.trustPEM)), BindDN: lab.admin,
		PasswordRef: writeServedCredentialFile(t, "ldap-two-user-admin", lab.adminPassword), UsersDN: "ou=services," + lab.base,
		AllowedRoles: []string{ldapTwoUserRole}, RoleBindings: map[string]string{ldapTwoUserRole: ldapTwoUserGroup},
		MaxTTL: "1h", AllowStaticRotation: true,
		RotationAccounts: map[string][]string{ldapTwoUserRole: {ldapTwoUserAccountA, ldapTwoUserAccountB}},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig}}, true); err != nil {
		t.Fatalf("two-user directory provider: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{providerConfig}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		// The paused directory waits out one delivery deadline.
		d.OutboxDeliveryTimeout = 3 * time.Second
	})
	registerServedTenant(t, h, "A240 directory two-user tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()
	initial, _ := json.Marshal(map[string]string{"url": "ldaps://" + lab.addr, "bind_dn": ldapTwoUserAccountA, "password": initialPassword})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-directory-orders",
		map[string]any{"name": ldapTwoUserRole, "value": string(initial)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "directory-orders-schedule",
		map[string]any{"name": "directory-orders", "provider": ldapTwoUserProvider, "key": ldapTwoUserRole, "old_ref": ldapTwoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"consumers": []string{"orders-app"}, "retire_after_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)

	app := &ldapOrdersApp{lab: lab, base: h.ts.URL, token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
		client: &http.Client{Timeout: 5 * time.Second}, binds: map[string]int{}}
	appCtx, stopApp := context.WithCancel(ctx)
	appDone := make(chan struct{})
	go app.run(appCtx, appDone)
	defer func() { stopApp(); <-appDone }()
	awaitBinds := func(account string) {
		t.Helper()
		start, _, _ := app.snapshot()
		for deadline := time.Now().Add(30 * time.Second); ; {
			binds, failures, readErrors := app.snapshot()
			if binds[account] > start[account] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the application never bound as %s: binds=%v failures=%v, %d failed reads", account, binds, failures, readErrors)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	awaitBinds(ldapTwoUserAccountA)
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
		for deadline := time.Now().Add(90 * time.Second); ; {
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
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("directory-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+ldapTwoUserRole, tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	readCredential := func() ldapTestCredential {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+ldapTwoUserRole, tok, nil)
		var out struct {
			Value string `json:"value"`
		}
		var credential ldapTestCredential
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil || json.Unmarshal([]byte(out.Value), &credential) != nil {
			t.Fatalf("read the secret: %d", status)
		}
		return credential
	}
	inGroup := func() {
		t.Helper()
		members, err := lab.tool("ldapsearch", "-D", lab.admin, "-w", lab.adminPassword, "-b", ldapTwoUserGroup, "-s", "base", "-LLL", "member")
		if err != nil || !strings.Contains(members, ldapTwoUserAccountA) || !strings.Contains(members, ldapTwoUserAccountB) {
			t.Fatalf("a rotation changed the group: %v\n%s", err, members)
		}
	}

	// Three unattended cycles: A -> B -> A -> B.
	live := ldapTestCredential{BindDN: ldapTwoUserAccountA, Password: initialPassword}
	for _, step := range []struct {
		n       int
		account string
	}{{1, ldapTwoUserAccountB}, {2, ldapTwoUserAccountA}, {3, ldapTwoUserAccountB}} {
		cmd := tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.NewRef != step.account || final.OldRef != live.BindDN ||
			final.VerifyMode != "authenticated" || final.ConsumerAdoption != "adopted" {
			t.Fatalf("cycle %d: %+v", step.n, final)
		}
		next := readCredential()
		if next.BindDN != step.account || lab.bind(next) != nil {
			t.Fatalf("cycle %d: the published credential for %s does not bind", step.n, step.account)
		}
		if lab.bind(live) == nil {
			t.Fatalf("cycle %d: the retired credential for %s still binds", step.n, live.BindDN)
		}
		inGroup()
		awaitBinds(step.account)
		live = next
	}

	// A paused directory: retirement cannot reach it and times out; the
	// command stays verified, and once the directory resumes the predecessor
	// still binds until retirement completes.
	app.quiet.Store(true)
	cmd := tick(4)
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	successor := readCredential()
	awaitBinds(ldapTwoUserAccountA)
	app.paused.Store(true)
	if out, err := exec.Command("docker", "pause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("pause the directory: %v %s", err, out)
	}
	// The application's report of the version it switched to arrives while the
	// directory is paused, so retirement runs into the pause.
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
			t.Fatalf("the retirement against a paused directory left no retry evidence (last_error %q)", lastError)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if view := command(cmd.ID); view.Phase != store.SecretStaticRotationVerified {
		t.Fatalf("retirement passed a paused directory: %+v", view)
	}
	if out, err := exec.Command("docker", "unpause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("unpause the directory: %v %s", err, out)
	}
	app.paused.Store(false)
	if lab.bind(live) != nil {
		t.Fatal("a timed-out retirement left the predecessor unable to bind")
	}
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted || final.NewRef != verified.NewRef {
		t.Fatalf("cycle 4 after the directory resumed: %+v", final)
	}
	if lab.bind(live) == nil || lab.bind(successor) != nil {
		t.Fatal("after the resumed retirement only the successor may bind")
	}
	inGroup()

	// Nothing outside the pair was created, and the application only failed
	// while the directory was paused.
	entries, err := lab.tool("ldapsearch", "-D", lab.admin, "-w", lab.adminPassword, "-b", "ou=services,"+lab.base, "-s", "one", "-LLL", "dn")
	if err != nil || strings.Count(entries, "dn: ") != 2 {
		t.Fatalf("service entries after the rotations: %v\n%s", err, entries)
	}
	stopApp()
	<-appDone
	binds, failures, _ := app.snapshot()
	if binds[ldapTwoUserAccountA] == 0 || binds[ldapTwoUserAccountB] == 0 {
		t.Fatalf("application binds per entry: %v", binds)
	}
	for _, failure := range failures {
		if !strings.HasPrefix(failure, "paused: ") {
			t.Fatalf("the application failed outside the paused window: %s", failure)
		}
	}
	t.Logf("application binds %v; %d failures, all while the directory was paused", binds, len(failures))
}
