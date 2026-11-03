// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/store"
)

const (
	unixAccountsImage    = "trstctl-sshd-accounts-test:a240"
	unixTwoUserProvider  = "orders-host"
	unixTwoUserRole      = "host/orders"
	unixSingleRole       = "host/single"
	unixTwoUserAccountA  = "orders-svc-a"
	unixTwoUserAccountB  = "orders-svc-b"
	unixSingleAccount    = "orders-single"
	unixInitialPasswordA = "orders-svc-a-initial" // #nosec G101 -- fabricated lab password the first rotation retires (CWE-798)
)

// labSSHAccounts is a running lab host from testdata/sshd-accounts.
type labSSHAccounts struct {
	id, addr, fingerprint string
}

// startLabSSHAccounts builds and runs the lab host, installs adminPublic as
// root's key and reads the host key it generated, or skips when docker or the
// base image is not available.
func startLabSSHAccounts(t *testing.T, adminPublic []byte) labSSHAccounts {
	t.Helper()
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", unixAccountsImage, filepath.Join("testdata", "sshd-accounts")).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the lab host image did not build (offline?): %v\n%s", err, out)
	}
	created, err := exec.Command("docker", "run", "-d", "-p", "127.0.0.1::22", unixAccountsImage).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker run: %v %s", err, created)
	}
	lab := labSSHAccounts{id: strings.TrimSpace(string(created))}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", lab.id).Run() }) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if out, err := lab.shell("cat > /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys", adminPublic); err != nil {
		t.Fatalf("install the administrator key: %v %s", err, out)
	}
	if out, err := lab.shell("chpasswd", []byte(unixTwoUserAccountA+":"+unixInitialPasswordA+"\n")); err != nil {
		t.Fatalf("set the first account's password: %v %s", err, out)
	}
	a201Await(t, "the lab host's sshd", func() bool {
		out, err := a201Exec(lab.id, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			return false
		}
		info, err := sshkeys.ParsePublicKey([]byte(out))
		if err != nil {
			return false
		}
		lab.fingerprint = info.FingerprintSHA256
		_, err = a201Exec(lab.id, "sh", "-c", "pgrep -x sshd")
		return err == nil
	})
	mapped, err := exec.Command("docker", "port", lab.id, "22/tcp").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	lab.addr = strings.TrimSpace(strings.Split(string(mapped), "\n")[0])
	return lab
}

// shell runs a fixed shell line in the lab host with stdin.
func (lab labSSHAccounts) shell(line string, stdin []byte) (string, error) {
	cmd := exec.Command("docker", "exec", "-i", lab.id, "sh", "-c", line) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Stdin = strings.NewReader(string(stdin))
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (lab labSSHAccounts) logsIn(account, password string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return crypto.VerifySSHAccountPassword(ctx, crypto.SSHAccountTarget{Address: lab.addr, HostKeyFingerprint: lab.fingerprint}, account, []byte(password)) == nil
}

type unixTestCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// unixOrdersApp logs in with whatever credential it last read, every tick,
// and reports a version verified once it logged in with it.
type unixOrdersApp struct {
	lab    labSSHAccounts
	base   string
	token  string
	client *http.Client
	paused atomic.Bool
	quiet  atomic.Bool

	mu         sync.Mutex
	version    int
	credential unixTestCredential
	reported   int
	logins     map[string]int
	failures   []string
}

func (app *unixOrdersApp) run(ctx context.Context, done chan<- struct{}) {
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

func (app *unixOrdersApp) tick(ctx context.Context) {
	// A tick that starts while the host is paused counts as paused however
	// late it finishes: a login queued behind the pause can complete after
	// the flag clears (CI-L33).
	pausedAtStart := app.paused.Load()
	var read struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	readOK := false
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.base+"/api/v1/secrets/store/"+unixTwoUserRole, nil); err == nil {
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
		var next unixTestCredential
		if json.Unmarshal([]byte(read.Value), &next) == nil {
			if !app.lab.logsIn(next.Username, next.Password) {
				app.fail(fmt.Sprintf("adopt version %d", read.Version), pausedAtStart)
			} else {
				app.mu.Lock()
				app.version, app.credential = read.Version, next
				app.mu.Unlock()
				current, credential = read.Version, next
			}
		}
	}
	if current == 0 {
		return
	}
	if !app.lab.logsIn(credential.Username, credential.Password) {
		if ctx.Err() == nil {
			app.fail(fmt.Sprintf("log in with version %d", current), pausedAtStart)
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

func (app *unixOrdersApp) fail(message string, pausedAtStart bool) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if pausedAtStart || app.paused.Load() {
		message = "paused: " + message
	}
	app.failures = append(app.failures, message)
}

func (app *unixOrdersApp) report(ctx context.Context, version int) error {
	body, _ := json.Marshal(map[string]any{"consumer": "orders-app", "state": "verified",
		"secrets": []map[string]any{{"name": unixTwoUserRole, "version": version}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.base+"/api/v1/secrets/deliveries", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("unix-orders-app-verified-%d", version))
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

func (app *unixOrdersApp) snapshot() (map[string]int, []string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	logins := map[string]int{}
	for account, n := range app.logins {
		logins[account] = n
	}
	return logins, append([]string(nil), app.failures...)
}

// A240 on a real host: a two-user static rotation alternates a role between
// two local accounts in the role's group, over SSH as root with a key and the
// host key pinned, running only chpasswd. Three unattended cycles run while an
// application logs in with whatever credential it last read and reports each
// version it used; retirement sets a password nobody holds on the other
// account, whose group and home stay. A paused host times the retirement out
// and leaves the predecessor logging in until it resumes. A role bound to one
// account rotates in place, so it warns and runs only when acknowledged.
func TestServedUnixLocalAccountsRotateA240(t *testing.T) {
	adminKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := crypto.SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	lab := startLabSSHAccounts(t, adminPublic)
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	providerConfig := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: unixTwoUserProvider, Type: "unix", Addr: lab.addr, AdminUser: "root",
		PrivateKeyRef: writeServedCredentialFile(t, "unix-admin-key.pem", string(adminPEM)), HostKeyFingerprint: lab.fingerprint,
		AllowedRoles: []string{unixTwoUserRole, unixSingleRole}, RoleBindings: map[string]string{unixSingleRole: unixSingleAccount},
		RotationAccounts: map[string][]string{unixTwoUserRole: {unixTwoUserAccountA, unixTwoUserAccountB}},
		MaxTTL:           "1h", AllowStaticRotation: true,
	}
	secret.Wipe(adminPEM)
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{providerConfig}}, true); err != nil {
		t.Fatalf("the local-account provider: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{providerConfig}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.OutboxDeliveryTimeout = 3 * time.Second // the paused host waits out one delivery deadline
	})
	registerServedTenant(t, h, "A240 local accounts tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	ctx := t.Context()
	initial, _ := json.Marshal(map[string]string{"username": unixTwoUserAccountA, "password": unixInitialPasswordA})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-host-orders",
		map[string]any{"name": unixTwoUserRole, "value": string(initial)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "host-orders-schedule",
		map[string]any{"name": "host-orders", "provider": unixTwoUserProvider, "key": unixTwoUserRole, "old_ref": unixTwoUserAccountA,
			"interval_seconds": 1, "enabled": true, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"consumers": []string{"orders-app"}, "retire_after_seconds": 600})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create schedule: %d %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &schedule)
	app := &unixOrdersApp{lab: lab, base: h.ts.URL, token: seedScopedTokenSubject(t, h.store, h.tenant, "orders-app", "secrets:read"),
		client: &http.Client{Timeout: 5 * time.Second}, logins: map[string]int{}}
	appCtx, stopApp := context.WithCancel(ctx)
	appDone := make(chan struct{})
	go app.run(appCtx, appDone)
	defer func() { stopApp(); <-appDone }()
	awaitLogins := func(account string) {
		t.Helper()
		start, _ := app.snapshot()
		for deadline := time.Now().Add(60 * time.Second); ; {
			logins, failures := app.snapshot()
			if logins[account] > start[account] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the application never logged in as %s: logins=%v failures=%v", account, logins, failures)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	awaitLogins(unixTwoUserAccountA)
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
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, fmt.Sprintf("host-tick-%d", n), nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("tick %d: %d %s", n, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations?key="+unixTwoUserRole, tok, nil)
		var list struct {
			Items []staticRotationCommandView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != n {
			t.Fatalf("tick %d commands: %d %s", n, status, body)
		}
		return list.Items[0]
	}
	readCredential := func(name string) unixTestCredential {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name, tok, nil)
		var out struct {
			Value string `json:"value"`
		}
		var credential unixTestCredential
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil || json.Unmarshal([]byte(out.Value), &credential) != nil {
			t.Fatalf("read %s: %d", name, status)
		}
		return credential
	}
	keepGroups := func() {
		t.Helper()
		for _, account := range []string{unixTwoUserAccountA, unixTwoUserAccountB} {
			if groups, err := a201Exec(lab.id, "id", "-nG", account); err != nil || !strings.Contains(" "+groups+" ", " orders ") {
				t.Fatalf("%s lost its group: %v %q", account, err, groups)
			}
		}
	}

	live := unixTestCredential{Username: unixTwoUserAccountA, Password: unixInitialPasswordA}
	for _, step := range []struct {
		n       int
		account string
	}{{1, unixTwoUserAccountB}, {2, unixTwoUserAccountA}, {3, unixTwoUserAccountB}} {
		cmd := tick(step.n)
		final := await(cmd.ID, "")
		if final.Phase != store.SecretStaticRotationCompleted || final.NewRef != step.account || final.OldRef != live.Username ||
			final.VerifyMode != "authenticated" || final.ConsumerAdoption != "adopted" || final.RotationPhase != "two_phase" {
			t.Fatalf("cycle %d: %+v", step.n, final)
		}
		next := readCredential(unixTwoUserRole)
		if next.Username != step.account || !lab.logsIn(next.Username, next.Password) {
			t.Fatalf("cycle %d: the published credential for %s does not log in", step.n, step.account)
		}
		if lab.logsIn(live.Username, live.Password) {
			t.Fatalf("cycle %d: the retired password of %s still logs in", step.n, live.Username)
		}
		keepGroups()
		awaitLogins(step.account)
		live = next
	}

	// A paused host: retirement times out, the command stays verified, and
	// the predecessor logs in until the host resumes and retirement completes.
	app.quiet.Store(true)
	cmd := tick(4)
	verified := await(cmd.ID, store.SecretStaticRotationVerified)
	successor := readCredential(unixTwoUserRole)
	awaitLogins(unixTwoUserAccountA)
	app.paused.Store(true)
	if out, err := exec.Command("docker", "pause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("pause the host: %v %s", err, out)
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
			t.Fatalf("the retirement against a paused host left no retry evidence (last_error %q)", lastError)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if view := command(cmd.ID); view.Phase != store.SecretStaticRotationVerified {
		t.Fatalf("retirement passed a paused host: %+v", view)
	}
	if out, err := exec.Command("docker", "unpause", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("unpause the host: %v %s", err, out)
	}
	if !lab.logsIn(live.Username, live.Password) {
		t.Fatal("a timed-out retirement left the predecessor unable to log in")
	}
	// The paused window ends once the resumed host serves logins again.
	app.paused.Store(false)
	if final := await(cmd.ID, ""); final.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("cycle 4 after the host resumed: %+v", final)
	}
	if lab.logsIn(live.Username, live.Password) || !lab.logsIn(successor.Username, successor.Password) {
		t.Fatal("after the resumed retirement only the successor may log in")
	}
	keepGroups()

	// The single-account role changes its password in place: the preview
	// warns, an unacknowledged rotation is refused, and an acknowledged one
	// leaves only the new password working.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-host-single",
		map[string]any{"name": unixSingleRole, "value": `{"username":"orders-single","password":"unknown"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the single-account secret: %d %s", status, body)
	}
	single := map[string]any{"provider": unixTwoUserProvider, "key": unixSingleRole, "old_ref": "none"}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, single); status != http.StatusBadRequest || !strings.Contains(string(body), "rotates in a single phase") {
		t.Fatalf("an unacknowledged in-place rotation: %d %s", status, body)
	}
	single["acknowledge_single_phase"] = true
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "host-single-1", single)
	var queued struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("an acknowledged in-place rotation: %d %s", status, body)
	}
	first := await(queued.CommandID, "")
	firstCredential := readCredential(unixSingleRole)
	if first.Phase != store.SecretStaticRotationCompleted || first.RotationPhase != "single_phase" || !lab.logsIn(unixSingleAccount, firstCredential.Password) {
		t.Fatalf("the first in-place rotation: %+v", first)
	}
	single["old_ref"] = first.NewRef
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "host-single-2", single)
	if status != http.StatusOK || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("the second in-place rotation: %d %s", status, body)
	}
	if second := await(queued.CommandID, ""); second.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("the second in-place rotation: %+v", second)
	}
	if secondCredential := readCredential(unixSingleRole); !lab.logsIn(unixSingleAccount, secondCredential.Password) || lab.logsIn(unixSingleAccount, firstCredential.Password) {
		t.Fatal("an in-place rotation must leave only the new password working")
	}

	stopApp()
	<-appDone
	logins, failures := app.snapshot()
	if logins[unixTwoUserAccountA] == 0 || logins[unixTwoUserAccountB] == 0 {
		t.Fatalf("application logins per account: %v", logins)
	}
	for _, failure := range failures {
		if !strings.HasPrefix(failure, "paused: ") {
			t.Fatalf("the application failed outside the paused window: %s", failure)
		}
	}
	t.Logf("application logins %v; %d failures, all while the host was paused", logins, len(failures))
}
