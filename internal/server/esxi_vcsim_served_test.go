// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
)

// A271-O1: the ESXi provider against stock vcsim, the vSphere API simulator
// from VMware's govmomi, in ESX mode (vcsim -esx), built from a pinned govmomi
// release (CI: the a271 lab job). The in-repo stand-in proves what a password
// change does to a host; vcsim proves the wire as VMware's own vim25 encoder
// writes it: the provider's SOAP envelopes, the ESX managed-object references
// (ha-sessionmgr, ha-localacctmgr, ha-user-directory, ha-authmgr), the session
// cookie, the fault shape, and the discovery answers.
//
// Stock vcsim's UpdateUser accepts a change without storing a password, and its
// Login accepts either any non-empty sign-in or exactly one configured account.
// So a new password's effect cannot be proven here: the stand-in proves it, and
// a live host is the Track B row.

// stockVcsim is one running vcsim: its https://host:port and the certificate
// the provider pins.
type stockVcsim struct {
	endpoint string
	caPEM    []byte
}

// startStockVcsim runs stock vcsim on a loopback port with a TLS identity the
// test pins. With admin set, vcsim accepts that one sign-in (its password read
// from passwordFile) and refuses every other; without it, vcsim accepts any
// non-empty user and password.
func startStockVcsim(t *testing.T, admin, passwordFile string) stockVcsim {
	t.Helper()
	path, err := exec.LookPath("vcsim")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_VCSIM") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_VCSIM is set but vcsim is not on PATH: %v", err)
		}
		t.Skip("vcsim not on PATH; set TRSTCTL_REQUIRE_VCSIM=1 in CI to make the stock vSphere API simulator mandatory")
	}
	identity := filepath.Join(t.TempDir(), "vcsim-tls.pem")
	cert, err := mtls.LoadOrCreateSelfSignedServerCert(identity, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-esx", "-l", "127.0.0.1:0", "-tlscert", identity, "-tlskey", identity, "-stdinexit"}
	if admin != "" {
		args = append(args, "-username", admin, "-password", passwordFile)
	}
	cmd := exec.Command(path, args...) // #nosec G204 -- the stock simulator on PATH with fixed arguments (CWE-78)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr lockedTail
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vcsim: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close() // -stdinexit: vcsim exits when its stdin closes
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	// vcsim prints two lines; a line nobody waits for is dropped rather than
	// blocking the simulator's output.
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
		close(lines)
	}()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("vcsim exited before it listened: %s", stderr.String())
			}
			rest, found := strings.CutPrefix(line, "export GOVC_URL=")
			if !found {
				continue
			}
			raw, _, _ := strings.Cut(rest, " ")
			// The URL carries the configured sign-in; only its host is read,
			// and it is never logged.
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				t.Fatal("vcsim printed a URL that does not parse")
			}
			return stockVcsim{endpoint: "https://" + u.Host, caPEM: cert.TrustPEM}
		case <-deadline:
			t.Fatalf("vcsim did not listen within 30s: %s", stderr.String())
		}
	}
}

// lockedTail keeps the end of a process's stderr for a failure message.
type lockedTail struct {
	mu  sync.Mutex
	buf []byte
}

func (l *lockedTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	if len(l.buf) > 4096 {
		l.buf = l.buf[len(l.buf)-4096:]
	}
	return len(p), nil
}

func (l *lockedTail) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.buf)
}

// soap sends one vim25 operation to the simulator, independently of the
// provider's own client.
func (v stockVcsim) soap(t *testing.T, client *http.Client, cookie, operation string) (int, []*http.Cookie, string) {
	t.Helper()
	body := `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body>` +
		operation + `</soapenv:Body></soapenv:Envelope>`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, v.endpoint+"/sdk", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"urn:vim25/7.0"`)
	if cookie != "" {
		req.Header.Set("Cookie", "vmware_soap_session="+cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("vcsim did not answer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Cookies(), string(raw)
}

// openSessions signs in to the simulator as user, counts the sessions it
// holds besides that one, and signs out again.
func (v stockVcsim) openSessions(t *testing.T, user, password string) int {
	t.Helper()
	transport, err := mtls.HTTPTransport(v.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	status, cookies, _ := v.soap(t, client, "", `<vim25:Login><vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this><vim25:userName>`+
		user+`</vim25:userName><vim25:password>`+password+`</vim25:password></vim25:Login>`)
	var cookie string
	for _, c := range cookies {
		if c.Name == "vmware_soap_session" {
			cookie = c.Value
		}
	}
	if status != http.StatusOK || cookie == "" {
		t.Fatalf("sign in to count sessions: %d", status)
	}
	status, _, raw := v.soap(t, client, cookie, `<vim25:RetrievePropertiesEx><vim25:_this type="PropertyCollector">ha-property-collector</vim25:_this>`+
		`<vim25:specSet><vim25:propSet><vim25:type>SessionManager</vim25:type><vim25:pathSet>sessionList</vim25:pathSet></vim25:propSet>`+
		`<vim25:objectSet><vim25:obj type="SessionManager">ha-sessionmgr</vim25:obj></vim25:objectSet></vim25:specSet><vim25:options></vim25:options></vim25:RetrievePropertiesEx>`)
	if status != http.StatusOK {
		t.Fatalf("read vcsim's session list: %d %s", status, raw)
	}
	sessions := strings.Count(raw, "<UserSession>")
	v.soap(t, client, cookie, `<vim25:Logout><vim25:_this type="SessionManager">ha-sessionmgr</vim25:_this></vim25:Logout>`)
	return sessions - 1
}

func writeVcsimPassword(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vcsim-admin-password")
	if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// vcsimProviderHarness serves an ESXi provider pointed at the simulator.
func vcsimProviderHarness(t *testing.T, sim stockVcsim, adminPassword string) (*servedHarness, string) {
	t.Helper()
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "vcsim-esx", Type: "esxi", Endpoint: sim.endpoint,
		TLSCARef: writeServedCredentialFile(t, "a271o1-vcsim-ca", string(sim.caPEM)), AllowPrivate: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		AdminUser: "root", PasswordRef: writeServedCredentialFile(t, "a271o1-vcsim-admin", adminPassword),
		AllowedRoles: []string{"esx/ops"}, RoleBindings: map[string]string{"esx/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "a271o1-vcsim-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")
	return sh, tok
}

// vcsimDiscovery saves the provider as a discovery source and runs it once.
func vcsimDiscovery(t *testing.T, sh *servedHarness, tok, key string) a260Run {
	t.Helper()
	if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/vcsim-esx", tok, key+"-source",
		map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("save the discovery source: %d %s", status, body)
	}
	status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/vcsim-esx/runs", tok, key+"-scan", nil)
	var queued a260Run
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("scan: %d %s", status, body)
	}
	return awaitQueuedDiscoveryProofA267(t, sh, tok, queued.ID)
}

// Against stock vcsim that accepts any sign-in: the rotation's whole SOAP
// exchange (administrator Login, UpdateUser, Logout, then Login and Logout as
// the account) completes and publishes the new credential; discovery reads
// vcsim's ESX local users with the roles its permissions grant, from vcsim's
// own vim25 answers; every session the provider opened is logged out; and no
// password reaches an event.
func TestServedESXiProviderAgainstStockVcsimA271O1(t *testing.T) {
	sim := startStockVcsim(t, "", "")
	sh, tok := vcsimProviderHarness(t, sim, "vcsim-admin-password-1")
	ctx := context.Background()
	seed, _ := json.Marshal(map[string]string{"username": "ops", "password": "vcsim-ops-password-1"}) // #nosec G101 -- fabricated test-only password for the simulator (CWE-798)
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", tok, "a271o1-seed",
		map[string]any{"name": "esx/ops", "value": string(seed)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, "a271o1-rotate",
		map[string]any{"provider": "vcsim-esx", "key": "esx/ops", "old_ref": "ops", "acknowledge_single_phase": true})
	var queued struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
		t.Fatalf("queue the rotation: %d %s", status, body)
	}
	var view staticRotationCommandView
	for deadline := time.Now().Add(90 * time.Second); ; {
		a270StaticRotationDue(t, sh)
		sh.srv.dispatchOnce(ctx)
		status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("read the rotation: %d %s", status, body)
		}
		if view.Terminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rotation did not finish: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if view.Phase != "completed" || view.RotationPhase != "single_phase" || view.VerifyMode != "authenticated" || !view.CredentialValid {
		t.Fatalf("the rotation against vcsim: %+v", view)
	}
	status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/esx/ops", tok, nil)
	var stored struct {
		Value string `json:"value"`
	}
	var credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &stored) != nil || json.Unmarshal([]byte(stored.Value), &credential) != nil {
		t.Fatalf("read the vault: %d", status)
	}
	if credential.Username != "ops" || credential.Password == "" || credential.Password == "vcsim-ops-password-1" {
		t.Fatal("the rotation did not publish a new password for ops")
	}

	if run := vcsimDiscovery(t, sh, tok, "a271o1"); run.Status != "completed" || run.Accounts != 2 {
		t.Fatalf("the scan of vcsim: %+v", run)
	}
	status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=vcsim-esx", tok, nil)
	var page struct {
		Items []a260Account `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("list accounts: %d %s", status, body)
	}
	found := map[string]string{}
	for _, a := range page.Items {
		found[a.Name] = strings.Join(a.Privileges, " ")
	}
	// vcsim's ESX model holds the local users root and admin, each granted the
	// Admin role on the root folder; the root group's grant is not a user's.
	if len(found) != 2 || found["root"] != "role Admin" || found["admin"] != "role Admin" {
		t.Fatalf("discovered %v from vcsim, want root and admin with role Admin", found)
	}
	if open := sim.openSessions(t, "a271o1-checker", "a271o1-checker-password"); open != 0 {
		t.Fatalf("%d vcsim sessions were left open", open)
	}
	leaks := [][]byte{[]byte("vcsim-admin-password-1"), []byte("vcsim-ops-password-1"), []byte(credential.Password)}
	if err := sh.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range leaks {
			if event.TenantID == sh.tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("a host password reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Against stock vcsim configured with one administrator sign-in: a scan by a
// provider holding the wrong administrator password fails as rejected and
// finds nothing, and the provider reads the refusal as the host's InvalidLogin
// fault, decoded from vim25's own fault encoding; with the right password the
// same scan completes. No session is left open either way.
func TestServedESXiProviderNamesStockVcsimsLoginFaultA271O1(t *testing.T) {
	const adminPassword = "vcsim-admin-password-2" // #nosec G101 -- fabricated test-only password for the simulator (CWE-798)
	sim := startStockVcsim(t, "root", writeVcsimPassword(t, adminPassword))
	sh, tok := vcsimProviderHarness(t, sim, "not-the-admin-password")
	run := vcsimDiscovery(t, sh, tok, "a271o1-wrong")
	if run.Status != "failed" || run.Failure != "rejected" || run.Accounts != 0 || len(run.Changes) != 0 {
		t.Fatalf("a scan with the wrong administrator password: %+v, want failed as rejected with nothing found", run)
	}
	transport, err := mtls.HTTPTransport(sim.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := dynsecret.NewESXiBackend(dynsecret.ESXiConfig{Endpoint: sim.endpoint, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
		AdminUser: "root", AdminPassword: []byte("not-the-admin-password"), RoleAccounts: map[string]string{"esx/ops": "ops"}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if _, err := backend.DiscoverPrivilegedAccounts(t.Context()); err == nil || !strings.Contains(err.Error(), "refused root's sign-in (InvalidLogin)") {
		t.Fatalf("the provider's reading of vcsim's refusal = %v, want the InvalidLogin fault named", err)
	}
	if open := sim.openSessions(t, "root", adminPassword); open != 0 {
		t.Fatalf("%d vcsim sessions were left open", open)
	}

	right, rightTok := vcsimProviderHarness(t, sim, adminPassword)
	if run := vcsimDiscovery(t, right, rightTok, "a271o1-right"); run.Status != "completed" || run.Accounts != 2 {
		t.Fatalf("the scan with the right administrator password: %+v, want completed with vcsim's two users", run)
	}
	if open := sim.openSessions(t, "root", adminPassword); open != 0 {
		t.Fatalf("%d vcsim sessions were left open", open)
	}
}
