// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

// A271-O2: the redfish provider against DMTF's stock Redfish Mockup Server
// (redfishMockupServer.py from a pinned release, CI: the a271 lab job)
// serving DMTF's public-rackmount1 mockup over TLS. The in-repo stand-in
// proves what a password change does to a controller; the mockup proves the
// provider reads DMTF's own resource shapes: the session answer, the account
// collection and its ManagerAccount members, the PATCH and the session
// DELETE. The mockup authenticates nothing and stores a PATCHed password as
// given, so a new password's effect is not provable here: the stand-in proves
// it, and a real controller is the Track B row.

// redfishMockup is one running mockup server: its https://host:port and a
// client that pins it.
type redfishMockup struct {
	endpoint string
	caPEM    []byte
	client   *http.Client
}

// startRedfishMockup runs the mockup server named by TRSTCTL_REDFISH_MOCKUP
// (its checkout, holding redfishMockupServer.py and public-rackmount1) with
// TRSTCTL_REDFISH_MOCKUP_PYTHON (python3 by default) on a loopback port, with
// a TLS identity the test pins.
func startRedfishMockup(t *testing.T) redfishMockup {
	t.Helper()
	dir := os.Getenv("TRSTCTL_REDFISH_MOCKUP")
	if dir == "" {
		if os.Getenv("TRSTCTL_REQUIRE_REDFISH_MOCKUP") == "1" {
			t.Fatal("TRSTCTL_REQUIRE_REDFISH_MOCKUP is set but TRSTCTL_REDFISH_MOCKUP does not name the mockup server's checkout")
		}
		t.Skip("TRSTCTL_REDFISH_MOCKUP not set; set it to DMTF's Redfish Mockup Server checkout, and TRSTCTL_REQUIRE_REDFISH_MOCKUP=1 in CI to make it mandatory")
	}
	python := os.Getenv("TRSTCTL_REDFISH_MOCKUP_PYTHON")
	if python == "" {
		python = "python3"
	}
	identity := filepath.Join(t.TempDir(), "redfish-mockup-tls.pem")
	cert, err := mtls.LoadOrCreateSelfSignedServerCert(identity, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The mockup reports the port it was given, not one it chose, so the
	// test picks a free one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	if !ok {
		t.Fatal("a loopback listener has no TCP address")
	}
	port := addr.Port
	cmd := exec.Command(python, filepath.Join(dir, "redfishMockupServer.py"), // #nosec G204 G702 -- the interpreter and checkout the CI lab names, fixed arguments (CWE-78)
		"-H", "127.0.0.1", "-p", strconv.Itoa(port), "-S", "-D", filepath.Join(dir, "public-rackmount1"),
		"-s", "--cert", identity, "--key", identity)
	var output lockedTail
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the Redfish mockup server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	transport, err := mtls.HTTPTransport(cert.TrustPEM)
	if err != nil {
		t.Fatal(err)
	}
	m := redfishMockup{endpoint: "https://127.0.0.1:" + strconv.Itoa(port), caPEM: cert.TrustPEM,
		client: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	for deadline := time.Now().Add(30 * time.Second); ; {
		if status, _, _ := m.do(t, http.MethodGet, "/redfish/v1/", nil); status == http.StatusOK {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Redfish mockup server did not answer within 30s: %s", output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// do sends one request to the mockup, independently of the provider; a
// request that gets no answer reads as status 0.
func (m redfishMockup) do(t *testing.T, method, path string, body any) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, m.endpoint+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, raw
}

// sessions counts the session resources the mockup holds.
func (m redfishMockup) sessions(t *testing.T) int {
	t.Helper()
	status, _, raw := m.do(t, http.MethodGet, "/redfish/v1/SessionService/Sessions", nil)
	var collection struct {
		Members []json.RawMessage `json:"Members"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &collection) != nil {
		t.Fatalf("read the mockup's sessions: %d %s", status, raw)
	}
	return len(collection.Members)
}

// Against DMTF's stock mockup: a rotation's whole exchange (an administrator
// session, the account collection and its members, the PATCH, the session's
// DELETE, then a session as the account) completes and publishes the new
// credential; discovery reads DMTF's Administrator and the added account with
// their RoleIds; every session the provider opened is deleted; and no
// password reaches an event, though the mockup echoes a PATCHed password back.
func TestServedRedfishProviderAgainstDMTFsMockupServerA271O2(t *testing.T) {
	mock := startRedfishMockup(t)
	ctx := context.Background()
	// The mockup's account collection holds only its Administrator; the
	// account to rotate is added through the mockup's own POST, as a
	// controller's administrator would add it.
	if status, _, raw := mock.do(t, http.MethodPost, "/redfish/v1/AccountService/Accounts",
		map[string]any{"UserName": "ops", "RoleId": "Operator", "Enabled": true}); status/100 != 2 {
		t.Fatalf("add the account to the mockup: %d %s", status, raw)
	}
	startingSessions := mock.sessions(t)
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "dmtf-mockup", Type: "redfish", Endpoint: mock.endpoint,
		TLSCARef: writeServedCredentialFile(t, "a271o2-mockup-ca", string(mock.caPEM)), AllowPrivate: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		AdminUser: "Administrator", PasswordRef: writeServedCredentialFile(t, "a271o2-mockup-admin", "mockup-admin-password-1"),
		AllowedRoles: []string{"bmc/ops"}, RoleBindings: map[string]string{"bmc/ops": "ops"}, MaxTTL: "1h", AllowStaticRotation: true}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	tok := seedScopedTokenSubject(t, sh.store, sh.tenant, "a271o2-mockup-operator", "secrets:read", "secrets:write", "access:read", "access:targets.write")
	seed, _ := json.Marshal(map[string]string{"username": "ops", "password": "mockup-ops-password-1"}) // #nosec G101 -- fabricated test-only password for the mockup (CWE-798)
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", tok, "a271o2-seed",
		map[string]any{"name": "bmc/ops", "value": string(seed)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/rotations", tok, "a271o2-rotate",
		map[string]any{"provider": "dmtf-mockup", "key": "bmc/ops", "old_ref": "ops", "acknowledge_single_phase": true})
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
		t.Fatalf("the rotation against the mockup: %+v", view)
	}
	status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/store/bmc/ops", tok, nil)
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
	if credential.Username != "ops" || credential.Password == "" || credential.Password == "mockup-ops-password-1" {
		t.Fatal("the rotation did not publish a new password for ops")
	}

	if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/discovery/sources/dmtf-mockup", tok, "a271o2-source",
		map[string]any{"interval_seconds": 3600}); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("save the discovery source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/discovery/sources/dmtf-mockup/runs", tok, "a271o2-scan", nil)
	var scan a260Run
	if status != http.StatusAccepted || json.Unmarshal(body, &scan) != nil {
		t.Fatalf("scan: %d %s", status, body)
	}
	if run := awaitQueuedDiscoveryProofA267(t, sh, tok, scan.ID); run.Status != "completed" || run.Accounts != 2 {
		t.Fatalf("the scan of the mockup: %+v", run)
	}
	status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=dmtf-mockup", tok, nil)
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
	if len(found) != 2 || found["Administrator"] != "role Administrator" || found["ops"] != "role Operator" {
		t.Fatalf("discovered %v from the mockup, want Administrator and ops with their RoleIds", found)
	}
	if now := mock.sessions(t); now != startingSessions {
		t.Fatalf("the mockup holds %d sessions, %d before the provider's: a session was left open", now, startingSessions)
	}
	leaks := [][]byte{[]byte("mockup-admin-password-1"), []byte("mockup-ops-password-1"), []byte(credential.Password)}
	if err := sh.log.Replay(ctx, 0, func(event events.Event) error {
		for _, s := range leaks {
			if event.TenantID == sh.tenant && bytes.Contains(event.Data, s) {
				t.Fatalf("a controller password reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
