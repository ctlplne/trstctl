// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/store"
)

func TestServedDesktopVaultedRegistrationA263(t *testing.T) {
	if os.Getenv("TRSTCTL_RDP_NATIVE_LAB") != "1" {
		if os.Getenv("TRSTCTL_REQUIRE_RDP_LAB") == "1" {
			t.Fatal("native desktop served lab required")
		}
		t.Skip("native Linux desktop served lab not requested")
	}
	runNativeDesktopJourney(t, false)
}
func TestServedADDesktopA263(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_DESKTOP_LAB") != "1" {
		t.Skip("owned Samba-backed desktop not requested")
	}
	runNativeDesktopJourney(t, true)
}
func runNativeDesktopJourney(t *testing.T, directory bool) {
	t.Helper()
	ctx := t.Context()
	st := nativeDesktopOwnedStore(t)
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	public, err := crypto.SSHPublicKeyFromSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	authorized := filepath.Join(dir, "authorized")
	if err = os.WriteFile(authorized, public, 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(encoded)
	keyFile := filepath.Join(dir, "admin.pem")
	if err = os.WriteFile(keyFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	hostPin, err := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub").Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(hostPin))
	if len(fields) < 2 {
		t.Fatal("missing lab SSH host pin")
	}
	sshConfig := filepath.Join(dir, "sshd_config")
	sshText := "Port 2222\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nPidFile " + filepath.Join(dir, "sshd.pid") + "\nAuthorizedKeysFile " + authorized + "\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes yes\nAllowUsers root\n"
	if err = os.WriteFile(sshConfig, []byte(sshText), 0o600); err != nil {
		t.Fatal(err)
	}
	sshd := exec.CommandContext(ctx, "/usr/sbin/sshd", "-D", "-e", "-f", sshConfig) // #nosec G204 -- fixed lab SSH daemon and test-owned configuration; no shell or credential arguments (CWE-78)
	if err = sshd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sshd.Process.Kill(); _ = sshd.Wait() }()
	pinBytes, err := os.ReadFile("/run/rdp-pin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "pam-desktop", Type: "unix", Addr: "127.0.0.1:2222", AdminUser: "root", PrivateKeyRef: "file:" + keyFile, HostKeyFingerprint: fields[1], AllowedRoles: []string{"desktop/account"}, RoleBindings: map[string]string{"desktop/account": "desktop-proof"}, AllowStaticRotation: true, MaxTTL: "1h"}
	if directory {
		pam, err := os.ReadFile("/etc/pam.d/xrdp-sesman")
		if err != nil || !bytes.Contains(pam, []byte("auth required pam_ldap.so")) || bytes.Contains(pam, []byte("auth required pam_unix.so")) {
			t.Fatal("AD proof requires LDAP-only target authentication")
		}
		state, err := exec.CommandContext(ctx, "/usr/bin/passwd", "-S", "a263-desktop").Output()
		if err != nil || len(strings.Fields(string(state))) < 2 || strings.Fields(string(state))[1] != "L" {
			t.Fatal("AD proof requires a locked local password")
		}
	}
	username, fixturePath, bindDN := "desktop-proof", "/run/rdp-password", ""
	if directory {
		username, fixturePath, bindDN = "a263-desktop", "/run/ad-desktop-password", "CN=a263-desktop,OU=TrstctlA263,DC=a263,DC=test"
		admin, err := os.ReadFile("/run/ad-admin-password")
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Wipe(admin)
		adminPath := filepath.Join(t.TempDir(), "ad-admin")
		if err = secretfile.Create(adminPath, admin); err != nil {
			t.Fatal(err)
		}
		cfg = config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "pam-desktop", Type: "ldap", DirectoryMode: "active_directory", ADLogonNames: map[string]string{bindDN: username}, Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:" + adminPath, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"desktop/account"}, RoleBindings: map[string]string{"desktop/account": bindDN}, AllowStaticRotation: true, MaxTTL: "1h"}
	}
	// Decode the public attachment so the pre-feature candidate reaches the API
	// refusal, rather than failing to compile against a field not yet built.
	raw, err := json.Marshal(map[string]any{"desktop": map[string]any{"address": "127.0.0.1:3389", "certificate_sha256": strings.TrimSpace(string(pinBytes)), "width": 800, "height": 600, "tls_only": true}})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	objects := s3test.NewServer(t)
	audit, err := jose.GenerateRSASigningKey("desktop-audit")
	if err != nil {
		t.Fatal(err)
	}
	jobKind := accessgateway.KindSessionDesktop
	if directory {
		jobKind = accessgateway.KindSessionADDesktop
	}
	h := newRoleHarnessNamedWithOwnedStore(t, "role-agent", []string{mtls.AgentRoleGateway}, []string{jobKind}, nil, st, func(d *Deps) {
		d.Protocols.SSH = config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
		d.ArchiveObjectStore = objects.Open(t)
		d.AuditSigningKey = audit
		d.EnableSecretsAPI = true
		d.TenantDynamicSecretProviders = registry
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a263-desktop", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "desktop-registrar", "access:read", "access:targets.write", "access:write", "secrets:read", "secrets:write")
	password, err := os.ReadFile(fixturePath) // #nosec G304 G703 -- one of two fixed owned native fixture credential paths, selected by the test (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(password)
	credential, err := json.Marshal(struct { // #nosec G117 -- byte-backed fixture credential goes only to the encrypted secret store and private native pipe (CWE-200)
		Host, Username string
		BindDN         string           `json:"bind_dn,omitempty"`
		Password       secret.JSONBytes `json:"password"`
	}{Host: "127.0.0.1:2222", Username: username, BindDN: bindDN, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", registrar, "desktop-seed", map[string]any{"name": "desktop/account", "value": secret.JSONBytes(credential)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed desktop secret status=%d", status)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "desktop-register", map[string]any{"id": "desktop-lab", "target_type": "rdp", "provider_id": "pam-desktop", "allowed_roles": []string{"desktop/account"}, "account_secret": "desktop/account", "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": gateway.Addr().String()}); status != http.StatusCreated {
		t.Fatalf("register real desktop account: %d %s", status, body)
	}
	badRole := map[string]any{"request_id": uuid.NewString(), "target_type": "rdp", "target_id": "desktop-lab", "role": "other/account", "ttl_seconds": 60, "reason": "negative role proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", registrar, "desktop-wrong-role", badRole); status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("is not allowed")) {
		t.Fatalf("actual desktop role denial: %d %s", status, body)
	}
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a263-desktop", Status: "active", Executors: &transport.ExecutorReport{Version: "a263-desktop", Kinds: []transport.ExecutorKind{{Kind: jobKind}}}}); e != nil {
		t.Fatal(e)
	}
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, e := h.client.SignGatewayServerCertificate(ctx, &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if e != nil {
			return nil, e
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("missing gateway certificate")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()
	tlsListener, err := mtls.GatewayWrapListener(gateway, cert)
	if err != nil {
		t.Fatal(err)
	}
	f := &gatewayFixture{t: t, ctx: ctx, h: h, objects: objects, dir: t.TempDir(), gatewayAddr: gateway.Addr().String(), gatewayLog: &lockedBuffer{}}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("desktop gateway diagnostics: %s", f.gatewayLog.String())
		}
	})
	f.requester = seedScopedTokenSubject(t, st, h.tenant, "desktop-requester", "access:read", "access:write")
	f.reviewerOne = seedScopedTokenSubject(t, st, h.tenant, "desktop-reviewer-one", "access:approve")
	f.reviewerTwo = seedScopedTokenSubject(t, st, h.tenant, "desktop-reviewer-two", "access:approve")
	f.operator = seedScopedTokenSubject(t, st, h.tenant, "desktop-operator", "access:read", "access:terminate")
	f.auditor = seedScopedTokenSubject(t, st, h.tenant, "desktop-auditor", "access:read", "recordings:read", "recordings:export")
	f.gw, err = accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: tlsListener, DesktopHelper: "/run/rdp-helper", MaxDesktopConnections: 1, ClaimInterval: 50 * time.Millisecond, ExtendInterval: 100 * time.Millisecond, Logf: func(format string, args ...any) {
		_, _ = f.gatewayLog.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
	}})
	if err != nil {
		t.Fatal(err)
	}
	running, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = f.gw.Run(running) }()
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(running)
	f.api = httptest.NewServer(h.srv.Handler())
	defer f.api.Close()
	session := f.open("desktop-approved", map[string]any{"target_type": "rdp", "target_id": "desktop-lab", "role": "desktop/account", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil {
		t.Fatal("desktop did not use gateway-only delivery")
	}
	desktopAwait(t, "native desktop session held", func() bool {
		for _, id := range f.gw.Sessions() {
			if id == session.ID {
				return true
			}
		}
		return false
	})
	commandPattern := regexp.MustCompile(`vncviewer .* 127\.0\.0\.1::(\d+)`)
	instruction, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, commandPattern.MatchString)
	defer stopTunnel()
	port, err := strconv.Atoi(commandPattern.FindStringSubmatch(instruction)[1])
	if err != nil {
		t.Fatal(err)
	}
	runDesktopViewerTask(t, ctx, port, username, password, func(exited <-chan struct{}) {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "desktop-terminate", map[string]any{"reason": "desktop proof complete"}); status != http.StatusAccepted {
			t.Fatalf("terminate desktop: %d %s", status, body)
		}
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("terminate left the live desktop viewer connected")
		}
	})
	desktopAwait(t, "desktop recording sealed", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && bytes.Contains(body, []byte(`"status":"sealed"`))
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"verified":true`)) || !bytes.Contains(body, []byte(`"scope":"desktop_pixels"`)) {
		t.Fatalf("verify desktop recording: %d %s", status, body)
	}

	status, exported := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/export", f.auditor, nil)
	if status != http.StatusOK || bytes.Contains(exported, password) {
		t.Fatal("desktop export failed or retained an upstream password")
	}
	var evidence struct {
		Frames []struct {
			Event   string `json:"e"`
			Data    string `json:"d"`
			Desktop *struct {
				Codec                  string `json:"codec"`
				Width, Height, Y, Rows uint16
				Last                   bool `json:"last"`
			} `json:"desktop"`
		} `json:"frames"`
	}
	if json.Unmarshal(exported, &evidence) != nil {
		t.Fatal("desktop export is not replay data")
	}
	completed := 0
	blue := false
	for _, line := range evidence.Frames {
		if line.Event != "desktop" {
			continue
		}
		if line.Desktop == nil || line.Desktop.Codec != "png" || line.Desktop.Rows == 0 || line.Desktop.Rows > 16 {
			t.Fatal("invalid exported desktop tile")
		}
		raw, e := base64.StdEncoding.DecodeString(line.Data)
		if e != nil {
			t.Fatal(e)
		}
		image, e := png.Decode(bytes.NewReader(raw))
		if e != nil || image.Bounds().Dx() != int(line.Desktop.Width) || image.Bounds().Dy() != int(line.Desktop.Rows) {
			t.Fatal("exported image dimensions differ")
		}
		for y := 0; y < image.Bounds().Dy(); y++ {
			for x := 0; x < image.Bounds().Dx(); x++ {
				r, g, b, _ := image.At(x, y).RGBA()
				if r == 0 && g == 0 && b == 32896 {
					blue = true
					break
				}
			}
		}
		if line.Desktop.Last {
			completed++
		}
	}
	if completed == 0 || !blue {
		t.Fatal("export does not replay the actual blue desktop")
	}
	if err = os.WriteFile("/run/trstctl-desktop-export.json", exported, 0o600); err != nil {
		t.Fatal(err)
	}

}

func runDesktopViewerTask(t *testing.T, parent context.Context, port int, username string, password []byte, after func(<-chan struct{})) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	x := exec.CommandContext(ctx, "/usr/bin/Xvfb", ":94", "-screen", "0", "1024x768x24", "-nolisten", "tcp", "-ac")
	if e := x.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = x.Process.Kill(); _ = x.Wait() }()
	desktopAwait(t, "owned display ready", func() bool { _, e := os.Stat("/tmp/.X11-unix/X94"); return e == nil })
	home := t.TempDir()
	viewer := exec.CommandContext(ctx, "/usr/bin/vncviewer", "-SecurityTypes=None", "-SendClipboard=0", "-AcceptClipboard=0", "-RemoteResize=0", "-AutoSelect=0", "-FullColor=1", "-PreferredEncoding=Raw", "-ReconnectOnError=0", "-AlertOnFatalError=0", fmt.Sprintf("127.0.0.1::%d", port)) // #nosec G204 -- stock viewer and port from this owned CLI tunnel; no shell or upstream credential (CWE-78)
	viewer.Env = []string{"DISPLAY=:94", "HOME=" + home, "LANG=C"}
	if e := viewer.Start(); e != nil {
		t.Fatal(e)
	}
	exited := make(chan struct{})
	go func() { _ = viewer.Wait(); close(exited) }()
	defer func() { _ = viewer.Process.Kill(); <-exited }()
	tool := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "/usr/bin/xdotool", args...) // #nosec G204 -- fixed tool and test-built public keyboard/window arguments, no shell (CWE-78)
		cmd.Env = []string{"DISPLAY=:94", "PATH=/usr/bin:/bin"}
		raw, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("desktop input tool failed: %s", raw)
		}
		return raw, nil
	}
	var window string
	desktopAwait(t, "approved stock desktop viewer", func() bool {
		raw, e := tool("search", "--name", "trstctl approved desktop")
		if e == nil && len(strings.Fields(string(raw))) > 0 {
			window = strings.Fields(string(raw))[0]
		}
		return window != ""
	})
	if _, e := strconv.ParseUint(window, 10, 32); e != nil {
		t.Fatal(e)
	}
	// Wait for the actual user desktop rather than treating RDP transport Ready
	// as authentication. The independent file is the task's completion evidence.
	time.Sleep(time.Second)
	proof := fmt.Sprintf("/home/%s/approved-gateway-proof-%d", username, time.Now().UnixNano())
	defer func() { _ = os.Remove(proof) }()
	if _, e := tool("windowfocus", window); e != nil {
		t.Fatal(e)
	}
	if _, e := tool("type", "--window", window, "--clearmodifiers", "--delay", "10", "(printf approved-desktop-proven:; id -un) > "+proof); e != nil {
		t.Fatal(e)
	}
	if _, e := tool("key", "--window", window, "Return"); e != nil {
		t.Fatal(e)
	}
	desktopAwait(t, "approved RDP task readback", func() bool {
		raw, e := os.ReadFile(proof) // #nosec G304 -- unique owned task file under fixed lab account home (CWE-22)
		return e == nil && string(raw) == "approved-desktop-proven:"+username+"\n"
	})
	for _, name := range []string{"cmdline", "environ"} {
		raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/%s", viewer.Process.Pid, name))
		if e != nil || bytes.Contains(raw, password) {
			t.Fatal("upstream password reached the stock viewer")
		}
	}
	after(exited)

}

func desktopAwait(t *testing.T, label string, ready func() bool) {
	t.Helper()
	until := time.Now().Add(30 * time.Second)
	for time.Now().Before(until) {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not become ready", label)
}

// nativeDesktopOwnedStore uses only the isolated Linux lab PostgreSQL instance.
func nativeDesktopOwnedStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()
	// Each invocation owns a fresh database. Recording evidence intentionally
	// outlives sessions, so truncating sessions is not a fresh recording store.
	database := "trstctl_desktop_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	create := exec.CommandContext(ctx, "/usr/lib/postgresql/15/bin/createdb", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", database) // #nosec G204 -- generated owned database identifier, fixed local test server/tool, no shell (CWE-78)
	if err := create.Run(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cleanup, "/usr/lib/postgresql/15/bin/dropdb", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", database)
		if err := cmd.Run(); err != nil {
			t.Error("drop exact owned native database:", err)
		}
	}) // #nosec G204 -- drops only the exact database this test created, no shell (CWE-78)
	st, err := store.Open(ctx, "postgres://postgres@127.0.0.1:55432/"+database+"?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err = st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resetServerTestStore(t, st)

	return st
}
