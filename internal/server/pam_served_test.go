// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// TestServedPAMJITBrokersPostgresAndSSHWithAuditAndExpiry is the PAM-01
// acceptance proof. It drives the assembled HTTP API: a requester presents an
// attested proof, trstctl brokers short-lived access to a real PostgreSQL target and
// a disposable sshd container that trusts the served SSH CA, emits audit/session
// events, and automatically expires the brokered access.
func TestServedPAMJITBrokersPostgresAndSSHWithAuditAndExpiry(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)

	h := newOperatingServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			d.PAM = PAMConfig{
				Enabled:        true,
				DefaultTTL:     2 * time.Second,
				MaxTTL:         5 * time.Second,
				ExpiryInterval: 10 * time.Millisecond,
				Attestors:      []attest.Attestor{servedPAMAttestor{}},
				PostgresTargets: []PAMPostgresTarget{{
					ID:             "pg-main",
					DSN:            []byte(pgDSN),
					Database:       "postgres",
					Schema:         "public",
					UsernamePrefix: "trstctl_pam",
				}},
				SSHTargets: []PAMSSHTarget{{
					ID:         "ssh-edge",
					Host:       "127.0.0.1",
					Principals: []string{"alice"},
				}},
			}
		},
	)
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")

	worker, ok := any(h.srv).(interface{ RunPAMSessionExpiry(context.Context) })
	if !ok {
		t.Fatal("served PAM expiry worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunPAMSessionExpiry(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})

	pg := servedPAMOpen(t, h, admin, "pam-01-postgres", map[string]any{
		"target_type":    "postgres",
		"target_id":      "pg-main",
		"role":           "readonly",
		"reason":         "production incident 42",
		"method":         "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ttl_seconds":    2,
	})
	if pg.ID == "" || pg.TargetType != "postgres" || pg.Status != "active" || pg.Postgres == nil || pg.Postgres.DSN == "" {
		t.Fatalf("postgres PAM response = %+v", pg)
	}
	if !strings.HasPrefix(pg.Postgres.Username, "trstctl_pam_") {
		t.Fatalf("postgres PAM username = %q", pg.Postgres.Username)
	}
	assertPAMPostgresAccess(t, pg.Postgres.DSN, true)

	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatalf("ssh authority key: %v", err)
	}
	sshd := startPAMSSHD(t, caPub)
	keyPath, publicKey := generatePAMSSHKey(t)
	ssh := servedPAMOpen(t, h, admin, "pam-01-ssh", map[string]any{
		"target_type":    "ssh",
		"target_id":      "ssh-edge",
		"role":           "user",
		"reason":         "production incident 42",
		"method":         "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ssh_public_key": publicKey,
		"ssh_principal":  "alice",
		"ttl_seconds":    2,
	})
	if ssh.ID == "" || ssh.TargetType != "ssh" || ssh.Status != "active" || ssh.SSH == nil || ssh.SSH.Certificate == "" {
		t.Fatalf("ssh PAM response = %+v", ssh)
	}
	if ssh.SSH.Principal != "alice" || ssh.SSH.KeyID == "" || ssh.SSH.Serial == 0 {
		t.Fatalf("ssh PAM certificate metadata = %+v", ssh.SSH)
	}
	assertPAMSSHAccess(t, sshd, keyPath, ssh.SSH.Certificate, true)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pamPostgresRoleExists(t, pgDSN, pg.Postgres.Username) && h.hasEvent(t, "pam.session.expired") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if pamPostgresRoleExists(t, pgDSN, pg.Postgres.Username) {
		t.Fatalf("postgres PAM role %q did not auto-expire", pg.Postgres.Username)
	}
	assertPAMPostgresAccess(t, pg.Postgres.DSN, false)
	for time.Now().Before(ssh.SSH.ValidBefore.Add(250 * time.Millisecond)) {
		time.Sleep(25 * time.Millisecond)
	}
	assertPAMSSHAccess(t, sshd, keyPath, ssh.SSH.Certificate, false)

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "pam.session.started", "pam.session.expired", "ssh.cert.issued"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served PAM did not emit %s", eventType)
		}
	}
	if h.logContains(t, pg.Postgres.DSN) || h.logContains(t, ssh.SSH.Certificate) {
		t.Fatal("PAM credential material reached the event log")
	}
}

type servedPAMAttestor struct{}

func (servedPAMAttestor) Method() string { return "stub_pam" }

func (servedPAMAttestor) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errServedEphemeralForgery
	}
	return attest.Attestation{
		Method:    "stub_pam",
		Subject:   "pam-workload",
		Selectors: []string{"pam:test"},
	}, nil
}

type servedPAMSessionResponse struct {
	ID         string                       `json:"id"`
	TargetID   string                       `json:"target_id"`
	TargetType string                       `json:"target_type"`
	Status     string                       `json:"status"`
	Subject    string                       `json:"subject"`
	ExpiresAt  time.Time                    `json:"expires_at"`
	Postgres   *servedPAMPostgresCredential `json:"postgres,omitempty"`
	SSH        *servedPAMSSHCredential      `json:"ssh,omitempty"`
}

type servedPAMPostgresCredential struct {
	Username string `json:"username"`
	DSN      string `json:"dsn"`
}

type servedPAMSSHCredential struct {
	Certificate string    `json:"certificate"`
	Principal   string    `json:"principal"`
	KeyID       string    `json:"key_id"`
	Serial      uint64    `json:"serial"`
	ValidBefore time.Time `json:"valid_before"`
}

func servedPAMOpen(t *testing.T, h *servedHarness, token, idemKey string, req map[string]any) servedPAMSessionResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", token, idemKey, req)
	if status != http.StatusCreated {
		t.Fatalf("open PAM session status = %d, want 201; body=%s", status, body)
	}
	var out servedPAMSessionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode PAM response: %v; body=%s", err, body)
	}
	return out
}

func startPAMPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freePAMPort(t)
	dir, err := os.MkdirTemp("", "trstctl-pam-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	runtime := filepath.Join(dir, "runtime")
	data := filepath.Join(dir, "data")
	for _, path := range []string{bin, runtime, data} {
		if err := os.MkdirAll(path, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

func seedPAMPostgresTable(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target postgres: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE TABLE public.pam_smoke (id int PRIMARY KEY); INSERT INTO public.pam_smoke VALUES (1);`); err != nil {
		t.Fatalf("seed target postgres: %v", err)
	}
}

func assertPAMPostgresAccess(t *testing.T, dsn string, wantOK bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		if wantOK {
			t.Fatalf("connect with PAM postgres credential: %v", err)
		}
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var n int
	err = conn.QueryRow(ctx, `SELECT count(*) FROM public.pam_smoke`).Scan(&n)
	if wantOK && (err != nil || n != 1) {
		t.Fatalf("query with PAM postgres credential: n=%d err=%v", n, err)
	}
	if !wantOK && err == nil {
		t.Fatalf("expired PAM postgres credential still queried target")
	}
}

func pamPostgresRoleExists(t *testing.T, adminDSN, user string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect target postgres as admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, user).Scan(&exists); err != nil {
		t.Fatalf("check target postgres role: %v", err)
	}
	return exists
}

func startPAMSSHD(t *testing.T, caPub []byte) pamSSHD {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the sshd acceptance backend: %v", err)
	}
	if out, err := pamDockerOutput(t, 15*time.Second, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required for the sshd acceptance backend: %v\n%s", err, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trusted_user_ca_keys"), caPub, 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write trusted CA: %v", err)
	}
	dockerfile := `FROM alpine:3.20
RUN apk add --no-cache openssh-server
RUN adduser -D -s /bin/sh alice && mkdir -p /etc/ssh/trstctl && ssh-keygen -A
RUN echo 'alice:disabled-password' | chpasswd
COPY trusted_user_ca_keys /etc/ssh/trstctl/trusted_user_ca_keys
RUN printf 'Port 22\nTrustedUserCAKeys /etc/ssh/trstctl/trusted_user_ca_keys\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile none\nPermitRootLogin no\nAllowUsers alice\nLogLevel VERBOSE\n' > /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e","-f","/etc/ssh/sshd_config"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write sshd Dockerfile: %v", err)
	}
	image := "trstctl-pam-sshd:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 3*time.Minute, "build", "-t", image, dir); err != nil {
		t.Skipf("build sshd container image: %v\n%s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("image", "rm", "-f", image) })
	name := "trstctl-pam-sshd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 30*time.Second, "run", "-d", "--name", name, "-p", "127.0.0.1::22", image); err != nil {
		t.Fatalf("run sshd container: %v\n%s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("rm", "-f", name) })
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := pamDockerOutput(t, 5*time.Second, "port", name, "22/tcp")
		if err == nil {
			addr = strings.TrimSpace(string(out))
			if addr != "" {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if addr == "" {
		logs, _ := pamDockerOutput(t, 15*time.Second, "logs", name)
		t.Fatalf("sshd container did not expose a port; logs:\n%s", logs)
	}
	parts := strings.Split(addr, ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("parse sshd port from %q: %v", addr, err)
	}
	return pamSSHD{Name: name, Port: port}
}

func pamDockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}

func pamDockerCleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", args...).Run() // #nosec G204 -- fixed best-effort test cleanup bounded by a context deadline (CWE-78)
}

type pamSSHD struct {
	Name string
	Port int
}

func generatePAMSSHKey(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen is required for the sshd acceptance backend: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "pam-01").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("generate SSH user key: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub") // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read SSH public key: %v", err)
	}
	return keyPath, string(pub)
}

func assertPAMSSHAccess(t *testing.T, sshd pamSSHD, keyPath, cert string, wantOK bool) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("ssh client is required for the sshd acceptance backend: %v", err)
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(cert), 0o600); err != nil {
		t.Fatalf("write SSH certificate: %v", err)
	}
	args := []string{
		"-F", "/dev/null",
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-p", strconv.Itoa(sshd.Port),
		"alice@127.0.0.1",
		"true",
	}
	cmd := exec.Command("ssh", args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	out, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		logs, _ := pamDockerOutput(t, 15*time.Second, "logs", sshd.Name)
		t.Fatalf("ssh with PAM certificate failed: %v\n%s\nsshd logs:\n%s", err, out, logs)
	}
	if !wantOK && err == nil {
		t.Fatalf("expired PAM SSH certificate still authenticated")
	}
}

func freePAMPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}
