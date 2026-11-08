// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mysqlsignin"
)

// startPAMMySQL runs the pinned MySQL image with an "app" database holding a
// note, and returns its container and a provider of per-session accounts in
// the "mysql-reader" role (SELECT on app).
func startPAMMySQL(t *testing.T, note string) (string, DynamicSecretProviderRegistry) {
	t.Helper()
	if out, err := exec.Command("docker", "image", "inspect", a201MySQLImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a201MySQLImage, err, out)
	}
	id, addr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=a256-admin", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	// The image's init server answers on the socket and then stops; only
	// the real server answers over TCP, after the init-done line.
	a256AwaitLog(t, id, "MySQL init process done")
	a201Await(t, "MySQL", func() bool {
		_, err := a201Exec(id, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-pa256-admin", "-e", "SELECT 1")
		return err == nil
	})
	if out, err := a201Exec(id, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-pa256-admin", "app", "-e",
		"CREATE TABLE notes (id INT PRIMARY KEY, note TEXT); INSERT INTO notes VALUES (1, '"+note+"');"); err != nil {
		t.Fatalf("seed MySQL: %v %s", err, out)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-mysql-provider", Type: "mysql",
		AdminDSNRef: writeServedCredentialFile(t, "mysql-admin-dsn", "root:a256-admin@tcp("+addr+")/app?parseTime=true\n"),
		Database:    "app", Addr: addr, AccountHost: "%", AllowWildcardAccountHost: true,
		AllowedRoles: []string{"mysql-reader"}, RoleAccess: map[string]string{"mysql-reader": "read"}, MaxTTL: "1h", UsernamePrefix: "a256_mysql",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, registry
}

var fixtureMySQLCommand = regexp.MustCompile(`mysql -h 127\.0\.0\.1 -P (\d+)`)

// mysqlSessionAccounts lists the per-session accounts the provider created.
func mysqlSessionAccounts(t *testing.T, mysqlID string) []string {
	t.Helper()
	out, err := a201Exec(mysqlID, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-pa256-admin", "-N", "-e", "SELECT user FROM mysql.user WHERE user LIKE 'a256_mysql%'")
	if err != nil {
		t.Fatalf("list accounts: %v %s", err, out)
	}
	var users []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "a256_mysql") {
			users = append(users, line)
		}
	}
	return users
}

// mysqlGatewayClient signs a raw client in through the tunnel, as a stock
// client would with no password: the gateway answers the handshake.
func mysqlGatewayClient(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, p, err := mysqlsignin.ReadPacket(conn); err != nil {
		t.Fatal(err)
	} else if _, err := mysqlsignin.ParseHandshake(p); err != nil {
		t.Fatal(err)
	}
	caps := mysqlsignin.ClientProtocol41 | mysqlsignin.ClientSecureConnection | mysqlsignin.ClientPluginAuth |
		mysqlsignin.ClientPluginAuthLenencClientData | mysqlsignin.ClientDeprecateEOF
	resp := binary.LittleEndian.AppendUint32(nil, caps)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, 255)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, "anyone\x00"...)
	resp = append(resp, 0)
	resp = append(resp, "caching_sha2_password\x00"...)
	if err := mysqlsignin.WritePacket(conn, 1, resp); err != nil {
		t.Fatal(err)
	}
	if _, p, err := mysqlsignin.ReadPacket(conn); err != nil || len(p) == 0 || p[0] != 0 {
		t.Fatalf("sign-in through the gateway = %q %v", p, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// TestServedGatewayMySQLSessionsA256: a MySQL target is served only through
// the access gateway, to the stock mysql client holding no password. The
// gateway answers the client's handshake itself and signs in as the
// session's own account (the first sign-in takes caching_sha2_password's full
// authentication); the account's grants scope the session; COM_CHANGE_USER
// is refused; the session is recorded masked, sealed and verifiable; an
// operator's termination closes a live connection and the gateway
// acknowledges it; the session's account is dropped.
func TestServedGatewayMySQLSessionsA256(t *testing.T) {
	token := "ghp_a256MySQLSessionToken" + strings.Repeat("M", 15) // a GitHub token's shape: ghp_ and 36 characters
	f := startGatewayFixture(t, gatewayFixtureOptions{mysqlNote: token})
	h := f.h

	session := f.open("a256-mysql", map[string]any{"target_type": "mysql", "target_id": "mysql-gw", "role": "mysql-reader", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil {
		t.Fatalf("the MySQL session was not delivered through its gateway: %+v", session)
	}
	tunnelOut, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, fixtureMySQLCommand.MatchString)
	defer stopTunnel()
	port := fixtureMySQLCommand.FindStringSubmatch(tunnelOut)[1]
	accounts := mysqlSessionAccounts(t, f.mysqlID)
	if len(accounts) != 1 {
		t.Fatalf("session accounts = %v, want the session's one", accounts)
	}
	_, read := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for what, text := range map[string]string{"session read": string(read), "CLI output": tunnelOut} {
		if strings.Contains(text, accounts[0]) || strings.Contains(text, "@tcp(") {
			t.Fatalf("the %s carries the session's credential: %s", what, text)
		}
	}
	mysqlCLI := func(sql string) string {
		cmd := exec.CommandContext(f.ctx, "docker", "exec", f.mysqlID, "mysql", "-h", "host.docker.internal", "-P", port, "-u", "anyone", "-N", "-e", sql) // #nosec G204 G702 -- the stock mysql client against the test's own tunnel (CWE-78)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	if got := mysqlCLI("SELECT CURRENT_USER(); SELECT note FROM app.notes"); !strings.Contains(got, accounts[0]+"@%") || !strings.Contains(got, token) {
		t.Fatalf("queries through the gateway = %q (gateway: %s)", got, f.gatewayLog.String())
	}
	if got := mysqlCLI("INSERT INTO app.notes VALUES (2, 'no')"); !strings.Contains(got, "INSERT command denied") {
		t.Fatalf("a write outside the session's grants = %q", got)
	}
	// A login change is refused at the gateway; the connection keeps its
	// account.
	conn := mysqlGatewayClient(t, "127.0.0.1:"+port)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := mysqlsignin.WritePacket(conn, 0, append([]byte{0x11}, "root\x00\x00app\x00"...)); err != nil {
		t.Fatal(err)
	}
	if seq, p, err := mysqlsignin.ReadPacket(conn); err != nil || seq != 1 || len(p) == 0 || p[0] != 0xff || !strings.Contains(string(p), "COM_CHANGE_USER is refused") {
		t.Fatalf("COM_CHANGE_USER through the gateway = %d %q %v", seq, p, err)
	}
	if err := mysqlsignin.WritePacket(conn, 0, append([]byte{0x03}, "SELECT CURRENT_USER()"...)); err != nil {
		t.Fatal(err)
	}
	var result []string
	for {
		_, p, err := mysqlsignin.ReadPacket(conn)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, string(p))
		if len(p) > 0 && (p[0] == 0xfe || p[0] == 0xff) {
			break
		}
	}
	if !strings.Contains(strings.Join(result, " "), accounts[0]+"@%") {
		t.Fatalf("after the refused COM_CHANGE_USER the connection is %q", result)
	}

	// The live connection, terminated.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator,
		"a256-mysql-terminate", map[string]any{"reason": "a256 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, _, err := mysqlsignin.ReadPacket(conn); err == nil {
		t.Fatal("the terminated connection is still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the terminated connection was not closed")
	}
	a201Await(t, "the gateway acknowledges the termination", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "the session's account is dropped", func() bool { return len(mysqlSessionAccounts(t, f.mysqlID)) == 0 })

	// The recording.
	a201Await(t, "the MySQL recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	if strings.Contains(text, token) || strings.Contains(text, "a256-admin") {
		t.Fatalf("the MySQL recording kept a secret:\n%s", text)
	}
	for _, want := range []string{"query: SELECT CURRENT_USER()", "columns: CURRENT_USER()", "query: SELECT note FROM app.notes",
		"row: [masked:github-token]", "error: 1142 42000: INSERT command denied", "refused: COM_CHANGE_USER"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the MySQL recording lacks %q:\n%s", want, text)
		}
	}
}
