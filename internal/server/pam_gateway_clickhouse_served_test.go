// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// a256ClickHouseImage is the A239 lab's pinned ClickHouse 24.8.
const a256ClickHouseImage = "clickhouse/clickhouse-server@sha256:1ffa82edee000a42c09313bd9f1293d94c570aee74babc1b3ca9983a35fa597b"

// pamClickHouse is the ClickHouse target: its container, its HTTP endpoint
// and its administrator's statements.
type pamClickHouse struct {
	ID, URL string
	admin   func(t *testing.T, statement string) string
}

// startPAMClickHouse runs the pinned ClickHouse with access management, a
// lab.notes table holding a note and a role reading it, and returns the
// target and a provider of per-session users in the "reader" role.
func startPAMClickHouse(t *testing.T, note string) (pamClickHouse, DynamicSecretProviderRegistry) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("the stock curl client is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a256ClickHouseImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a256ClickHouseImage, err, out)
	}
	id, addr := a201Container(t, "8123", "-e", "CLICKHOUSE_USER=lab_admin", "-e", "CLICKHOUSE_PASSWORD=a256-admin",
		"-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1", a256ClickHouseImage)
	ch := pamClickHouse{ID: id, URL: "http://" + addr + "/"}
	ch.admin = func(t *testing.T, statement string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ch.URL, strings.NewReader(statement))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("lab_admin", "a256-admin")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "unreachable: " + err.Error()
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "HTTP " + resp.Status + ": " + string(body)
		}
		return strings.TrimSpace(string(body))
	}
	a201Await(t, "ClickHouse", func() bool { return ch.admin(t, "SELECT 1") == "1" })
	for _, statement := range []string{"CREATE DATABASE lab", "CREATE TABLE lab.notes (id UInt32, note String) ENGINE = MergeTree ORDER BY id",
		"INSERT INTO lab.notes VALUES (1, '" + note + "')", "CREATE ROLE notes_reader", "GRANT SELECT ON lab.* TO notes_reader"} {
		if out := ch.admin(t, statement); out != "" {
			t.Fatalf("%s: %s", statement, out)
		}
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-clickhouse-provider", Type: "clickhouse", Endpoint: ch.URL, AdminUser: "lab_admin",
		PasswordRef:  writeServedCredentialFile(t, "clickhouse-admin-password", "a256-admin"),
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "notes_reader"},
		MaxTTL: "1h", UsernamePrefix: "a256_ch", AllowInsecureLoopback: true,
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ch, registry
}

var fixtureClickHouseCommand = regexp.MustCompile(`curl http://127\.0\.0\.1:(\d+)/`)

// clickhouseSessionUsers lists the per-session users the provider created.
func clickhouseSessionUsers(t *testing.T, ch pamClickHouse) []string {
	t.Helper()
	var users []string
	for _, line := range strings.Split(ch.admin(t, "SELECT name FROM system.users WHERE startsWith(name, 'a256_ch')"), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "a256_ch") {
			users = append(users, line)
		}
	}
	return users
}

// TestServedGatewayClickHouseSessionsA256: a ClickHouse target is served only
// through the access gateway, to stock curl on ClickHouse's HTTP interface
// with no credential. The gateway signs every request in as the session's
// own user; credentials a client sends are removed; the user's role scopes
// the session; the session is recorded masked, sealed and verifiable; an
// operator's termination closes a live connection and the gateway
// acknowledges it; the user is dropped.
func TestServedGatewayClickHouseSessionsA256(t *testing.T) {
	token := "ghp_a256ClickHouseSessionTok" + strings.Repeat("H", 12) // a GitHub token's shape: ghp_ and 36 characters
	f := startGatewayFixture(t, gatewayFixtureOptions{clickhouseNote: token})
	h := f.h

	session := f.open("a256-clickhouse", map[string]any{"target_type": "clickhouse", "target_id": "clickhouse-gw", "role": "reader", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil {
		t.Fatalf("the ClickHouse session was not delivered through its gateway: %+v", session)
	}
	tunnelOut, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, fixtureClickHouseCommand.MatchString)
	defer stopTunnel()
	local := "127.0.0.1:" + fixtureClickHouseCommand.FindStringSubmatch(tunnelOut)[1]
	users := clickhouseSessionUsers(t, f.clickhouse)
	if len(users) != 1 {
		t.Fatalf("session users = %v, want the session's one", users)
	}
	_, read := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for what, text := range map[string]string{"session read": string(read), "CLI output": tunnelOut} {
		if strings.Contains(text, users[0]) {
			t.Fatalf("the %s carries the session's credential: %s", what, text)
		}
	}
	curl := func(args ...string) string {
		cmd := exec.CommandContext(f.ctx, "curl", append([]string{"-sS", "http://" + local + "/"}, args...)...) // #nosec G204 G702 -- the stock curl against the test's own tunnel (CWE-78)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	if got := curl("--data-binary", "SELECT currentUser(), note FROM lab.notes"); got != users[0]+"\t"+token {
		t.Fatalf("a query through the gateway = %q (gateway: %s)", got, f.gatewayLog.String())
	}
	// A client's own credentials, as a header and as parameters, are
	// removed: the request still runs as the session's user.
	if got := curl("-u", "lab_admin:a256-admin", "--data-binary", "SELECT currentUser()"); got != users[0] {
		t.Fatalf("with a client's basic auth the request ran as %q", got)
	}
	if got := curl("-H", "X-ClickHouse-User: lab_admin", "-H", "X-ClickHouse-Key: a256-admin", "--data-binary", "SELECT currentUser()"); got != users[0] {
		t.Fatalf("with a client's ClickHouse headers the request ran as %q", got)
	}
	if got := curl("--get", "--data-urlencode", "user=lab_admin", "--data-urlencode", "password=a256-admin", "--data-urlencode", "query=SELECT currentUser()"); got != users[0] {
		t.Fatalf("with a client's user and password parameters the request ran as %q", got)
	}
	if got := curl("--data-binary", "INSERT INTO lab.notes VALUES (2, 'no')"); !strings.Contains(got, "Not enough privileges") {
		t.Fatalf("a write outside the session's role = %q", got)
	}

	// A live keep-alive connection, terminated.
	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, "GET /?query=SELECT%201 HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	replies := bufio.NewReader(conn)
	resp, err := http.ReadResponse(replies, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("a keep-alive request through the gateway = %v %v", resp, err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator,
		"a256-clickhouse-terminate", map[string]any{"reason": "a256 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := replies.ReadByte(); err == nil {
		t.Fatal("the terminated connection is still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the terminated connection was not closed")
	}
	a201Await(t, "the gateway acknowledges the termination", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "the session's user is dropped", func() bool { return len(clickhouseSessionUsers(t, f.clickhouse)) == 0 })

	// The recording.
	a201Await(t, "the ClickHouse recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	if strings.Contains(text, token) || strings.Contains(text, "a256-admin") {
		t.Fatalf("the ClickHouse recording kept a secret:\n%s", text)
	}
	for _, want := range []string{"request: POST / body=SELECT currentUser(), note FROM lab.notes", "[masked:github-token]",
		"request: POST / body=INSERT INTO lab.notes", "exception 497", "request: GET / query=SELECT currentUser()"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the ClickHouse recording lacks %q:\n%s", want, text)
		}
	}
}
