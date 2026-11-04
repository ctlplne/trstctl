// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/redisacl"
)

// startPAMRedis runs the pinned Redis image with an administrator ACL and
// returns its container and a provider of per-session ACL users in the
// "redis-writer" role: keys under a256:, GET, SET and DEL.
func startPAMRedis(t *testing.T) (string, DynamicSecretProviderRegistry) {
	t.Helper()
	if out, err := exec.Command("docker", "image", "inspect", a201RedisImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a201RedisImage, err, out)
	}
	aclDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(aclDir, "users.acl"), []byte("user default on >a256-admin ~* +@all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, addr := a201Container(t, "6379", "--user", currentUID(t), "--mount", "type=bind,src="+aclDir+",dst=/acl",
		"--entrypoint", "redis-server", a201RedisImage, "--aclfile", "/acl/users.acl", "--save", "", "--appendonly", "no")
	a201Await(t, "Redis", func() bool {
		out, err := a201Exec(id, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "PING")
		return err == nil && out == "PONG"
	})
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-redis-provider", Type: "redis", Addr: addr,
		PasswordRef: writeServedCredentialFile(t, "redis-admin-password", "a256-admin"), AllowPlaintextRedis: true,
		AllowedRoles:  []string{"redis-writer"},
		RedisACLRoles: map[string]redisacl.Role{"redis-writer": {KeyPrefixes: []string{"a256:"}, Commands: []string{"get", "set", "del"}}},
		MaxTTL:        "1h", UsernamePrefix: "a256_redis",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, registry
}

var fixtureRedisCommand = regexp.MustCompile(`redis-cli -h 127\.0\.0\.1 -p (\d+)`)

// redisSessionUsers lists the per-session ACL users the provider created.
func redisSessionUsers(t *testing.T, redisID string) []string {
	t.Helper()
	out, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "ACL", "USERS")
	if err != nil {
		t.Fatalf("ACL USERS: %v %s", err, out)
	}
	var users []string
	for _, u := range strings.Fields(out) {
		if strings.HasPrefix(u, "a256_redis") {
			users = append(users, u)
		}
	}
	return users
}

// TestServedGatewayRedisSessionsA256: a Redis target is served only through
// the access gateway, to a stock redis-cli holding no credential. The gateway
// signs in as the session's own ACL user, whose ACL scopes the session; a
// command that would change the connection's login (AUTH, HELLO with AUTH,
// RESET) is refused in order and the connection keeps the session's user;
// the session is recorded masked, sealed and verifiable; an operator's
// termination closes a live connection and the gateway acknowledges it; the
// session's ACL user is removed. A Redis target without a gateway is refused.
func TestServedGatewayRedisSessionsA256(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{redis: true})
	h := f.h
	gatewayID := agentRowID(servedTestTenant, "role-agent")

	// A tenant registration: a Redis target names its gateway.
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a256-redis-direct", map[string]any{
		"id": "redis-direct", "target_type": "redis", "provider_id": "pam-redis-provider", "allowed_roles": []string{"redis-writer"}})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "only through an access gateway") {
		t.Fatalf("a Redis target without a gateway = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a256-redis-api", map[string]any{
		"id": "redis-api", "target_type": "redis", "provider_id": "pam-redis-provider", "allowed_roles": []string{"redis-writer"},
		"gateway_agent_id": gatewayID, "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register the Redis target = %d %s", status, body)
	}

	// A session on the registered target. redis-cli runs in the target's own
	// image and reaches the CLI tunnel on this host.
	session := f.open("a256-redis", map[string]any{"target_type": "redis", "target_id": "redis-api", "role": "redis-writer", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil || session.SSH != nil {
		t.Fatalf("the Redis session was not delivered through its gateway: %+v", session)
	}
	tunnelOut, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, fixtureRedisCommand.MatchString)
	defer stopTunnel()
	port := fixtureRedisCommand.FindStringSubmatch(tunnelOut)[1]
	cli := func(stdin string, args ...string) string {
		cmd := exec.CommandContext(f.ctx, "docker", append([]string{"exec", "-i", f.redisID, "redis-cli", "-h", "host.docker.internal", "-p", port}, args...)...) // #nosec G204 G702 -- the stock redis-cli against the test's own tunnel (CWE-78)
		cmd.Stdin = strings.NewReader(stdin)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	users := redisSessionUsers(t, f.redisID)
	if len(users) != 1 {
		t.Fatalf("session ACL users = %v, want the session's one", users)
	}
	sessionUser := users[0]
	_, read := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for what, text := range map[string]string{"session read": string(read), "CLI output": tunnelOut} {
		if strings.Contains(text, sessionUser) || strings.Contains(text, "redis://") {
			t.Fatalf("the %s carries the session's credential: %s", what, text)
		}
	}
	token := "ghp_a256RedisSessionToken" + strings.Repeat("A", 15) // a GitHub token's shape: ghp_ and 36 characters
	if got := cli("", "SET", "a256:note", token); got != "OK" {
		t.Fatalf("SET through the gateway = %q (gateway: %s)", got, f.gatewayLog.String())
	}
	if got := cli("", "GET", "a256:note"); got != token {
		t.Fatalf("GET through the gateway = %q", got)
	}
	// One connection: each login change is refused in its place, and the
	// connection is still the session's user — its keys read, others don't.
	// redis-cli prints a blank line after each error reply.
	var lines []string
	for _, line := range strings.Split(cli("AUTH default a256-admin\nGET a256:note\nRESET\nGET other:key\nHELLO 3 AUTH default a256-admin\nGET a256:note\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 6 || !strings.Contains(lines[0], "TRSTCTL-GATEWAY-REFUSED-AUTH") || lines[1] != token ||
		!strings.Contains(lines[2], "TRSTCTL-GATEWAY-REFUSED-RESET") || !strings.Contains(lines[3], "NOPERM") ||
		!strings.Contains(lines[4], "TRSTCTL-GATEWAY-REFUSED-HELLO") || lines[5] != token {
		t.Fatalf("login changes through the gateway answered:\n%s", strings.Join(lines, "\n"))
	}
	// Without the gateway the target admits no one with this client's
	// (absent) credential.
	if out, _ := a201Exec(f.redisID, "redis-cli", "GET", "a256:note"); !strings.Contains(out, "NOAUTH") {
		t.Fatalf("the target answered a client with no credential: %q", out)
	}

	// A live connection on the operator's own target, terminated.
	live := f.open("a256-redis-live", map[string]any{"target_type": "redis", "target_id": "redis-gw", "role": "redis-writer", "ttl_seconds": 120})
	liveOut, stopLive := f.connect(live.ID, live.Gateway.Ticket, fixtureRedisCommand.MatchString)
	defer stopLive()
	conn, err := net.Dial("tcp", "127.0.0.1:"+fixtureRedisCommand.FindStringSubmatch(liveOut)[1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	replies := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := replies.ReadString('\n'); err != nil || line != "+PONG\r\n" {
		t.Fatalf("PING through the gateway = %q %v", line, err)
	}
	if len(redisSessionUsers(t, f.redisID)) != 2 {
		t.Fatal("the live session has no ACL user of its own")
	}
	for _, id := range []string{session.ID, live.ID} {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/terminate", f.operator,
			"a256-terminate-"+id, map[string]any{"reason": "a256 proof"}); status != http.StatusAccepted {
			t.Fatalf("terminate %s = %d %s", id, status, body)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := replies.ReadString('\n'); err == nil {
		t.Fatal("the terminated connection is still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the terminated connection was not closed")
	}
	for _, id := range []string{session.ID, live.ID} {
		a201Await(t, "the gateway acknowledges terminating "+id, func() bool {
			end, _ := f.sessionRead(id)["gateway_end"].(map[string]any)
			return end != nil && end["ended"] == "recalled"
		})
	}
	a201Await(t, "the sessions' ACL users are removed", func() bool { return len(redisSessionUsers(t, f.redisID)) == 0 })

	// The recording: sealed, verified, masked, with each command, reply and
	// refusal.
	a201Await(t, "the Redis recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	if strings.Contains(text, token) || strings.Contains(text, "a256-admin") {
		t.Fatalf("the Redis recording kept a secret:\n%s", text)
	}
	for _, want := range []string{"command: SET a256:note [masked:github-token]", "status: OK", "command: GET a256:note", "bulk: [masked:github-token]",
		"refused: AUTH", "refused: RESET", "refused: HELLO", "command: GET other:key", "error: NOPERM"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the Redis recording lacks %q:\n%s", want, text)
		}
	}
}
