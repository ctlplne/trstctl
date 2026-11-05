// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A263 uses the existing SQL API stand-in's real RSA/JWT authentication and
// provider-created users. It does not qualify a live Snowflake account.
func TestServedGatewaySnowflakeSQLAPISessionsA263(t *testing.T) {
	admin, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	adminPEM, err := admin.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(adminPEM)
	knownToken := "ghp_" + strings.Repeat("Z", 36)
	sf, stand := newSnowflakeSQLAPIStandIn(t, admin.Public().DER, func(w http.ResponseWriter, r *http.Request, statement string) {
		if r.Header.Get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(statement, "DROP ") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"insufficient_privileges"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "090001", "data": [][]string{{knownToken}}})
	})
	admin.Destroy()
	adminFile := filepath.Join(t.TempDir(), "snowflake-admin.pem")
	if err := os.WriteFile(adminFile, adminPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(adminPEM)
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{TenantID: servedTestTenant, ID: "pam-snowflake-provider", Type: "snowflake", Endpoint: stand.URL, Account: "served-lab", AdminUser: "TRSTCTL_ADMIN", PrivateKeyRef: "file:" + adminFile, AllowedRoles: []string{"analyst"}, RoleBindings: map[string]string{"analyst": "ANALYST"}, MaxTTL: "1h", UsernamePrefix: "A263_SF", AllowInsecureLoopback: true}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := startGatewayFixture(t, gatewayFixtureOptions{snowflake: registry})
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-snowflake-direct", map[string]any{"id": "snowflake-direct", "target_type": "snowflake", "provider_id": "pam-snowflake-provider", "allowed_roles": []string{"analyst"}})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "only through an access gateway") {
		t.Fatalf("direct target = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-snowflake-register", map[string]any{"id": "snowflake-api", "target_type": "snowflake", "provider_id": "pam-snowflake-provider", "allowed_roles": []string{"analyst"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register gateway target = %d %s", status, body)
	}
	session := f.open("a263-snowflake", map[string]any{"target_type": "snowflake", "target_id": "snowflake-api", "role": "analyst", "ttl_seconds": 120})
	if session.Delivery != "gateway" || session.Gateway == nil || session.Postgres != nil || session.SSH != nil {
		t.Fatal("Snowflake did not use gateway custody")
	}
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a263-snowflake-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureClickHouseCommand.MatchString)
	defer stop()
	local := "127.0.0.1:" + fixtureClickHouseCommand.FindStringSubmatch(out)[1]
	sf.mu.Lock()
	var user, pub string
	for name, key := range sf.keys {
		if name != "TRSTCTL_ADMIN" {
			if user != "" {
				t.Fatal("more than one session user")
			}
			user, pub = name, key
		}
	}
	sf.mu.Unlock()
	if user == "" || pub == "" {
		t.Fatal("no actual issued key-pair user")
	}
	curl := func(path string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(f.ctx, "curl", append([]string{"--fail-with-body", "-sS", "http://" + local + path}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.dir, "TMPDIR=" + f.dir}
		data, err := cmd.CombinedOutput()
		return string(data), err
	} // #nosec G204 G702 -- stock curl against the test-owned gateway tunnel (CWE-78)
	if data, err := curl("/api/v2/statements", "-H", "Content-Type: application/json", "--data-binary", `{"statement":"SELECT CURRENT_ROLE()"}`); err != nil || !strings.Contains(data, "090001") {
		t.Fatalf("SQL API query = %v %s (gateway %s)", err, data, f.gatewayLog.String())
	}
	if data, err := curl("/api/v2/statements", "-H", "Authorization: Bearer client-auth-canary", "-H", "X-Snowflake-Authorization-Token-Type: OAUTH", "--data-binary", `{"statement":"SELECT 1"}`); err != nil || !strings.Contains(data, "090001") {
		t.Fatalf("client authentication replaced session = %v %s", err, data)
	}
	if _, err := curl("/session/v1/login-request"); err == nil {
		t.Fatal("non-SQL login endpoint reached target")
	}
	if _, err := curl("/api/v2/statements", "--data-binary", `{"statement":"DROP DATABASE forbidden"}`); err == nil {
		t.Fatal("stand-in allowed SQL outside its granted role")
	}
	direct, err := http.Post(stand.URL+"/api/v2/statements", "application/json", strings.NewReader(`{"statement":"SELECT 1"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = direct.Body.Close()
	if direct.StatusCode != http.StatusUnauthorized {
		t.Fatal("direct target admitted an unauthenticated client")
	}
	deniedReq := map[string]any{"target_type": "snowflake", "target_id": "snowflake-api", "role": "ACCOUNTADMIN", "ttl_seconds": 60, "reason": "negative proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-snowflake-denied-role", deniedReq); status != http.StatusUnprocessableEntity {
		t.Fatalf("unauthorized role = %d %s", status, body)
	}
	otherID := uuid.NewString()
	registerServedTenantID(t, f.h.servedHarness, otherID, "A263 other tenant")
	other := seedScopedTokenSubject(t, f.h.store, otherID, "other-user", "access:read", "access:write")
	if status, _ := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, other, nil); status != http.StatusNotFound {
		t.Fatal("another tenant read Snowflake session")
	}
	refusedTicket := func(id, ticket string) {
		t.Helper()
		peer, err := mtls.GatewayDial(f.ctx, session.Gateway.Address, []byte(session.Gateway.CAPEM), session.Gateway.SPIFFEID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = peer.Close() }()
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprintf(peer, "TRSTCTL-GATEWAY/1 %s %s\n", id, ticket)
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(peer).ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "DENY ") {
			t.Fatal("invalid or ended Snowflake ticket admitted")
		}
	}
	refusedTicket(session.ID, "a263-wrong-session-ticket")
	files, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), pub) || strings.Contains(string(data), user) {
			t.Fatal("Snowflake sign-in material reached client files")
		}
	}
	// Its public key exists only in the independently observed target, never in
	// operator-facing session metadata or the credential-free CLI output.
	_, read := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	der, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{out, string(read), f.gatewayLog.String()} {
		for _, bad := range []string{user, "PRIVATE KEY", pub, base64.StdEncoding.EncodeToString(der)} {
			if strings.Contains(text, bad) {
				t.Fatal("session credential escaped gateway custody")
			}
		}
	}
	// The wrong ticket is refused while the same session is live; after
	// successful termination that exact formerly valid ticket is also refused.
	// A keep-alive SQL API session is closed by the same live termination job.
	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, "GET /api/v2/statements/owned-handle HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	replies := bufio.NewReader(conn)
	response, err := http.ReadResponse(replies, nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("keep-alive SQL API = %v %v", response, err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a263-snowflake-terminate", map[string]any{"reason": "A263 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	if _, err := replies.ReadByte(); err == nil {
		t.Fatal("terminated SQL API connection remains open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("termination did not close connection")
	}
	a201Await(t, "Snowflake user dropped", func() bool { sf.mu.Lock(); defer sf.mu.Unlock(); _, exists := sf.keys[user]; return !exists })
	refusedTicket(session.ID, session.Gateway.Ticket)
	a201Await(t, "Snowflake gateway recalled", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "Snowflake recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("recording verify = %d %s", status, body)
	}
	recording := recordingText(t, f.h, session.ID)
	for _, bad := range []string{"PRIVATE KEY", "client-auth-canary", pub, knownToken} {
		if strings.Contains(recording, bad) {
			t.Fatal("Snowflake recording retained sign-in material")
		}
	}
	for _, want := range []string{"snowflake", "SELECT CURRENT_ROLE()", "090001", "[masked:github-token]"} {
		if !strings.Contains(recording, want) {
			t.Fatalf("recording lacks %q", want)
		}
	}
	expired := f.open("a263-snowflake-expiry", map[string]any{"target_type": "snowflake", "target_id": "snowflake-api", "role": "analyst", "ttl_seconds": 5})
	a201Await(t, "Snowflake exact session expires", func() bool {
		state := f.sessionRead(expired.ID)
		status, _ := state["status"].(string)
		return status == "expired"
	})
	refusedTicket(expired.ID, expired.Gateway.Ticket)
	a201Await(t, "expired Snowflake users removed", func() bool {
		sf.mu.Lock()
		defer sf.mu.Unlock()
		return len(sf.keys) == 1 && sf.keys["TRSTCTL_ADMIN"] != ""
	})

}
