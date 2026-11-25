// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/redisacl"
)

func startPAMRedisPlaintext(t *testing.T) (string, DynamicSecretProviderRegistry) {
	t.Helper()
	if out, err := exec.Command("docker", "image", "inspect", a201RedisImage).CombinedOutput(); err != nil { // #nosec G204 -- fixed pinned fixture image (CWE-78)
		t.Skipf("the pinned Redis image is unavailable: %v %s", err, out)
	}
	aclDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(aclDir, "users.acl"), []byte("user default on >a256-admin ~* +@all\n"), 0o600); err != nil { // #nosec G703 -- fixed fixture file under t.TempDir (CWE-22)
		t.Fatal(err)
	}
	id, addr := a201Container(t, "6379", "--user", currentUID(t), "--mount", "type=bind,src="+aclDir+",dst=/acl",
		"--entrypoint", "redis-server", a201RedisImage, "--aclfile", "/acl/users.acl", "--save", "", "--appendonly", "no")
	a201Await(t, "legacy plaintext Redis", func() bool {
		out, err := a201Exec(id, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "PING")
		return err == nil && out == "PONG"
	})
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-redis-provider", Type: "redis", Addr: addr,
		PasswordRef: writeServedCredentialFile(t, "redis-admin-password", "a256-admin"), AllowPlaintextRedis: true,
		AllowedRoles: []string{"redis-writer"}, RedisACLRoles: map[string]redisacl.Role{
			"redis-writer": {KeyPrefixes: []string{"a256:"}, Commands: []string{"get", "set", "del"}}},
		MaxTTL: "1h", UsernamePrefix: "a256_redis",
	}}, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, registry
}

func TestCR039ServedRedisPlaintextProviderCannotIssueGatewayTicket(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{redis: true, redisPlaintext: true})
	req := map[string]any{"target_type": "redis", "target_id": "redis-gw", "role": "redis-writer", "ttl_seconds": 120,
		"reason": "verified gateway transport", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	servedPAMApproveOpen(t, f.h.servedHarness, f.requester, f.reviewerOne, f.reviewerTwo, "cr039-redis-plain", req)
	status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester,
		"cr039-redis-plain", req)
	if status != http.StatusForbidden || !strings.Contains(string(body), "verified TLS") {
		t.Fatalf("plaintext Redis provider issued a gateway ticket: status=%d ticket_present=%t", status,
			strings.Contains(string(body), `"ticket"`))
	}
	users, err := a201Exec(f.redisID, "redis-cli", "--no-auth-warning", "-a", "a256-admin", "ACL", "USERS")
	if err != nil || strings.Contains(users, "a256_redis") {
		t.Fatalf("refused Redis gateway session created an upstream ACL user: err=%v present=%t", err,
			strings.Contains(users, "a256_redis"))
	}
}
