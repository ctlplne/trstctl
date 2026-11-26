// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/redisacl"
)

func TestCR597RedisPrefixEditRevokesRealACLUser(t *testing.T) {
	if testing.Short() {
		t.Skip("pinned Redis container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if _, err := exec.Command("docker", "image", "inspect", a201RedisImage).CombinedOutput(); err != nil { // #nosec G204 -- reads exact pinned fixture image only (CWE-78)
		t.Skip("the exact pinned Redis image is not cached")
	}
	aclDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(aclDir, "users.acl"), []byte("user default on >cr597-admin ~* +@all\n"), 0o600); err != nil { // #nosec G101 -- fabricated test administrator credential (CWE-798)
		t.Fatal(err)
	}
	id, addr := a201Container(t, "6379", "--user", currentUID(t), "--mount", "type=bind,src="+aclDir+",dst=/acl",
		"--entrypoint", "redis-server", a201RedisImage, "--aclfile", "/acl/users.acl", "--save", "", "--appendonly", "no")
	a201Await(t, "Redis", func() bool {
		out, err := a201Exec(id, "redis-cli", "--no-auth-warning", "-a", "cr597-admin", "PING")
		return err == nil && out == "PONG"
	})
	config := dynsecret.RedisConfig{Addr: addr, Password: []byte("cr597-admin"), UsernamePrefix: "earlier", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"cr597:"}, Commands: []string{"get"}}}}
	issued, err := dynsecret.NewRedisBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issued.Close)
	ref, credential, err := issued.Create(context.Background(), "reader")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	parts := strings.Split(ref, ":")
	if len(parts) != 4 || parts[0] != "v1" || !strings.HasPrefix(parts[3], "earlier_reader_") {
		t.Fatalf("Redis lease was not bound to its issuing prefix and target: %q", ref)
	}
	user := parts[3]
	users := func() string {
		t.Helper()
		out, err := a201Exec(id, "redis-cli", "--no-auth-warning", "-a", "cr597-admin", "ACL", "USERS")
		if err != nil {
			t.Fatalf("read Redis ACL users: %v", err)
		}
		return out
	}
	if !strings.Contains("\n"+users()+"\n", "\n"+user+"\n") {
		t.Fatal("issued ACL user was absent before prefix edit")
	}
	config.UsernamePrefix = "newer"
	current, err := dynsecret.NewRedisBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(current.Close)
	if err := current.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("revoke old Redis lease after prefix edit: %v", err)
	}
	if strings.Contains("\n"+users()+"\n", "\n"+user+"\n") {
		t.Fatal("old ACL user remains after reported revocation")
	}
}
