// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/redisacl"
)

// The MySQL and Redis builds the DoD census pins.
const (
	a201MySQLImage = "mysql:8.4@sha256:d36d39a64cd12a5c1cc9e6aa2bfb5f8d4c81a2f6586e0a04a9ae13939db02209"
	a201RedisImage = "redis:8.2-bookworm@sha256:14678cf7a021c8fef198403f2cf5f6d30492218156f41f03cdb79a4caafb8bd4"
)

// a201Container runs one image on a loopback port for the test and returns
// its container id and host address.
func a201Container(t *testing.T, port string, args ...string) (string, string) {
	t.Helper()
	run := append([]string{"run", "-d", "--rm", "-p", "127.0.0.1::" + port}, args...)
	out, err := exec.Command("docker", run...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })  // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	mapped, err := exec.Command("docker", "port", id, port+"/tcp").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	return id, strings.TrimSpace(strings.Split(string(mapped), "\n")[0])
}

// a201Exec runs a command inside a container and returns its output.
func a201Exec(id string, args ...string) (string, error) {
	out, err := exec.Command("docker", append([]string{"exec", id}, args...)...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	return strings.TrimSpace(string(out)), err
}

func a201Await(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become ready", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestServedDynamicLeaseRotationOnMySQLAndRedis is A201 on the pinned MySQL 8.4
// and Redis 8.2 images, through providers configured as the binary configures
// them. For each, the rotated secret carries a new lease of the requested TTL
// whose credential works, and the old lease's account is gone: MySQL's
// mysql.user no longer lists it and it cannot log in; Redis's ACL no longer
// lists it and AUTH with it is refused. The Redis proof runs the new lease
// check (AUTH + PING as the lease user).
func TestServedDynamicLeaseRotationOnMySQLAndRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	for _, image := range []string{a201MySQLImage, a201RedisImage} {
		if out, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Skipf("the pinned image %s is not present locally: %v\n%s", image, err, out)
		}
	}
	ctx := context.Background()

	_, mysqlAddr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=a201-admin", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	mysqlAdminDSN := "root:a201-admin@tcp(" + mysqlAddr + ")/app?parseTime=true"
	a201Await(t, "MySQL", func() bool {
		db, err := dynsecret.OpenMySQLExecutor(ctx, []byte(mysqlAdminDSN))
		if err != nil {
			return false
		}
		defer func() { _ = db.Close() }()
		var one int
		return db.QueryRowContext(ctx, "SELECT 1").Scan(&one) == nil
	})

	aclDir := t.TempDir()
	aclFile := filepath.Join(aclDir, "users.acl")
	if err := os.WriteFile(aclFile, []byte("user default on >a201-admin ~* +@all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	redisID, redisAddr := a201Container(t, "6379", "--user", currentUID(t), "--mount", "type=bind,src="+aclDir+",dst=/acl",
		"--entrypoint", "redis-server", a201RedisImage, "--aclfile", "/acl/users.acl", "--save", "", "--appendonly", "no")
	a201Await(t, "Redis", func() bool {
		out, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "a201-admin", "PING")
		return err == nil && out == "PONG"
	})

	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{
		{TenantID: servedTestTenant, ID: "mysql-leases", Type: "mysql",
			AdminDSNRef: writeServedCredentialFile(t, "mysql-admin-dsn", mysqlAdminDSN+"\n"), Database: "app", Addr: mysqlAddr,
			AccountHost: "%", AllowWildcardAccountHost: true, AllowedRoles: []string{"mysql-reader"}, MaxTTL: "1h", UsernamePrefix: "a201_mysql"},
		{TenantID: servedTestTenant, ID: "redis-leases", Type: "redis", Addr: redisAddr,
			PasswordRef: writeServedCredentialFile(t, "redis-admin-password", "a201-admin"), AllowPlaintextRedis: true,
			AllowedRoles:  []string{"redis-reader"},
			RedisACLRoles: map[string]redisacl.Role{"redis-reader": {KeyPrefixes: []string{"a201:"}, Commands: []string{"get"}}},
			MaxTTL:        "1h", UsernamePrefix: "a201_redis"},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "dynamic-lease rotation tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// MySQL.
	mysqlOut := runDynamicLeaseRotationJourney(t, h, tok, "mysql-leases", "mysql-reader", 600, 1200)
	checkDynamicLeaseRotationOutcome(t, mysqlOut, 1200, "connected")
	mysqlUser := func(credential string) string { return credential[:strings.IndexByte(credential, ':')] }
	admin, err := dynsecret.OpenMySQLExecutor(ctx, []byte(mysqlAdminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	accounts := func(user string) int {
		var n int
		if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE user = ?", user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if accounts(mysqlUser(mysqlOut.oldCredential)) != 0 || accounts(mysqlUser(mysqlOut.published)) != 1 {
		t.Fatalf("mysql.user: old account %d, new account %d; want 0 and 1",
			accounts(mysqlUser(mysqlOut.oldCredential)), accounts(mysqlUser(mysqlOut.published)))
	}
	if db, err := dynsecret.OpenMySQLExecutor(ctx, []byte(mysqlOut.published)); err != nil || db.PingContext(ctx) != nil {
		t.Fatalf("the published MySQL credential does not log in: %v", err)
	} else {
		_ = db.Close()
	}
	if db, err := dynsecret.OpenMySQLExecutor(ctx, []byte(mysqlOut.oldCredential)); err == nil {
		pingErr := db.PingContext(ctx)
		_ = db.Close()
		if pingErr == nil {
			t.Fatal("the old MySQL lease still logs in")
		}
	}

	// Redis.
	redisOut := runDynamicLeaseRotationJourney(t, h, tok, "redis-leases", "redis-reader", 600, 900)
	checkDynamicLeaseRotationOutcome(t, redisOut, 900, "authenticated")
	redisUserPass := func(credential string) (string, string) {
		userinfo := credential[strings.Index(credential, "://")+3 : strings.LastIndexByte(credential, '@')]
		user, pass, _ := strings.Cut(userinfo, ":")
		return user, pass
	}
	acl, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "a201-admin", "ACL", "USERS")
	if err != nil {
		t.Fatalf("ACL USERS: %v %s", err, acl)
	}
	oldUser, oldPass := redisUserPass(redisOut.oldCredential)
	newUser, newPass := redisUserPass(redisOut.published)
	if strings.Contains(acl, oldUser) || !strings.Contains(acl, newUser) {
		t.Fatalf("Redis ACL users %q: want %s gone and %s present", acl, oldUser, newUser)
	}
	if out, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "--user", newUser, "--pass", newPass, "PING"); err != nil || out != "PONG" {
		t.Fatalf("the published Redis credential: %v %q", err, out)
	}
	if out, _ := a201Exec(redisID, "redis-cli", "--no-auth-warning", "--user", oldUser, "--pass", oldPass, "PING"); out == "PONG" {
		t.Fatal("the old Redis lease still authenticates")
	}
	t.Logf("A201_MYSQL_REDIS_OK mysql=%s→%s redis=%s→%s", mysqlOut.old.ID, mysqlOut.new.ID, redisOut.old.ID, redisOut.new.ID)
}

func currentUID(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
