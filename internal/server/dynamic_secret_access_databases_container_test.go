// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/redisacl"
	"trstctl.com/trstctl/internal/store"
)

// TestServedLeaseAccessReadsMySQLMongoDBAndRedisG2L2 is G2-L2 for database
// logins, on the pinned MySQL 8.4, MongoDB 7.0 and Redis 8.2 images through
// providers configured as the binary configures them. Each lease links to the
// database or server its login reaches, with the grants the target itself
// reports for that login: MySQL's grants, MongoDB's roles, Redis's ACL rules
// (never its password hashes). Each answer is cross-checked against the
// target. A login the target no longer has is shown as unknown
// (login_missing), never as no grants.
func TestServedLeaseAccessReadsMySQLMongoDBAndRedisG2L2(t *testing.T) {
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

	_, mysqlAddr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=g2l2-admin", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	mysqlAdminDSN := "root:g2l2-admin@tcp(" + mysqlAddr + ")/app?parseTime=true"
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
	if err := os.WriteFile(filepath.Join(aclDir, "users.acl"), []byte("user default on >g2l2-admin ~* +@all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	redisID, redisAddr := a201Container(t, "6379", "--user", currentUID(t), "--mount", "type=bind,src="+aclDir+",dst=/acl",
		"--entrypoint", "redis-server", a201RedisImage, "--aclfile", "/acl/users.acl", "--save", "", "--appendonly", "no")
	a201Await(t, "Redis", func() bool {
		out, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "g2l2-admin", "PING")
		return err == nil && out == "PONG"
	})
	mongo := startLabMongo(t)
	mongoAdminURI := (&url.URL{Scheme: "mongodb", User: url.UserPassword("root", mongo.rootPassword), Host: mongo.addr, Path: "/orders",
		RawQuery: "authSource=admin&directConnection=true"}).String()

	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{
		{TenantID: servedTestTenant, ID: "mysql-g2l2", Type: "mysql",
			AdminDSNRef: writeServedCredentialFile(t, "g2l2-mysql-admin-dsn", mysqlAdminDSN+"\n"), Database: "app", Addr: mysqlAddr,
			AccountHost: "%", AllowWildcardAccountHost: true, AllowedRoles: []string{"mysql-reader"}, RoleAccess: map[string]string{"mysql-reader": "read"},
			MaxTTL: "1h", UsernamePrefix: "g2l2_mysql"},
		{TenantID: servedTestTenant, ID: "mongo-g2l2", Type: "mongodb",
			AdminDSNRef: writeServedCredentialFile(t, "g2l2-mongo-admin", mongoAdminURI), Database: "orders",
			AllowedRoles: []string{"mongo-reader"}, RoleAccess: map[string]string{"mongo-reader": "read"}, MaxTTL: "1h", UsernamePrefix: "g2l2_mongo"},
		{TenantID: servedTestTenant, ID: "redis-g2l2", Type: "redis", Addr: redisAddr,
			PasswordRef: writeServedCredentialFile(t, "g2l2-redis-admin-password", "g2l2-admin"), AllowPlaintextRedis: true,
			AllowedRoles:  []string{"redis-reader"},
			RedisACLRoles: map[string]redisacl.Role{"redis-reader": {KeyPrefixes: []string{"g2l2:"}, Commands: []string{"get"}}},
			MaxTTL:        "1h", UsernamePrefix: "g2l2_redis"},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
		d.DynamicSecretAccessInterval = time.Hour // the test drives each read itself
	})
	registerServedTenant(t, h, "G2-L2 lease access tenant")
	startServedExternalCADispatcher(t, h)
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "g2l2-issuer", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g2l2-graph-reader", "graph:read", "access:read")
	resolve := func() {
		t.Helper()
		if err := h.srv.ResolveDynamicSecretAccessOnce(ctx); err != nil {
			t.Fatalf("lease access pass: %v", err)
		}
	}

	mysqlLease, mysqlCredential := issueG2Lease(t, h, issuer, "g2l2-mysql-1", "mysql-g2l2", "mysql-reader")
	mongoLease, mongoCredential := issueG2Lease(t, h, issuer, "g2l2-mongo-1", "mongo-g2l2", "mongo-reader")
	redisLease, redisCredential := issueG2Lease(t, h, issuer, "g2l2-redis-1", "redis-g2l2", "redis-reader")
	resolve()
	g := readG2Graph(t, h, reader)

	// leaseNode checks one lease's access is resolved for its target.
	leaseNode := func(lease, provider, target string) g2GraphNode {
		t.Helper()
		n, ok := g.node("lease:" + lease)
		if !ok || n.Attrs["access_status"] != store.DynamicSecretAccessResolved || n.Attrs["login"] == "" || n.Attrs["target"] != target {
			t.Fatalf("%s lease node = %+v (present %v); want resolved access to %s", provider, n, ok, target)
		}
		return n
	}
	targetOf := func(kind, target string) string { return "res:" + kind + ":" + target }
	// linked checks the lease reaches its target, and the provider's backend
	// connects to it.
	linked := func(lease, provider, kind, target string) {
		t.Helper()
		node := targetOf(kind, target)
		res, ok := g.node(node)
		if !ok || res.Kind != "resource" || res.Attrs["resource_kind"] != "database" || res.Attrs["target_kind"] != kind ||
			!g.edge("lease:"+lease, node, "GRANTS_ACCESS") || !g.edge("res:dynamic-secret:"+provider, node, "CONNECTS_TO") {
			t.Fatalf("%s: no grants-access link from the lease to %s: %+v (present %v)", provider, node, res, ok)
		}
	}

	// MySQL: the lease user's grants, as information_schema states them.
	mysqlTarget := "mysql://" + mysqlAddr + "/app"
	my := leaseNode(mysqlLease, "mysql-g2l2", mysqlTarget)
	linked(mysqlLease, "mysql-g2l2", "mysql_database", mysqlTarget)
	if my.Attrs["grants"] != "SELECT on app.*" || my.Attrs["grant_count"] != "1" || !strings.HasPrefix(my.Attrs["login"], "g2l2_mysql") ||
		!strings.HasPrefix(mysqlCredential, my.Attrs["login"]+":") {
		t.Fatalf("MySQL lease = %+v; want SELECT on app.* for the lease's own user", my.Attrs)
	}
	admin, err := dynsecret.OpenMySQLExecutor(ctx, []byte(mysqlAdminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	var privileges []string
	rows, err := admin.QueryContext(ctx, "SELECT PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = ? AND TABLE_SCHEMA = 'app'",
		"'"+my.Attrs["login"]+"'@'%'")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		privileges = append(privileges, p)
	}
	_ = rows.Close()
	if strings.Join(privileges, ",") != "SELECT" {
		t.Fatalf("MySQL reports %v for the lease user; the graph says %q", privileges, my.Attrs["grants"])
	}

	// MongoDB: the lease user's roles, as getUser states them.
	mongoTarget := "mongodb://" + mongo.addr + "/orders"
	mg := leaseNode(mongoLease, "mongo-g2l2", mongoTarget)
	linked(mongoLease, "mongo-g2l2", "mongodb_database", mongoTarget)
	if mg.Attrs["grants"] != "role read on database orders" || !strings.Contains(mongoCredential, mg.Attrs["login"]) {
		t.Fatalf("MongoDB lease = %+v; want role read on database orders", mg.Attrs)
	}
	out, err := mongo.eval("JSON.stringify(db.getSiblingDB('orders').getUser('" + mg.Attrs["login"] + "').roles)")
	var roles []struct {
		Role string `json:"role"`
		DB   string `json:"db"`
	}
	if err != nil || json.Unmarshal([]byte(out), &roles) != nil || len(roles) != 1 || roles[0].Role != "read" || roles[0].DB != "orders" {
		t.Fatalf("MongoDB reports %s (%v) for the lease user; the graph says %q", out, err, mg.Attrs["grants"])
	}

	// Redis: the lease user's ACL rules, as ACL GETUSER states them.
	redisTarget := "redis://" + redisAddr
	rd := leaseNode(redisLease, "redis-g2l2", redisTarget)
	linked(redisLease, "redis-g2l2", "redis_server", redisTarget)
	for _, want := range []string{"flags on", "keys ~g2l2:*", "+get", "+ping"} {
		if !strings.Contains(rd.Attrs["grants"], want) {
			t.Fatalf("Redis lease grants %q lack %q", rd.Attrs["grants"], want)
		}
	}
	if strings.Contains(rd.Attrs["grants"], "passwords") || !strings.Contains(redisCredential, rd.Attrs["login"]) {
		t.Fatalf("Redis lease = %+v", rd.Attrs)
	}
	rules, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "g2l2-admin", "ACL", "GETUSER", rd.Attrs["login"])
	if err != nil || !strings.Contains(rules, "~g2l2:*") || !strings.Contains(rules, "+get") {
		t.Fatalf("Redis reports %q (%v) for the lease user; the graph says %q", rules, err, rd.Attrs["grants"])
	}

	// A login the target no longer has is unknown (login_missing), never none.
	if _, err := a201Exec(redisID, "redis-cli", "--no-auth-warning", "-a", "g2l2-admin", "ACL", "DELUSER", rd.Attrs["login"]); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(ctx,
		`UPDATE dynamic_secret_lease_access SET checked_at = checked_at - interval '7 hours', rechecked_at = NULL WHERE tenant_id = $1 AND lease_id = $2`,
		h.tenant, redisLease); err != nil {
		t.Fatal(err)
	}
	resolve()
	g = readG2Graph(t, h, reader)
	if n, _ := g.node("lease:" + redisLease); n.Attrs["access_status"] != store.DynamicSecretAccessUnknown || n.Attrs["grants"] != "unknown" ||
		n.Attrs["access_reason"] != "login_missing" || !g.edge("lease:"+redisLease, targetOf("redis_server", redisTarget), "GRANTS_ACCESS") {
		t.Fatalf("a Redis login the server no longer has = %+v; want unknown (login_missing), still linked", n.Attrs)
	}

	for _, leaked := range []string{"g2l2-admin", mongo.rootPassword, mysqlCredential, redisCredential, mongoCredential} {
		if h.logContains(t, leaked) {
			t.Fatal("a credential reached the event log")
		}
	}
	t.Logf("G2L2_OK mysql=%q mongo=%q redis=%q", my.Attrs["grants"], mg.Attrs["grants"], rd.Attrs["grants"])
}
