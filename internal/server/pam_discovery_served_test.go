// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// a260PostgresImage is the PostgreSQL build the DoD census pins for the
// secret integrations.
const a260PostgresImage = "postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"

type a260Account struct {
	ID         string            `json:"id"`
	ProviderID string            `json:"provider_id"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Privileges []string          `json:"privileges"`
	Disabled   bool              `json:"disabled"`
	Details    map[string]string `json:"details"`
	RemovedAt  *time.Time        `json:"removed_at"`
	Status     string            `json:"status"`
}

type a260Run struct {
	ID          string `json:"id"`
	ProviderID  string `json:"provider_id"`
	Status      string `json:"status"`
	Failure     string `json:"failure"`
	RequestedBy string `json:"requested_by"`
	Accounts    int    `json:"accounts"`
	Added       int    `json:"added"`
	Removed     int    `json:"removed"`
	Changed     int    `json:"changed"`
	Changes     []struct {
		Change  string      `json:"change"`
		Account a260Account `json:"account"`
	} `json:"changes"`
}

// TestServedPrivilegedAccountDiscoveryA260: discovery reads a PostgreSQL
// server, a MySQL server and a Linux host through their providers'
// administrator connections and stages their privileged accounts — and only
// those — with what makes each privileged. The scans change nothing on the
// targets: their account tables hash the same before and after. A re-scan
// after the targets change shows the accounts added, removed and changed;
// the scheduler scans an interval source when it is due and not before; an
// unreachable target fails its run without touching the staged accounts; and
// discovery is tenant-scoped.
func TestServedPrivilegedAccountDiscoveryA260(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	for _, image := range []string{a260PostgresImage, a201MySQLImage} {
		if out, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Skipf("the pinned image %s is not present locally: %v\n%s", image, err, out)
		}
	}

	// PostgreSQL: a superuser, a role maker, a member of pg_read_all_data, a
	// database owner that cannot log in, and a plain login.
	pgID, pgAddr := a201Container(t, "5432", "-e", "POSTGRES_PASSWORD=a260-pg-admin", a260PostgresImage)
	a256AwaitLog(t, pgID, "PostgreSQL init process complete")
	psql := func(sql string) string {
		t.Helper()
		var out string
		var err error
		for i := 0; i < 30; i++ {
			if out, err = a201Exec(pgID, "psql", "-U", "postgres", "-tAc", sql); err == nil {
				return out
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: %v %s", sql, err, out)
		return ""
	}
	psql("CREATE ROLE app_admin SUPERUSER LOGIN PASSWORD 'a260-app-admin'")
	psql("CREATE ROLE role_maker CREATEROLE LOGIN")
	psql("CREATE ROLE etl LOGIN")
	psql("GRANT pg_read_all_data TO etl")
	psql("CREATE ROLE reader LOGIN")
	psql("CREATE ROLE orders_owner NOLOGIN")
	psql("CREATE DATABASE orders OWNER orders_owner")
	pgTables := func() string {
		return psql("SELECT md5(string_agg(rolname || rolsuper || rolcreaterole || rolcreatedb || rolreplication || rolbypassrls || rolcanlogin || " +
			"coalesce(rolpassword, '') || coalesce(rolvaliduntil::text, ''), ',' ORDER BY rolname)) || " +
			"(SELECT md5(string_agg(roleid || ':' || member, ',' ORDER BY roleid, member)) FROM pg_auth_members) FROM pg_authid")
	}

	// MySQL: an administrator with every global privilege, a replication
	// account, an account with one dynamic administration privilege, and a
	// reader.
	myID, myAddr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=a260-root", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	a256AwaitLog(t, myID, "MySQL init process done")
	mysql := func(sql string) string {
		t.Helper()
		var out string
		var err error
		for i := 0; i < 30; i++ {
			if out, err = a201Exec(myID, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-uroot", "-pa260-root", "-N", "-e", sql); err == nil {
				return out
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: %v %s", sql, err, out)
		return ""
	}
	mysql("CREATE USER 'ops_admin'@'%' IDENTIFIED BY 'a260-ops'; GRANT ALL ON *.* TO 'ops_admin'@'%' WITH GRANT OPTION;" +
		"CREATE USER 'replicator'@'%' IDENTIFIED BY 'a260-repl'; GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'%';" +
		"CREATE USER 'tuner'@'%' IDENTIFIED BY 'a260-tuner'; GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO 'tuner'@'%';" +
		"CREATE USER 'reader'@'%' IDENTIFIED BY 'a260-reader'; GRANT SELECT ON app.* TO 'reader'@'%';")
	myTables := func() string {
		return mysql("SELECT MD5(GROUP_CONCAT(CONCAT_WS(':', User, Host, authentication_string, account_locked, password_expired, Super_priv, "+
			"Grant_priv, Create_user_priv, Repl_slave_priv) ORDER BY User, Host)) FROM mysql.user") + "/" +
			mysql("SELECT MD5(COALESCE(GROUP_CONCAT(CONCAT_WS(':', USER, HOST, PRIV) ORDER BY USER, HOST, PRIV), '')) FROM mysql.global_grants")
	}

	// A Linux host: root, a member of sudo, an account a sudoers.d rule names
	// for one command, keys for the sudo member, and plain accounts.
	adminKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := crypto.SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	lab := startLabSSHAccounts(t, adminPublic)
	hostShell := func(line string) {
		t.Helper()
		if out, err := lab.shell(line, nil); err != nil {
			t.Fatalf("%s: %v %s", line, err, out)
		}
	}
	const opsKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEONBEKOQaw/bt2mEQDmf9AQ68I5RY375vL/1Fe94Slh alice@lab"
	hostShell("printf 'root ALL=(ALL:ALL) ALL\\n%%sudo ALL=(ALL:ALL) ALL\\n@includedir /etc/sudoers.d\\n' > /etc/sudoers && chmod 0440 /etc/sudoers && " +
		"mkdir -p /etc/sudoers.d && printf 'orders-single ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\\n' > /etc/sudoers.d/deploy && " +
		"usermod -aG sudo orders-svc-a && mkdir -p /home/orders-svc-a/.ssh && echo '" + opsKey + "' > /home/orders-svc-a/.ssh/authorized_keys")
	hostTables := func() string {
		out, err := lab.shell("cat /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d/* /root/.ssh/authorized_keys "+
			"/home/*/.ssh/authorized_keys 2>/dev/null | sha256sum", nil)
		if err != nil {
			t.Fatalf("hash the host's account files: %v %s", err, out)
		}
		return out
	}
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	providers := []config.DynamicSecretProviderConfig{
		{TenantID: servedTestTenant, ID: "a260-pg", Type: "postgresql", Database: "postgres", Schema: "public", UsernamePrefix: "a260",
			AdminDSNRef:  writeServedCredentialFile(t, "a260-pg-dsn", "postgres://postgres:a260-pg-admin@"+pgAddr+"/postgres?sslmode=disable"),
			AllowedRoles: []string{"readonly"}, MaxTTL: "1h"},
		{TenantID: servedTestTenant, ID: "a260-mysql", Type: "mysql", Database: "app", Addr: myAddr, AccountHost: "%", AllowWildcardAccountHost: true,
			AdminDSNRef:  writeServedCredentialFile(t, "a260-mysql-dsn", "root:a260-root@tcp("+myAddr+")/app\n"),
			AllowedRoles: []string{"reader"}, MaxTTL: "1h", UsernamePrefix: "a260"},
		{TenantID: servedTestTenant, ID: "a260-host", Type: "unix", Addr: lab.addr, AdminUser: "root", HostKeyFingerprint: lab.fingerprint,
			PrivateKeyRef: writeServedCredentialFile(t, "a260-host-admin-key.pem", string(adminPEM)),
			AllowedRoles:  []string{"host/single"}, RoleBindings: map[string]string{"host/single": "orders-single"}, MaxTTL: "1h",
			AllowStaticRotation: true},
		{TenantID: servedTestTenant, ID: "a260-gone", Type: "postgresql", Database: "postgres", Schema: "public", UsernamePrefix: "a260",
			AdminDSNRef:  writeServedCredentialFile(t, "a260-gone-dsn", "postgres://postgres:x@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=2"),
			AllowedRoles: []string{"readonly"}, MaxTTL: "1h"},
	}
	secret.Wipe(adminPEM)
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a260-operator", "access:read", "access:targets.write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "a260-reader", "access:read")

	save := func(provider string, interval int) int {
		t.Helper()
		status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/"+provider, operator,
			"a260-save-"+provider+"-"+time.Now().Format("150405.000000"), map[string]any{"interval_seconds": interval})
		return status
	}
	scan := func(provider string) a260Run {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/"+provider+"/runs", operator,
			"a260-scan-"+provider+"-"+time.Now().Format("150405.000000"), nil)
		var run a260Run
		if status != http.StatusAccepted || json.Unmarshal(body, &run) != nil {
			t.Fatalf("scan %s = %d %s", provider, status, body)
		}
		return awaitQueuedDiscoveryProofA267(t, h.servedHarness, operator, run.ID)
	}
	accounts := func(provider string, removed bool) map[string]a260Account {
		t.Helper()
		path := "/api/v1/access/discovery/accounts?provider_id=" + provider
		if removed {
			path += "&include_removed=true"
		}
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, path, reader, nil)
		var page struct {
			Items []a260Account `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list accounts = %d %s", status, body)
		}
		out := map[string]a260Account{}
		for _, a := range page.Items {
			out[a.Name] = a
		}
		return out
	}
	privileges := func(found map[string]a260Account, want map[string]string) {
		t.Helper()
		for name, p := range want {
			if got := strings.Join(found[name].Privileges, " "); got != p {
				t.Fatalf("%s privileges = %q, want %q (all: %+v)", name, got, p, found)
			}
		}
	}

	// Sources: only a provider of a discoverable type in this tenant, an
	// interval of an hour at least, and only with access:targets.write.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260-pg", reader, "a260-reader-save",
		map[string]any{"interval_seconds": 0}); status != http.StatusForbidden {
		t.Fatalf("a reader saved a source: %d", status)
	}
	if status := save("no-such-provider", 0); status != http.StatusUnprocessableEntity && status != http.StatusBadRequest {
		t.Fatalf("an unknown provider was saved: %d", status)
	}
	if status := save("a260-pg", 600); status != http.StatusUnprocessableEntity && status != http.StatusBadRequest {
		t.Fatalf("a ten-minute interval was saved: %d", status)
	}
	for _, p := range []string{"a260-pg", "a260-mysql", "a260-host", "a260-gone"} {
		if status := save(p, 0); status != http.StatusOK {
			t.Fatalf("save source %s = %d", p, status)
		}
	}

	before := map[string]string{"pg": pgTables(), "mysql": myTables(), "host": hostTables()}
	pgRun, myRun, hostRun := scan("a260-pg"), scan("a260-mysql"), scan("a260-host")
	for _, run := range []a260Run{pgRun, myRun, hostRun} {
		if run.Status != "completed" || run.RequestedBy != "a260-operator" || run.Added != run.Accounts || run.Removed != 0 {
			t.Fatalf("first scan of %s = %+v", run.ProviderID, run)
		}
	}
	pg := accounts("a260-pg", false)
	privileges(pg, map[string]string{
		"app_admin":    "superuser",
		"role_maker":   "createrole",
		"etl":          "member:pg_read_all_data",
		"orders_owner": "owns_database:orders",
	})
	if _, ok := pg["reader"]; ok || !pg["orders_owner"].Disabled || pg["app_admin"].Disabled || !strings.Contains(strings.Join(pg["postgres"].Privileges, " "), "superuser") {
		t.Fatalf("PostgreSQL accounts = %+v", pg)
	}
	my := accounts("a260-mysql", false)
	privileges(my, map[string]string{"replicator@%": "repl_slave", "tuner@%": "system_variables_admin"})
	if p := strings.Join(my["ops_admin@%"].Privileges, " "); !strings.Contains(p, "grant") || !strings.Contains(p, "create_user") ||
		!strings.Contains(p, "system_user") {
		t.Fatalf("ops_admin privileges = %q", p)
	}
	if _, ok := my["reader@%"]; ok {
		t.Fatalf("the reader was staged as privileged: %+v", my)
	}
	host := accounts("a260-host", false)
	privileges(host, map[string]string{
		"root":          "authorized_keys:1 group:root sudo:ALL uid0",
		"orders-svc-a":  "authorized_keys:1 group:sudo sudo:ALL",
		"orders-single": "sudo:commands",
	})
	if _, ok := host["orders-svc-b"]; ok || host["orders-svc-a"].Details["authorized_keys"] != "ssh-ed25519 SHA256:ZUpKtGMGRETPHM0PB9T33QPyS819RJFBPoNlAV+BA3Q" {
		t.Fatalf("host accounts = %+v", host)
	}
	after := map[string]string{"pg": pgTables(), "mysql": myTables(), "host": hostTables()}
	for k := range before {
		if before[k] != after[k] {
			t.Fatalf("scanning changed the %s target's accounts: %s → %s", k, before[k], after[k])
		}
	}

	// The targets change; a re-scan shows what was added, removed and
	// changed.
	psql("CREATE ROLE new_admin SUPERUSER NOLOGIN")
	psql("DROP ROLE role_maker")
	psql("ALTER ROLE etl BYPASSRLS")
	mysql("DROP USER 'replicator'@'%'; CREATE USER 'new_ops'@'%' IDENTIFIED BY 'a260-new'; GRANT CREATE USER ON *.* TO 'new_ops'@'%';")
	hostShell("gpasswd -a orders-svc-b sudo >/dev/null && rm /etc/sudoers.d/deploy && " +
		"echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6UiOzCUKMXMPaGQ3pH7FQEjY4DgBzEvVSIgotafOnSo4ZQfbmLQDHFsQI8Z0jczvlg9mZiJL2AULsQD9dsQ+k= ops' >> /home/orders-svc-a/.ssh/authorized_keys")
	changes := func(run a260Run) []string {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+run.ID, reader, nil)
		var full a260Run
		if status != http.StatusOK || json.Unmarshal(body, &full) != nil {
			t.Fatalf("read run = %d %s", status, body)
		}
		var out []string
		for _, c := range full.Changes {
			out = append(out, c.Account.Name+" "+c.Change)
		}
		sort.Strings(out)
		return out
	}
	for provider, want := range map[string]string{
		"a260-pg":    "etl changed,new_admin added,role_maker removed",
		"a260-mysql": "new_ops@% added,replicator@% removed",
		"a260-host":  "orders-single removed,orders-svc-a changed,orders-svc-b added",
	} {
		run := scan(provider)
		if got := strings.Join(changes(run), ","); got != want {
			t.Fatalf("re-scan of %s changes = %s, want %s", provider, got, want)
		}
	}
	if _, ok := accounts("a260-pg", false)["role_maker"]; ok {
		t.Fatal("a removed role is still listed as staged")
	}
	if gone := accounts("a260-pg", true)["role_maker"]; gone.RemovedAt == nil {
		t.Fatalf("the removed role is not listed with include_removed: %+v", gone)
	}

	// An unreachable target fails its run with a class and stages nothing.
	if run := scan("a260-gone"); run.Status != "failed" || run.Failure != "unreachable" || run.Accounts != 0 {
		t.Fatalf("an unreachable source's run = %+v", run)
	}

	// The scheduler scans an interval source once it is due, and not again
	// before its interval.
	if status := save("a260-mysql", 3600); status != http.StatusOK {
		t.Fatalf("set an interval = %d", status)
	}
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE pam_discovery_runs SET finished_at = finished_at - interval '2 hours' WHERE provider_id = 'a260-mysql'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.pam.discoveryPass(context.Background())
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	runs := func() []a260Run {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs?provider_id=a260-mysql", reader, nil)
		var page struct {
			Items []a260Run `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list runs = %d %s", status, body)
		}
		return page.Items
	}
	listed := runs()
	if len(listed) != 3 || listed[0].RequestedBy != "scheduler" || listed[0].Status != "completed" || listed[0].Added+listed[0].Removed+listed[0].Changed != 0 {
		t.Fatalf("the due source was not scanned by the scheduler: %+v", listed)
	}
	h.srv.pam.discoveryPass(context.Background())
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	if again := runs(); len(again) != 3 {
		t.Fatalf("the scheduler scanned a source before its interval: %d runs", len(again))
	}

	// Another tenant sees none of it and cannot use this tenant's provider.
	otherTenant := "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: otherTenant, Name: "A260 foreign tenant"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, otherTenant, "a260-foreign", "access:read", "access:targets.write")
	for _, path := range []string{"/api/v1/access/discovery/sources", "/api/v1/access/discovery/runs", "/api/v1/access/discovery/accounts"} {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, path, foreign, nil)
		var page struct {
			Items []json.RawMessage `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 0 {
			t.Fatalf("the other tenant read %s: %d %s", path, status, body)
		}
	}
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+pgRun.ID, foreign, nil); status != http.StatusNotFound {
		t.Fatalf("the other tenant read a run: %d", status)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260-pg", foreign, "a260-foreign-save",
		map[string]any{"interval_seconds": 0}); status == http.StatusOK {
		t.Fatal("the other tenant saved a source on this tenant's provider")
	}
}
