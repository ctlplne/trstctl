// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestServedCredentialHealthNeverLocksOutA258: the broker's MySQL account
// locks after two failed sign-ins (FAILED_LOGIN_ATTEMPTS 2), as a control
// account shows. Checked every two seconds, the account reads healthy; when
// its password changes at the server it reads rejected within one interval
// and stays so with one refused sign-in only, so it never locks; a new stored
// credential reads healthy within one interval; an expired password reads
// expired within one interval; repaired at the server with the stored
// credential unchanged, it stays failing until an operator checks it now.
func TestServedCredentialHealthNeverLocksOutA258(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a201MySQLImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a201MySQLImage, err, out)
	}
	id, addr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=a258-root", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	a256AwaitLog(t, id, "MySQL init process done")
	asUser := func(user, password, sql string) (string, error) {
		return a201Exec(id, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-u"+user, "-p"+password, "-N", "-e", sql)
	}
	a201Await(t, "MySQL", func() bool { _, err := asUser("root", "a258-root", "SELECT 1"); return err == nil })
	root := func(sql string) {
		t.Helper()
		if out, err := asUser("root", "a258-root", sql); err != nil {
			t.Fatalf("%s: %v %s", sql, err, out)
		}
	}
	const policy = " FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1"
	root("CREATE USER 'broker'@'%' IDENTIFIED BY 'first-password'" + policy + "; GRANT ALL ON *.* TO 'broker'@'%' WITH GRANT OPTION;" +
		"CREATE USER 'control'@'%' IDENTIFIED BY 'control-password'" + policy + ";")

	// The control: two refused sign-ins lock an account with this policy.
	for i := 0; i < 2; i++ {
		if _, err := asUser("control", "wrong", "SELECT 1"); err == nil {
			t.Fatal("a wrong password signed in")
		}
	}
	if out, err := asUser("control", "control-password", "SELECT 1"); err == nil || !strings.Contains(out, "3955") {
		t.Fatalf("the control account is not locked after two refused sign-ins: %v %s", err, out)
	}

	dsnRef := writeServedCredentialFile(t, "a258-broker-dsn", "broker:first-password@tcp("+addr+")/app\n")
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "a258-mysql", Type: "mysql", AdminDSNRef: dsnRef,
		Database: "app", Addr: addr, AccountHost: "%", AllowWildcardAccountHost: true,
		AllowedRoles: []string{"reader"}, MaxTTL: "1h", UsernamePrefix: "a258",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const interval = 2 * time.Second
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			HealthInterval: interval, Attestors: []attest.Attestor{servedPAMAttestor{}},
			DatabaseTargets: []PAMDatabaseTarget{{TargetType: "mysql", TenantID: servedTestTenant, ID: "orders-db", ProviderID: "a258-mysql",
				AllowedRoles: []string{"reader"}, GatewayAgentID: agentRowID(servedTestTenant, "role-agent"), GatewayAddress: "127.0.0.1:1"}}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.srv.RunPAMAccountHealth(ctx)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a258-operator", "access:read", "access:targets.write")

	type health struct {
		Status     string    `json:"status"`
		Attempts   int       `json:"attempts"`
		CheckedAt  time.Time `json:"checked_at"`
		NotRetried bool      `json:"not_retried"`
	}
	read := func() health {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/targets/mysql/orders-db", operator, nil)
		var target struct {
			Health *health `json:"health"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &target) != nil {
			t.Fatalf("read the target = %d %s", status, body)
		}
		if target.Health == nil {
			return health{}
		}
		return *target.Health
	}
	// within awaits a status no later than one interval (and the check's own
	// time) after since.
	within := func(what, want string, since time.Time) health {
		t.Helper()
		var got health
		a201Await(t, what, func() bool { got = read(); return got.Status == want && got.CheckedAt.After(since) })
		if late := got.CheckedAt.Sub(since); late > interval+3*time.Second {
			t.Fatalf("%s took %s, more than one %s interval", what, late, interval)
		}
		return got
	}
	refusedSignIns := func(since time.Time) int {
		t.Helper()
		n := 0
		if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
			var pl projections.PAMAccountHealthChecked
			if e.Type == projections.EventPAMAccountHealthChecked && e.TenantID == h.tenant && json.Unmarshal(e.Data, &pl) == nil &&
				pl.TargetID == "orders-db" && pl.CheckedAt.After(since) && pl.Status != "healthy" {
				n += pl.Attempts
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	a201Await(t, "the account reads healthy", func() bool { return read().Status == "healthy" })

	// The password changes at the server: rejected within one interval, then
	// no further sign-in with the refused credential.
	changed := time.Now()
	root("ALTER USER 'broker'@'%' IDENTIFIED BY 'second-password'")
	if got := within("the changed password reads rejected", "rejected", changed); !got.NotRetried || got.Attempts != 1 {
		t.Fatalf("rejected health = %+v", got)
	}
	time.Sleep(5 * interval)
	if got := read(); got.Status != "rejected" {
		t.Fatalf("after five more intervals the account reads %+v", got)
	}
	if n := refusedSignIns(changed); n != 1 {
		t.Fatalf("%d refused sign-ins were made with the unchanged credential, want 1", n)
	}
	if out, err := asUser("broker", "second-password", "SELECT 1"); err != nil {
		t.Fatalf("the checks locked the broker's account: %v %s", err, out)
	}

	// A new stored credential is checked at the next slot.
	stored := time.Now()
	if err := os.WriteFile(strings.TrimPrefix(dsnRef, "file:"), []byte("broker:second-password@tcp("+addr+")/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	within("the new stored credential reads healthy", "healthy", stored)

	// An expired password reads expired within one interval.
	expired := time.Now()
	root("ALTER USER 'broker'@'%' PASSWORD EXPIRE")
	within("the expired password reads expired", "expired", expired)

	// Repaired at the server with the stored credential unchanged: the
	// scheduled checks do not try the judged credential again; an operator's
	// check now does, once a minute at most.
	root("ALTER USER 'broker'@'%' IDENTIFIED BY 'second-password'")
	time.Sleep(3 * interval)
	if got := read(); got.Status != "expired" {
		t.Fatalf("a scheduled check retried the judged credential: %+v", got)
	}
	time.Sleep(time.Minute) // the operator's check is spaced from the last one
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets/mysql/orders-db/health-check", operator, "a258-check-now", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"healthy"`) {
		t.Fatalf("check now = %d %s", status, body)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets/mysql/orders-db/health-check", operator, "a258-check-again", nil); status == http.StatusOK {
		t.Fatal("a second check within a minute was made")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets/mysql/orders-db/health-check",
		seedScopedTokenSubject(t, h.store, h.tenant, "a258-reader", "access:read"), "a258-reader-check", nil); status != http.StatusForbidden {
		t.Fatalf("a reader checked an account now: %d", status)
	}
}
