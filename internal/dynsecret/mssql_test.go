// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	mssql "github.com/microsoft/go-mssqldb"
)

type mssqlCall struct {
	query string
	args  map[string]any
}

// recordingMSSQL records each statement with its named arguments; failOn makes
// a statement containing it fail with a SQL Server error whose message quotes
// statement text, as a real syntax error would.
type recordingMSSQL struct {
	calls  []mssqlCall
	failOn string
}

func (r *recordingMSSQL) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	call := mssqlCall{query: query, args: map[string]any{}}
	for _, arg := range args {
		named := arg.(sql.NamedArg)
		if raw, ok := named.Value.([]byte); ok {
			// The provider wipes the password after the call returns.
			named.Value = append([]byte(nil), raw...)
		}
		call.args[named.Name] = named.Value
	}
	r.calls = append(r.calls, call)
	if r.failOn != "" && strings.Contains(fmtArgs(call), r.failOn) {
		return nil, mssql.Error{Number: 15151, Message: "Incorrect syntax near 'Secret-Statement-Text'"}
	}
	return nil, nil
}

func fmtArgs(c mssqlCall) string {
	var b strings.Builder
	b.WriteString(c.query)
	for k, v := range c.args {
		b.WriteString(" " + k + "=")
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
	}
	return b.String()
}

func TestMSSQLLoginLeaseStatementsA239(t *testing.T) {
	exec := &recordingMSSQL{}
	b, err := NewMSSQLBackend(exec, MSSQLConfig{Database: "orders", RoleBindings: map[string]string{"reader": "db_datareader, report_reader"}})
	if err != nil {
		t.Fatal(err)
	}
	user, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-0001"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Username, Password, Database string }
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || got.Database != "orders" || len(got.Password) != 32 {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	if len(exec.calls) != 4 {
		t.Fatalf("statements %d, want login, user and two roles", len(exec.calls))
	}
	login := exec.calls[0]
	if login.query != mssqlUpsertLogin || login.args["login"] != user || login.args["db"] != "orders" ||
		!bytes.Equal(login.args["password"].([]byte), []byte(got.Password)) {
		t.Fatalf("login statement %+v", login)
	}
	for i, call := range exec.calls {
		if strings.Contains(call.query, got.Password) {
			t.Fatalf("statement %d carries the password in its text", i)
		}
		if i > 0 && !strings.HasPrefix(call.query, "EXEC [orders].sys.sp_executesql @statement, N'@login sysname") {
			t.Fatalf("statement %d does not run in the database: %q", i, call.query)
		}
	}
	if exec.calls[1].args["statement"] != mssqlEnsureUser || exec.calls[2].args["role"] != "db_datareader" || exec.calls[3].args["role"] != "report_reader" ||
		exec.calls[2].query != "EXEC [orders].sys.sp_executesql @statement, N'@login sysname, @role sysname', @login = @login, @role = @role" {
		t.Fatalf("user and role statements %+v", exec.calls[1:])
	}
	exec.calls = nil
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 3 || exec.calls[0].query != mssqlEndSessions || exec.calls[0].args["contained"] != 0 ||
		exec.calls[1].args["statement"] != mssqlDropUser || exec.calls[2].query != mssqlDropLogin {
		t.Fatalf("revocation statements %+v", exec.calls)
	}
	for _, foreign := range []string{"sa", "app_reader", "trstctl/../x", "trstctl]; DROP LOGIN sa; --"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("revoked %q, a principal this provider did not create", foreign)
		}
	}
}

func TestMSSQLContainedUserAndCleanupA239(t *testing.T) {
	exec := &recordingMSSQL{}
	b, err := NewMSSQLBackend(exec, MSSQLConfig{Contained: true, Database: "orders-db", RoleBindings: map[string]string{"reader": "db_datareader", "broken": "no_such_role"}})
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-0002"})
	if err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 2 || exec.calls[0].args["statement"] != mssqlUpsertContainedUser ||
		exec.calls[0].query != "EXEC [orders-db].sys.sp_executesql @statement, N'@login sysname, @password varbinary(256)', @login = @login, @password = @password" {
		t.Fatalf("contained statements %+v", exec.calls)
	}
	exec.calls = nil
	if err := b.Revoke(context.Background(), user); err != nil || len(exec.calls) != 2 || exec.calls[0].args["contained"] != 1 {
		t.Fatalf("contained revocation %v %+v", err, exec.calls)
	}
	// A failed membership removes the new principal again, and the error names
	// only the SQL Server error number, never the driver's message.
	exec.calls, exec.failOn = nil, "no_such_role"
	_, _, err = b.CreateCredential(context.Background(), GenerateRequest{Role: "broken", LeaseID: "lease-0003"})
	if err == nil || !strings.Contains(err.Error(), "SQL Server error 15151") || strings.Contains(err.Error(), "Secret-Statement-Text") {
		t.Fatalf("failed membership: %v", err)
	}
	if last := exec.calls[len(exec.calls)-1]; last.args["statement"] != mssqlDropUser {
		t.Fatalf("the new user was not dropped after the failed membership: %+v", exec.calls)
	}
	if got := mssqlErrorNumber(errors.New("dial tcp 10.0.0.5:1433: password=hunter2")); got != "connection error" {
		t.Fatalf("a non-server error leaked: %q", got)
	}
}

func TestMSSQLConfigAndPasswordA239(t *testing.T) {
	for name, cfg := range map[string]MSSQLConfig{
		"no database":   {RoleBindings: map[string]string{"r": "db_datareader"}},
		"bad database":  {Database: "orders]; --", RoleBindings: map[string]string{"r": "db_datareader"}},
		"no roles":      {Database: "orders"},
		"bad role name": {Database: "orders", RoleBindings: map[string]string{"r": "db_datareader]; --"}},
	} {
		if _, err := NewMSSQLBackend(&recordingMSSQL{}, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewMSSQLBackend(nil, MSSQLConfig{Database: "orders", RoleBindings: map[string]string{"r": "db_datareader"}}); err == nil {
		t.Error("accepted a nil executor")
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := randomPolicyPassword(32)
		if err != nil {
			t.Fatal(err)
		}
		var upper, lower, digit bool
		for _, c := range pw {
			upper = upper || (c >= 'A' && c <= 'Z')
			lower = lower || (c >= 'a' && c <= 'z')
			digit = digit || (c >= '2' && c <= '9')
			if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", rune(c)) {
				t.Fatalf("character %q outside the alphabet", c)
			}
		}
		if len(pw) != 32 || !upper || !lower || !digit || seen[string(pw)] {
			t.Fatalf("password %q", pw)
		}
		seen[string(pw)] = true
	}
}

// A240: a two-user rotation sets a new password on the login the
// predecessor does not name and retires the other with a password nobody
// holds, killing its sessions; nothing is created, disabled or dropped, so
// both keep their role memberships. Contained users do the same inside the
// database.
func TestMSSQLTwoUserRotationOnlyChangesPasswordsA240(t *testing.T) {
	for _, contained := range []bool{false, true} {
		exec := &recordingMSSQL{}
		b, err := NewMSSQLBackend(exec, MSSQLConfig{Contained: contained, Database: "orders",
			RotationAccounts: map[string][2]string{"app": {"orders_app_a", "orders_app_b"}},
			AdminDSN:         []byte("sqlserver://sa:admin@127.0.0.1:1433?database=master&encrypt=true\n")})
		if err != nil {
			t.Fatal(err)
		}
		ref, raw, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "app", Static: true, Predecessor: "orders_app_a"})
		if err != nil || ref != "orders_app_b" {
			t.Fatalf("contained=%v stage = %q, %v", contained, ref, err)
		}
		var credential struct{ Username, Password, Database string }
		if err := json.Unmarshal(raw, &credential); err != nil || credential.Username != "orders_app_b" || credential.Database != "orders" || len(credential.Password) != 32 {
			t.Fatalf("contained=%v credential = %s", contained, raw)
		}
		if len(exec.calls) != 1 || exec.calls[0].args["login"] != "orders_app_b" || string(exec.calls[0].args["password"].([]byte)) != credential.Password {
			t.Fatalf("contained=%v stage calls = %+v", contained, exec.calls)
		}
		if strings.Contains(exec.calls[0].query, credential.Password) {
			t.Fatal("the password reached the statement text")
		}
		wantAlter := "N'ALTER LOGIN '"
		if contained {
			wantAlter = "N'ALTER USER '"
		}
		if !strings.Contains(fmtArgs(exec.calls[0]), wantAlter) {
			t.Fatalf("contained=%v stage ran %q", contained, exec.calls[0].query)
		}
		exec.calls = nil
		if err := b.Revoke(context.Background(), "orders_app_a"); err != nil {
			t.Fatal(err)
		}
		if len(exec.calls) != 2 || exec.calls[1].query != mssqlKillSessions || exec.calls[0].args["login"] != "orders_app_a" ||
			string(exec.calls[0].args["password"].([]byte)) == credential.Password {
			t.Fatalf("contained=%v retire calls = %+v", contained, exec.calls)
		}
		for _, call := range exec.calls {
			for _, verb := range []string{"DROP ", "CREATE ", "DISABLE"} {
				if strings.Contains(fmtArgs(call), verb) {
					t.Fatalf("contained=%v a two-user retirement ran %s: %q", contained, verb, call.query)
				}
			}
		}
	}
	if _, err := NewMSSQLBackend(&recordingMSSQL{}, MSSQLConfig{Database: "orders",
		RotationAccounts: map[string][2]string{"app": {"orders_app_a", "orders_app_a"}}}); err == nil {
		t.Fatal("one account named twice was accepted")
	}
	b, err := NewMSSQLBackend(&recordingMSSQL{}, MSSQLConfig{Database: "orders", RoleBindings: map[string]string{"reader": "db_datareader"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", Static: true}); err == nil {
		t.Fatal("a static credential without rotation_accounts was accepted")
	}
	if err := b.VerifyCredential(context.Background(), []byte(`{"username":"x","password":"y"}`)); !errors.Is(err, ErrNoSelfProof) {
		t.Fatalf("verify without an admin DSN = %v", err)
	}
}

// A240: every SQL Server connection the provider opens carries dial and
// connection timeouts, so an unresponsive server fails the attempt instead of
// holding an outbox worker (CI 41578461348); an operator's own values stay.
func TestMSSQLConnectionsAreBoundedA240(t *testing.T) {
	for raw, want := range map[string][2]string{
		"sqlserver://admin:pw@db.internal:1433?database=orders":                                      {"10", "15"},
		"sqlserver://admin:pw@db.internal:1433?database=orders&dial+timeout=3&connection+timeout=60": {"3", "60"},
		"sqlserver://admin:pw@db.internal:1433?connection+timeout=5":                                 {"10", "5"},
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		mssqlBoundConnection(target)
		query := target.Query()
		if query.Get("dial timeout") != want[0] || query.Get("connection timeout") != want[1] || (strings.Contains(raw, "database") && query.Get("database") != "orders") {
			t.Errorf("%s -> %s", raw, target.Redacted())
		}
	}
	b, err := NewMSSQLBackend(&recordingMSSQL{}, MSSQLConfig{Database: "orders", AdminDSN: []byte("sqlserver://admin:pw@db.internal:1433?database=orders"), RoleBindings: map[string]string{"reader": "db_datareader"}})
	if err != nil {
		t.Fatal(err)
	}
	if query := b.verifyURL.Query(); query.Get("connection timeout") != "15" || query.Get("dial timeout") != "10" {
		t.Fatalf("the verification URL is unbounded: %s", b.verifyURL.Redacted())
	}
}
