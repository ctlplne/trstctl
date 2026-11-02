// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
