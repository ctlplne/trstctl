// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sijms/go-ora/v2/network"
)

// fakeOracle records each PL/SQL block with its named binds and answers from
// fail, keyed by a statement fragment, popping one error per call.
type fakeOracle struct {
	calls []oracleCall
	fail  map[string][]error
}

type oracleCall struct {
	statement string
	binds     map[string]any
}

func (f *fakeOracle) ExecContext(_ context.Context, statement string, args ...any) (sql.Result, error) {
	call := oracleCall{statement: statement, binds: map[string]any{}}
	for _, arg := range args {
		named := arg.(sql.NamedArg)
		if raw, ok := named.Value.([]byte); ok {
			named.Value = string(raw)
		}
		call.binds[named.Name] = named.Value
	}
	f.calls = append(f.calls, call)
	for fragment, errs := range f.fail {
		if strings.Contains(statement, fragment) && len(errs) > 0 {
			f.fail[fragment] = errs[1:]
			if errs[0] != nil {
				return nil, errs[0]
			}
		}
	}
	return nil, nil
}

func newTestOracle(t *testing.T, fake *fakeOracle) *OracleBackend {
	t.Helper()
	b, err := NewOracleBackend(fake, OracleConfig{
		AdminDSN:         []byte("oracle://lab_admin:admin-password@127.0.0.1:1521/FREEPDB1?SSL=false\n"),
		RoleBindings:     map[string]string{"reader": "ORDERS_READER, AUDIT_READER"},
		RotationAccounts: map[string][2]string{"app": {"ORDERS_APP_A", "ORDERS_APP_B"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.retryWait = 0
	return b
}

// A239: a lease is an upper-case user created (or, on a retry, given the new
// password and unlocked) and granted exactly its role's Oracle roles; the
// password only ever travels as a bind, never in the PL/SQL text.
func TestOracleLeaseIsAUserGrantedOnlyItsRoles(t *testing.T) {
	fake := &fakeOracle{}
	b := newTestOracle(t, fake)
	ref, raw, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal(raw, &credential); err != nil || credential.Username != ref || len(credential.Password) != 30 {
		t.Fatalf("credential %s: %v", raw, err)
	}
	if ref != strings.ToUpper(ref) || !strings.HasPrefix(ref, "TRSTCTL_READER_") || !issuedPrincipalName("", ref) {
		t.Fatalf("user name = %q", ref)
	}
	if len(fake.calls) != 3 || fake.calls[0].statement != oracleUpsertUser {
		t.Fatalf("calls = %+v", fake.calls)
	}
	if fake.calls[0].binds["username"] != ref || fake.calls[0].binds["password"] != credential.Password {
		t.Fatalf("upsert binds = %v", fake.calls[0].binds)
	}
	for i, role := range []string{"ORDERS_READER", "AUDIT_READER"} {
		call := fake.calls[1+i]
		if call.statement != oracleGrantRole || call.binds["role"] != role || call.binds["username"] != ref {
			t.Fatalf("grant %d = %+v", i, call)
		}
	}
	for _, call := range fake.calls {
		if strings.Contains(call.statement, credential.Password) || strings.Contains(call.statement, ref) {
			t.Fatalf("a value reached the PL/SQL text: %q", call.statement)
		}
	}
	again, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-1"})
	if err != nil || again != ref {
		t.Fatalf("a retry of the same lease = %q, %v", again, err)
	}
}

// A239: a refused grant drops the new user again; errors name the ORA-
// number only.
func TestOracleFailedGrantDropsTheNewUser(t *testing.T) {
	fake := &fakeOracle{fail: map[string][]error{"'GRANT '": {nil, &network.OracleError{ErrCode: 1919, ErrMsg: "ORA-01919: role 'AUDIT_READER' does not exist"}}}}
	b := newTestOracle(t, fake)
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-2"})
	if err == nil || !strings.Contains(err.Error(), "ORA-01919") || strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
	if last := fake.calls[len(fake.calls)-1]; last.statement != oracleDropUser {
		t.Fatalf("the new user was not dropped: %+v", fake.calls)
	}
}

// A239: revocation locks the user, kills its sessions and drops it, waiting
// out ORA-01940 while a killed session goes; it drops only users this
// provider issued.
func TestOracleRevokeEndsSessionsThenDropsOnlyIssuedUsers(t *testing.T) {
	connected := &network.OracleError{ErrCode: oracleUserConnected, ErrMsg: "ORA-01940: cannot drop a user who is currently connected"}
	fake := &fakeOracle{fail: map[string][]error{"'DROP USER '": {connected, connected, nil}}}
	b := newTestOracle(t, fake)
	ref := "TRSTCTL_READER_ABB2116E09"
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 4 || fake.calls[0].statement != oracleEndSessions || fake.calls[0].binds["lock_account"] != 1 {
		t.Fatalf("calls = %+v", fake.calls)
	}
	for _, call := range fake.calls[1:] {
		if call.statement != oracleDropUser || call.binds["username"] != ref {
			t.Fatalf("drop = %+v", call)
		}
	}
	fake.calls = nil
	for _, ref := range []string{"SYSTEM", "ORDERS", "TRSTCTL_ADMIN", `TRSTCTL_READER" CASCADE`} {
		if err := b.Revoke(context.Background(), ref); err == nil {
			t.Errorf("revoked %q", ref)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("a refused revocation reached the database: %+v", fake.calls)
	}
}

// A240: a two-user rotation sets a new password on the account the
// predecessor does not name and retires the other with a password nobody
// holds, ending its sessions without locking or dropping it.
func TestOracleTwoUserRotationOnlyChangesPasswords(t *testing.T) {
	fake := &fakeOracle{}
	b := newTestOracle(t, fake)
	ref, raw, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "app", Static: true, Predecessor: "ORDERS_APP_A"})
	if err != nil || ref != "ORDERS_APP_B" {
		t.Fatalf("stage = %q, %v", ref, err)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal(raw, &credential); err != nil || credential.Username != "ORDERS_APP_B" {
		t.Fatalf("credential = %s", raw)
	}
	if len(fake.calls) != 1 || fake.calls[0].statement != oracleAlterUserIdentifiedBy || fake.calls[0].binds["password"] != credential.Password {
		t.Fatalf("stage calls = %+v", fake.calls)
	}
	fake.calls = nil
	if err := b.Revoke(context.Background(), "ORDERS_APP_A"); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0].statement != oracleAlterUserIdentifiedBy || fake.calls[1].statement != oracleEndSessions ||
		fake.calls[1].binds["lock_account"] != 0 || fake.calls[0].binds["password"] == credential.Password {
		t.Fatalf("retire calls = %+v", fake.calls)
	}
	for _, call := range fake.calls {
		if strings.Contains(call.statement, "DROP USER") || strings.Contains(call.statement, "CREATE USER") {
			t.Fatalf("a two-user retirement created or dropped a user: %q", call.statement)
		}
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", Static: true}); err == nil {
		t.Fatal("a static credential without rotation_accounts was accepted")
	}
}

// A239: the admin URL must name an address and a service; a bound role or a
// rotation account must be a plain Oracle name.
func TestOracleConfigRules(t *testing.T) {
	for name, cfg := range map[string]OracleConfig{
		"no scheme":       {AdminDSN: []byte("lab_admin/pw@127.0.0.1:1521/FREEPDB1"), RoleBindings: map[string]string{"reader": "ORDERS_READER"}},
		"no service":      {AdminDSN: []byte("oracle://lab_admin:pw@127.0.0.1:1521"), RoleBindings: map[string]string{"reader": "ORDERS_READER"}},
		"quoted role":     {AdminDSN: []byte("oracle://lab_admin:pw@127.0.0.1:1521/FREEPDB1"), RoleBindings: map[string]string{"reader": `ORDERS"READER`}},
		"one account":     {AdminDSN: []byte("oracle://lab_admin:pw@127.0.0.1:1521/FREEPDB1"), RotationAccounts: map[string][2]string{"app": {"ORDERS_APP_A", "ORDERS_APP_A"}}},
		"nothing to rent": {AdminDSN: []byte("oracle://lab_admin:pw@127.0.0.1:1521/FREEPDB1")},
	} {
		if _, err := NewOracleBackend(&fakeOracle{}, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewOracleBackend(nil, OracleConfig{}); err == nil {
		t.Fatal("no executor accepted")
	}
	if got := oracleErrorCode(errors.New("dial tcp 10.0.0.5:1521: refused")); got != "connection error" {
		t.Fatalf("got %q", got)
	}
}
