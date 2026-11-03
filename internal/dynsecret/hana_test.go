// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeHANA records each SQLScript block with its positional parameters and
// answers from fail, keyed by a statement fragment.
type fakeHANA struct {
	calls []hanaCall
	fail  map[string]error
}

type hanaCall struct {
	statement string
	args      []any
}

func (f *fakeHANA) ExecContext(_ context.Context, statement string, args ...any) (sql.Result, error) {
	call := hanaCall{statement: statement}
	for _, arg := range args {
		if raw, ok := arg.([]byte); ok {
			arg = string(raw)
		}
		call.args = append(call.args, arg)
	}
	f.calls = append(f.calls, call)
	for fragment, err := range f.fail {
		if strings.Contains(statement, fragment) {
			return nil, err
		}
	}
	return nil, nil
}

func newTestHANA(t *testing.T, fake *fakeHANA) *HANABackend {
	t.Helper()
	b, err := NewHANABackend(fake, HANAConfig{AdminDSN: []byte("hdb://LAB_ADMIN:admin@127.0.0.1:39041\n"),
		RoleBindings: map[string]string{"reader": "ORDERS_READER, AUDIT_READER"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A239: a lease is an upper-case user created (or, on a retry, given the new
// password and reactivated) and granted exactly its role's HANA roles; the
// password and the names only ever travel as parameters.
func TestHANALeaseIsAUserGrantedOnlyItsRolesA239(t *testing.T) {
	fake := &fakeHANA{}
	b := newTestHANA(t, fake)
	ref, raw, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal(raw, &credential); err != nil || credential.Username != ref || len(credential.Password) != 32 {
		t.Fatalf("credential %s: %v", raw, err)
	}
	if ref != strings.ToUpper(ref) || !strings.HasPrefix(ref, "TRSTCTL_READER_") || !issuedPrincipalName("", ref) {
		t.Fatalf("user name = %q", ref)
	}
	if len(fake.calls) != 3 || fake.calls[0].statement != hanaUpsertUser || fake.calls[0].args[0] != ref || fake.calls[0].args[1] != credential.Password {
		t.Fatalf("calls = %+v", fake.calls)
	}
	for i, role := range []string{"ORDERS_READER", "AUDIT_READER"} {
		call := fake.calls[1+i]
		if call.statement != hanaGrantRole || call.args[0] != role || call.args[1] != ref {
			t.Fatalf("grant %d = %+v", i, call)
		}
	}
	for _, call := range fake.calls {
		if strings.Contains(call.statement, credential.Password) || strings.Contains(call.statement, ref) {
			t.Fatalf("a value reached the SQLScript text: %q", call.statement)
		}
	}
	if !strings.Contains(hanaUpsertUser, "NO FORCE_FIRST_PASSWORD_CHANGE") || !strings.Contains(hanaUpsertUser, "DISABLE PASSWORD LIFETIME") {
		t.Fatal("a leased password could be forced to change or expire before the lease ends")
	}
}

// A239: a refused grant drops the new user again; revocation drops only a
// user this provider issued; errors name the HANA error code only.
func TestHANAFailedGrantAndRevocationA239(t *testing.T) {
	fake := &fakeHANA{fail: map[string]error{`'GRANT "'`: errors.New("SQL error 258 - insufficient privilege: Not authorized: CREATE USER \"X\" PASSWORD ...")}}
	b := newTestHANA(t, fake)
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-2"})
	if err == nil || strings.Contains(err.Error(), "PASSWORD") {
		t.Fatalf("err = %v", err)
	}
	if last := fake.calls[len(fake.calls)-1]; last.statement != hanaRevokeUser {
		t.Fatalf("the new user was not dropped: %+v", fake.calls)
	}
	fake = &fakeHANA{}
	b = newTestHANA(t, fake)
	if err := b.Revoke(context.Background(), "TRSTCTL_READER_ABB2116E09"); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 1 || fake.calls[0].statement != hanaRevokeUser || fake.calls[0].args[0] != "TRSTCTL_READER_ABB2116E09" {
		t.Fatalf("revoke = %+v", fake.calls)
	}
	for _, ref := range []string{"SYSTEM", "LAB_ADMIN", "TRSTCTL_ADMIN", `TRSTCTL_READER" CASCADE`} {
		if err := b.Revoke(context.Background(), ref); err == nil {
			t.Errorf("revoked %q", ref)
		}
	}
	if len(fake.calls) != 1 {
		t.Fatalf("a refused revocation reached the database: %+v", fake.calls)
	}
	for name, cfg := range map[string]HANAConfig{
		"no URL":      {RoleBindings: map[string]string{"reader": "ORDERS_READER"}},
		"wrong URL":   {AdminDSN: []byte("oracle://x:y@127.0.0.1:1521/FREE"), RoleBindings: map[string]string{"reader": "ORDERS_READER"}},
		"quoted role": {AdminDSN: []byte("hdb://x:y@127.0.0.1:39041"), RoleBindings: map[string]string{"reader": `ORDERS"READER`}},
		"no roles":    {AdminDSN: []byte("hdb://x:y@127.0.0.1:39041")},
	} {
		if _, err := NewHANABackend(&fakeHANA{}, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", Static: true}); err == nil {
		t.Fatal("a static credential was accepted")
	}
	if got := hanaErrorCode(errors.New("dial tcp 10.0.0.5:39041: refused")); got != "connection error" {
		t.Fatalf("got %q", got)
	}
}
