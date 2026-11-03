// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// fakeCassandra records each statement and answers from fail, keyed by a
// statement prefix.
type fakeCassandra struct {
	statements []string
	fail       map[string]error
	closed     int
}

func (f *fakeCassandra) Exec(_ context.Context, statement string) error {
	f.statements = append(f.statements, statement)
	for prefix, err := range f.fail {
		if strings.HasPrefix(statement, prefix) {
			return err
		}
	}
	return nil
}

func (f *fakeCassandra) Close() { f.closed++ }

// cassandraRequestError is a server error frame as gocql reports it.
type cassandraRequestError struct {
	code    int
	message string
}

func (e cassandraRequestError) Code() int       { return e.code }
func (e cassandraRequestError) Message() string { return e.message }
func (e cassandraRequestError) Error() string   { return e.message }

func newTestCassandra(t *testing.T, fake *fakeCassandra) *CassandraBackend {
	t.Helper()
	b, err := NewCassandraBackend(CassandraConfig{Addr: "127.0.0.1:9042", AllowPlaintext: true, AdminUser: "lab_admin",
		AdminPassword: []byte("admin-password"), RoleBindings: map[string]string{"reader": "orders_reader, audit_reader"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	b.connect = func(context.Context) (cassandraAdmin, error) { return fake, nil }
	return b
}

var cassandraHashedPassword = regexp.MustCompile(`HASHED PASSWORD = '(\$2a\$10\$[./A-Za-z0-9]{53})'`)

// A239: a lease is a login role created (or, on a retry, given the new
// password) with only the password's bcrypt hash in CQL, then granted exactly
// its role's Cassandra roles; the credential's password matches that hash.
func TestCassandraLeaseIsAHashedLoginRoleWithOnlyItsRoles(t *testing.T) {
	fake := &fakeCassandra{}
	b := newTestCassandra(t, fake)
	ref, raw, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct{ Username, Password string }
	if err := json.Unmarshal(raw, &credential); err != nil || credential.Username != ref || len(credential.Password) != 32 {
		t.Fatalf("credential %s: %v", raw, err)
	}
	if !issuedPrincipalName("", ref) {
		t.Fatalf("role name %q is not an issued name", ref)
	}
	if len(fake.statements) != 4 {
		t.Fatalf("statements = %q", fake.statements)
	}
	quoted := `"` + ref + `"`
	for i, want := range []string{"CREATE ROLE IF NOT EXISTS " + quoted + " WITH HASHED PASSWORD = '", "ALTER ROLE " + quoted + " WITH HASHED PASSWORD = '"} {
		statement := fake.statements[i]
		if !strings.HasPrefix(statement, want) || strings.Contains(statement, credential.Password) {
			t.Fatalf("statement %d = %q", i, statement)
		}
		m := cassandraHashedPassword.FindStringSubmatch(statement)
		if m == nil || !crypto.VerifyBcrypt([]byte(m[1]), []byte(credential.Password)) {
			t.Fatalf("statement %d does not carry the password's bcrypt hash: %q", i, statement)
		}
	}
	if !strings.HasSuffix(fake.statements[0], "AND LOGIN = true AND SUPERUSER = false") {
		t.Fatalf("create = %q", fake.statements[0])
	}
	if fake.statements[2] != `GRANT "orders_reader" TO `+quoted || fake.statements[3] != `GRANT "audit_reader" TO `+quoted {
		t.Fatalf("grants = %q", fake.statements[2:])
	}
	if fake.closed != 1 {
		t.Fatalf("admin sessions closed = %d", fake.closed)
	}

	// The retry of an uncertain issue meets the grant it already made.
	retry := &fakeCassandra{fail: map[string]error{"GRANT": cassandraRequestError{code: gocql.ErrCodeInvalid, message: ref + " is a member of orders_reader"}}}
	b.connect = func(context.Context) (cassandraAdmin, error) { return retry, nil }
	again, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-1"})
	if err != nil || again != ref {
		t.Fatalf("retry = %q, %v", again, err)
	}
}

// A239: a grant the node refuses drops the new role again, and the error
// carries Cassandra's code, not its message (which can quote CQL).
func TestCassandraFailedGrantDropsTheNewRole(t *testing.T) {
	fake := &fakeCassandra{fail: map[string]error{`GRANT "audit_reader"`: cassandraRequestError{code: gocql.ErrCodeUnauthorized,
		message: "User lab_admin has no AUTHORIZE permission on <role audit_reader> HASHED PASSWORD = '$2a$10$...'"}}}
	b := newTestCassandra(t, fake)
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-2"})
	if err == nil || !strings.Contains(err.Error(), "Cassandra error 0x2100") || strings.Contains(err.Error(), "HASHED") {
		t.Fatalf("err = %v", err)
	}
	last := fake.statements[len(fake.statements)-1]
	if !strings.HasPrefix(last, `DROP ROLE IF EXISTS "trstctl_reader_`) {
		t.Fatalf("the new role was not dropped: %q", fake.statements)
	}
}

// A239: revocation drops only a role this provider issued.
func TestCassandraRevokeDropsOnlyIssuedRoles(t *testing.T) {
	fake := &fakeCassandra{}
	b := newTestCassandra(t, fake)
	ref, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "reader", LeaseID: "lease-3"})
	if err != nil {
		t.Fatal(err)
	}
	fake.statements = nil
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if len(fake.statements) != 1 || fake.statements[0] != `DROP ROLE IF EXISTS "`+ref+`"` {
		t.Fatalf("revoke ran %q", fake.statements)
	}
	for _, ref := range []string{"cassandra", "orders_reader", "trstctl_admin", `trstctl_reader" OR 1_0123456789`, "other_reader_0123456789"} {
		if err := b.Revoke(context.Background(), ref); err == nil {
			t.Errorf("revoked %q", ref)
		}
	}
	if len(fake.statements) != 1 {
		t.Fatalf("a refused revocation reached the node: %q", fake.statements)
	}
}

// A239: the provider refuses plaintext beyond a literal loopback or private
// IP, an IP address without the certificate name to verify, and a bound role
// that is not a plain name; the administrator's password goes only to
// Cassandra's PasswordAuthenticator, as SASL PLAIN.
func TestCassandraTransportAndAuthenticatorRules(t *testing.T) {
	base := CassandraConfig{Addr: "10.0.0.5:9042", TLSServerName: "cassandra.internal", AdminUser: "lab_admin",
		AdminPassword: []byte("admin-password"), RoleBindings: map[string]string{"reader": "orders_reader"}}
	if b, err := NewCassandraBackend(base); err != nil {
		t.Fatal(err)
	} else {
		b.Close()
	}
	for name, mutate := range map[string]func(*CassandraConfig){
		"plaintext to a public IP": func(c *CassandraConfig) { c.Addr, c.TLSServerName, c.AllowPlaintext = "8.8.8.8:9042", "", true },
		"plaintext to a host name": func(c *CassandraConfig) {
			c.Addr, c.TLSServerName, c.AllowPlaintext = "cassandra.internal:9042", "", true
		},
		"plaintext with TLS name":   func(c *CassandraConfig) { c.AllowPlaintext = true },
		"IP without the TLS name":   func(c *CassandraConfig) { c.TLSServerName = "" },
		"no port":                   func(c *CassandraConfig) { c.Addr = "10.0.0.5" },
		"no administrator password": func(c *CassandraConfig) { c.AdminPassword = nil },
		"a quoted role":             func(c *CassandraConfig) { c.RoleBindings = map[string]string{"reader": `orders"reader`} },
		"no roles":                  func(c *CassandraConfig) { c.RoleBindings = nil },
	} {
		cfg := base
		mutate(&cfg)
		if b, err := NewCassandraBackend(cfg); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	password, err := secret.NewFrom([]byte("admin-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Destroy()
	auth := cassandraPasswordAuth{user: "lab_admin", password: password}
	resp, next, err := auth.Challenge([]byte(cassandraAuthenticator))
	if err != nil || next != nil || !bytes.Equal(resp, []byte("\x00lab_admin\x00admin-password")) {
		t.Fatalf("PLAIN response = %q, %v", resp, err)
	}
	if resp, _, err := auth.Challenge([]byte("com.example.CustomAuthenticator")); err == nil || resp != nil {
		t.Fatalf("sent the password to another authenticator: %q", resp)
	}
	plain := cassandraDialer{backend: &CassandraBackend{}}
	if _, err := plain.DialContext(context.Background(), "tcp", "8.8.8.8:9042"); err == nil || !strings.Contains(err.Error(), "refusing plaintext") {
		t.Fatalf("plaintext dial to a public IP: %v", err)
	}
}

// A239: a connection failure names no server detail.
func TestCassandraErrorCodeNamesOnlyTheCode(t *testing.T) {
	if got := cassandraErrorCode(cassandraRequestError{code: gocql.ErrCodeSyntax, message: "line 1:20 HASHED PASSWORD"}); got != "Cassandra error 0x2000" {
		t.Fatalf("got %q", got)
	}
	if got := cassandraErrorCode(errors.New("dial tcp 10.0.0.5:9042: secret detail")); got != "connection error" {
		t.Fatalf("got %q", got)
	}
}
