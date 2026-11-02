// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeDirectory is an in-memory directory: entries, their passwords and the
// members of groupOfNames groups.
type fakeDirectory struct {
	admin     string
	adminPW   string
	entries   map[string]map[string][]string
	passwords map[string]string
	groups    map[string]map[string]bool
	failPW    bool
	binds     []string
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{admin: "cn=admin,dc=lab,dc=test", adminPW: "admin-pw",
		entries: map[string]map[string][]string{}, passwords: map[string]string{},
		groups: map[string]map[string]bool{
			"cn=readers,ou=groups,dc=lab,dc=test": {"cn=admin,dc=lab,dc=test": true},
			"cn=writers,ou=groups,dc=lab,dc=test": {"cn=admin,dc=lab,dc=test": true},
		}}
}

func (f *fakeDirectory) Bind(dn, password string) error {
	f.binds = append(f.binds, dn)
	if (dn == f.admin && password == f.adminPW) || (f.passwords[dn] != "" && f.passwords[dn] == password) {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (f *fakeDirectory) Add(req *ldap.AddRequest) error {
	if _, ok := f.entries[req.DN]; ok {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
	}
	attrs := map[string][]string{}
	for _, a := range req.Attributes {
		attrs[a.Type] = a.Vals
	}
	f.entries[req.DN] = attrs
	return nil
}

func (f *fakeDirectory) Del(req *ldap.DelRequest) error {
	if _, ok := f.entries[req.DN]; !ok {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	delete(f.entries, req.DN)
	delete(f.passwords, req.DN)
	return nil
}

func (f *fakeDirectory) Modify(req *ldap.ModifyRequest) error {
	members, ok := f.groups[req.DN]
	if !ok {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such group"))
	}
	for _, change := range req.Changes {
		for _, value := range change.Modification.Vals {
			switch change.Operation {
			case ldap.AddAttribute:
				members[value] = true
			case ldap.DeleteAttribute:
				if !members[value] {
					return ldap.NewError(ldap.LDAPResultNoSuchAttribute, errors.New("no such value"))
				}
				delete(members, value)
			}
		}
	}
	return nil
}

func (f *fakeDirectory) PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	if f.failPW {
		return nil, ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("unwilling"))
	}
	if _, ok := f.entries[req.UserIdentity]; !ok {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	f.passwords[req.UserIdentity] = req.NewPassword
	return &ldap.PasswordModifyResult{}, nil
}

func (f *fakeDirectory) Close() error { return nil }

func newTestLDAPBackend(t *testing.T, directory *fakeDirectory) *LDAPBackend {
	t.Helper()
	b, err := NewLDAPBackend(LDAPConfig{
		Addr: "ldap.lab.test:636", BindDN: directory.admin, BindPassword: []byte(directory.adminPW),
		UsersDN: "ou=leases,dc=lab,dc=test", UsernamePrefix: "trstctl",
		RoleGroups: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test", "readwrite": "cn=writers,ou=groups,dc=lab,dc=test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.dial = func(context.Context) (ldapConn, error) { return directory, nil }
	t.Cleanup(b.Close)
	return b
}

// A239: a lease is a directory entry with a password the directory set, in its
// role's group only; revocation takes it out of the group and deletes it, and
// the leased password no longer binds; a second revocation succeeds.
func TestLDAPBackendCreatesAndRevokesALeasedEntryA239(t *testing.T) {
	directory := newFakeDirectory()
	b := newTestLDAPBackend(t, directory)
	ref, raw, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readonly", LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct{ URL, BindDN, Username, Password string }
	if err := json.Unmarshal(raw, &struct {
		URL      *string `json:"url"`
		BindDN   *string `json:"bind_dn"`
		Username *string `json:"username"`
		Password *string `json:"password"`
	}{&credential.URL, &credential.BindDN, &credential.Username, &credential.Password}); err != nil {
		t.Fatal(err)
	}
	if ref != credential.BindDN || !strings.HasPrefix(ref, "uid=trstctl-readonly-") || !strings.HasSuffix(ref, ",ou=leases,dc=lab,dc=test") ||
		credential.URL != "ldaps://ldap.lab.test:636" || len(credential.Password) != 48 {
		t.Fatalf("ref %q credential %+v", ref, credential)
	}
	if err := directory.Bind(ref, credential.Password); err != nil {
		t.Fatalf("the leased password does not bind: %v", err)
	}
	if !directory.groups["cn=readers,ou=groups,dc=lab,dc=test"][ref] || directory.groups["cn=writers,ou=groups,dc=lab,dc=test"][ref] {
		t.Fatalf("group membership %v", directory.groups)
	}
	if classes := strings.Join(directory.entries[ref]["objectClass"], ","); classes != "top,person,organizationalPerson,inetOrgPerson" {
		t.Fatalf("objectClass %s", classes)
	}

	if err := b.Revoke(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if _, ok := directory.entries[ref]; ok || directory.groups["cn=readers,ou=groups,dc=lab,dc=test"][ref] {
		t.Fatal("revocation left the entry or its membership")
	}
	if err := directory.Bind(ref, credential.Password); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("a revoked entry still binds: %v", err)
	}
	if err := b.Revoke(t.Context(), ref); err != nil {
		t.Fatalf("a second revocation: %v", err)
	}
	if err := b.Revoke(t.Context(), "uid=someone,ou=people,dc=lab,dc=test"); err == nil {
		t.Fatal("an entry outside users_dn was accepted for revocation")
	}
}

// A239: an issue resumed after an uncertain outcome converges on the same entry
// (one entry, a new password), and a failed password step leaves nothing.
func TestLDAPBackendConvergesOnOneEntryAfterARetryA239(t *testing.T) {
	directory := newFakeDirectory()
	b := newTestLDAPBackend(t, directory)
	first, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readwrite", LeaseID: "lease-2"})
	if err != nil {
		t.Fatal(err)
	}
	firstPassword := directory.passwords[first]
	second, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readwrite", LeaseID: "lease-2"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(directory.entries) != 1 || directory.passwords[second] == firstPassword {
		t.Fatalf("a retry made %d entries (%q, %q)", len(directory.entries), first, second)
	}
	directory.failPW = true
	if _, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readonly", LeaseID: "lease-3"}); err == nil {
		t.Fatal("an issue whose password could not be set succeeded")
	}
	if len(directory.entries) != 1 {
		t.Fatalf("a failed issue left %d entries", len(directory.entries))
	}
	if _, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "admin", LeaseID: "lease-4"}); err == nil {
		t.Fatal("a role with no group was issued")
	}
	if _, _, err := b.CreateCredential(t.Context(), GenerateRequest{Role: "readonly", Static: true}); err == nil {
		t.Fatal("a static credential was issued")
	}
}

// A239: the backend refuses plaintext beyond a literal private address, and
// configuration that isn't a directory name.
func TestLDAPBackendRefusesUnsafeConfigurationA239(t *testing.T) {
	base := LDAPConfig{Addr: "ldap.lab.test:636", BindDN: "cn=admin,dc=lab,dc=test", BindPassword: []byte("pw"),
		UsersDN: "ou=leases,dc=lab,dc=test", RoleGroups: map[string]string{"readonly": "cn=readers,dc=lab,dc=test"}}
	if _, err := NewLDAPBackend(base); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
	plaintext := base
	plaintext.Addr, plaintext.AllowPlaintext = "127.0.0.1:389", true
	if _, err := NewLDAPBackend(plaintext); err != nil {
		t.Fatalf("plaintext at loopback with the opt-in: %v", err)
	}
	for name, mutate := range map[string]func(*LDAPConfig){
		"TLS to a bare IP":        func(c *LDAPConfig) { c.Addr = "192.0.2.10:636" },
		"plaintext to a name":     func(c *LDAPConfig) { c.AllowPlaintext = true },
		"plaintext to public IP":  func(c *LDAPConfig) { c.Addr, c.AllowPlaintext = "8.8.8.8:389", true },
		"plaintext with TLS name": func(c *LDAPConfig) { c.Addr, c.AllowPlaintext, c.TLSServerName = "127.0.0.1:389", true, "x" },
		"no port":                 func(c *LDAPConfig) { c.Addr = "ldap.lab.test" },
		"bad bind dn":             func(c *LDAPConfig) { c.BindDN = "admin" },
		"bad users dn":            func(c *LDAPConfig) { c.UsersDN = "" },
		"bad group":               func(c *LDAPConfig) { c.RoleGroups = map[string]string{"readonly": "readers"} },
		"no groups":               func(c *LDAPConfig) { c.RoleGroups = nil },
		"no password":             func(c *LDAPConfig) { c.BindPassword = nil },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := NewLDAPBackend(cfg); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
