// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// TestLDAPDynamicLeaseExpiresInOpenLDAPA239L2 is A239-L2's proof on stock
// OpenLDAP 2.6 with the dds overlay (scripts/labs/openldap-dds.sh runs it):
// a lease's entry is created as a dynamic object kept for the lease's 20
// seconds, the lease's password binds, a renewal refreshes it to 30 seconds
// (entryTtl reads it), and then — with nothing from trstctl, no revocation,
// as if the control plane were down — the directory deletes the entry once
// its time runs out: the password no longer binds and the entry is gone.
func TestLDAPDynamicLeaseExpiresInOpenLDAPA239L2(t *testing.T) {
	if os.Getenv("TRSTCTL_LDAP_DDS_LAB") != "1" {
		t.Skip("owned OpenLDAP dds lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	admin, err := os.ReadFile(os.Getenv("TRSTCTL_LDAP_DDS_ADMIN")) // #nosec G304 G703 -- the lab runner's own protected password file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	admin = bytes.TrimSpace(admin)
	defer secret.Wipe(admin)
	addr := os.Getenv("TRSTCTL_LDAP_DDS_ADDR")
	backend, err := NewLDAPBackend(LDAPConfig{Addr: addr, AllowPlaintext: true, BindDN: "cn=admin,dc=lab,dc=test", BindPassword: admin,
		UsersDN: "ou=leases,dc=lab,dc=test", UsernamePrefix: "trstctl", DynamicEntries: true,
		RoleGroups: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ref, raw, err := backend.CreateCredential(ctx, GenerateRequest{Role: "readonly", TTL: 20 * time.Second, LeaseID: "a239l2-lab", PrincipalSuffix: testPrincipalSuffix("a239l2-lab")})
	if err != nil {
		t.Fatal("create a dynamic lease entry:", err)
	}
	var credential struct {
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(raw, &credential); err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential.Password)
	bindAsLease := func() error {
		conn, err := ldap.DialURL("ldap://" + addr)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return conn.Bind(credential.BindDN, string(credential.Password))
	}
	entryTTL := func() (int, error) {
		conn, err := ldap.DialURL("ldap://" + addr)
		if err != nil {
			return 0, err
		}
		defer func() { _ = conn.Close() }()
		if err := conn.Bind("cn=admin,dc=lab,dc=test", string(admin)); err != nil {
			return 0, err
		}
		result, err := conn.Search(ldap.NewSearchRequest(ref, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=dynamicObject)", []string{"entryTtl"}, nil))
		if err != nil {
			return 0, err
		}
		if len(result.Entries) != 1 {
			return 0, errors.New("not exactly one entry")
		}
		return strconv.Atoi(result.Entries[0].GetAttributeValue("entryTtl"))
	}
	if err := bindAsLease(); err != nil {
		t.Fatal("the lease's password does not bind:", err)
	}
	if ttl, err := entryTTL(); err != nil || ttl < 15 || ttl > 20 {
		t.Fatalf("the new entry's entryTtl is %d (%v), want the lease's 20 s", ttl, err)
	}
	if err := backend.RefreshCredential(ctx, ref, 30*time.Second); err != nil {
		t.Fatal("refresh the entry for a renewal:", err)
	}
	if ttl, err := entryTTL(); err != nil || ttl < 25 || ttl > 30 {
		t.Fatalf("the renewed entry's entryTtl is %d (%v), want 30 s", ttl, err)
	}
	t.Logf("dynamic entry %s kept 30 s after a renewal; trstctl now does nothing", ref)
	deadline := time.Now().Add(90 * time.Second)
	for {
		_, err := entryTTL()
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the directory did not delete the expired entry: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	err = bindAsLease()
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("after the directory expired the entry the lease's password reads %v, want invalid credentials", err)
	}
	t.Logf("A239L2_LAB_OK %s expired in the directory with no revocation", ref)
}
