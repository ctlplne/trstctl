// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// dynamicDirectory is the fake directory with RFC 2589 Refresh: it records
// each refresh and grants up to maxTTL.
type dynamicDirectory struct {
	*fakeDirectory
	maxTTL    int64
	refreshed map[string]int64
	refuse    bool
}

func (d *dynamicDirectory) Extended(req *ldap.ExtendedRequest) (*ldap.ExtendedResponse, error) {
	if req.Name != ldapRefreshOID || req.Value == nil || req.Value.ClassType != ber.ClassContext || req.Value.Tag != 1 {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("not a refresh"))
	}
	if d.refuse {
		return nil, ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("no dds"))
	}
	inner, err := ber.DecodePacketErr(req.Value.Data.Bytes())
	if err != nil || len(inner.Children) != 2 || inner.Children[0].Tag != 0 || inner.Children[1].Tag != 1 {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("malformed refresh"))
	}
	dn := inner.Children[0].Data.String()
	if _, ok := d.entries[dn]; !ok {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	var ttl int64
	for _, b := range inner.Children[1].Data.Bytes() {
		ttl = ttl<<8 | int64(b)
	}
	if ttl > d.maxTTL {
		ttl = d.maxTTL
	}
	d.refreshed[dn] = ttl
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Refresh response")
	response.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 1, ttl, "responseTtl"))
	return &ldap.ExtendedResponse{Name: ldapRefreshOID, Value: ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string(response.Bytes()), "responseValue")}, nil
}

func newDynamicLDAPBackend(t *testing.T, directory *dynamicDirectory) *LDAPBackend {
	t.Helper()
	b, err := NewLDAPBackend(LDAPConfig{
		Addr: "ldap.lab.test:636", BindDN: directory.admin, BindPassword: []byte(directory.adminPW),
		UsersDN: "ou=leases,dc=lab,dc=test", UsernamePrefix: "trstctl", DynamicEntries: true,
		RoleGroups: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.dial = func(context.Context) (ldapConn, error) { return directory, nil }
	t.Cleanup(b.Close)
	return b
}

// A239-L2: with dynamic_entries a lease's entry is an RFC 2589 dynamic object
// given the lease's time to live, and a renewal refreshes it; a directory that
// grants less time, or no refresh at all, refuses the lease rather than end it
// early, leaving no entry behind. Without the option nothing is refreshed, and
// an Active Directory provider cannot take it.
func TestLDAPLeaseEntriesExpireInTheDirectoryA239L2(t *testing.T) {
	ctx := context.Background()
	directory := &dynamicDirectory{fakeDirectory: newFakeDirectory(), maxTTL: 86400, refreshed: map[string]int64{}}
	b := newDynamicLDAPBackend(t, directory)
	ref, raw, err := b.CreateCredential(ctx, GenerateRequest{Role: "readonly", TTL: 15 * time.Minute, LeaseID: "l-1"})
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		BindDN string `json:"bind_dn"`
	}
	if json.Unmarshal(raw, &credential) != nil || credential.BindDN != ref {
		t.Fatalf("credential %s", raw)
	}
	classes := directory.entries[ref]["objectClass"]
	if len(classes) == 0 || classes[len(classes)-1] != "dynamicObject" || directory.refreshed[ref] != 900 {
		t.Fatalf("the entry is %v with time to live %d; want a dynamicObject kept 900 s", classes, directory.refreshed[ref])
	}
	if err := b.RefreshCredential(ctx, ref, 45*time.Minute); err != nil || directory.refreshed[ref] != 2700 {
		t.Fatalf("a renewal refreshed it to %d (%v), want 2700", directory.refreshed[ref], err)
	}

	// A directory that keeps entries for at most 10 minutes would end a
	// 15-minute lease early: refused, and no entry is left.
	directory.maxTTL = 600
	if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "readonly", TTL: 15 * time.Minute, LeaseID: "l-2"}); !errors.Is(err, ErrLDAPDynamicTTLShortened) {
		t.Fatalf("a shortened time to live was accepted: %v", err)
	}
	if len(directory.entries) != 1 {
		t.Fatalf("a refused lease left %d entries", len(directory.entries))
	}
	if err := b.RefreshCredential(ctx, ref, 45*time.Minute); !errors.Is(err, ErrLDAPDynamicTTLShortened) {
		t.Fatalf("a renewal past the directory's maximum was accepted: %v", err)
	}
	// A directory without RFC 2589 refuses the refresh: no lease, no entry.
	directory.maxTTL, directory.refuse = 86400, true
	if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "readonly", TTL: time.Minute, LeaseID: "l-3"}); err == nil || len(directory.entries) != 1 {
		t.Fatalf("a directory without dynamic entries took the lease: %v, %d entries", err, len(directory.entries))
	}
	// Outside the provider's leases nothing is refreshed.
	if err := b.RefreshCredential(ctx, "cn=admin,dc=lab,dc=test", time.Minute); err == nil {
		t.Fatal("an entry outside users_dn was refreshed")
	}

	plain := newTestLDAPBackend(t, newFakeDirectory())
	if err := plain.RefreshCredential(ctx, "uid=x,ou=leases,dc=lab,dc=test", time.Minute); err != nil {
		t.Fatalf("a provider without dynamic entries refreshed: %v", err)
	}
	if _, err := NewLDAPBackend(LDAPConfig{DirectoryMode: "active_directory", DynamicEntries: true, Addr: "ad.lab.test:636", BindDN: "cn=admin,dc=lab,dc=test",
		BindPassword: []byte("pw"), UsersDN: "ou=svc,dc=lab,dc=test", RoleGroups: map[string]string{"r": "cn=a,ou=svc,dc=lab,dc=test"}}); err == nil {
		t.Fatal("an Active Directory provider took dynamic entries")
	}
}
