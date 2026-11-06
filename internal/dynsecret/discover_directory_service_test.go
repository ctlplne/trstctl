// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
	"testing/quick"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

type serviceAccountDirectoryFixture struct {
	queries               []*ldap.SearchRequest
	badIdentity, referral bool
}

func fixtureServiceEntry(name string) *ldap.Entry {
	sid := make([]byte, 28)
	sid[0] = 1
	sid[1] = 5
	sid[7] = 5
	for i, v := range []uint32{21, 1, 2, 3, 1001} {
		binary.LittleEndian.PutUint32(sid[8+i*4:], v)
	}
	return ldap.NewEntry("CN="+name+",OU=services,DC=lab,DC=test", map[string][]string{"sAMAccountName": {name}, "userAccountControl": {"512"}, "objectGUID": {strings.Repeat("g", 16)}, "objectSid": {string(sid)}, "servicePrincipalName": {"HTTP/work.lab.test"}})
}
func (f *serviceAccountDirectoryFixture) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.queries = append(f.queries, req)
	if strings.Contains(req.Filter, "servicePrincipalName=*") || req.Scope == ldap.ScopeBaseObject {
		entry := fixtureServiceEntry("nonadmin-service")
		if f.badIdentity {
			entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "objectGUID", Values: []string{"bad"}, ByteValues: [][]byte{[]byte("bad")}})
		}
		out := &ldap.SearchResult{Entries: []*ldap.Entry{entry}}
		if f.referral {
			out.Referrals = []string{"ldaps://foreign.test"}
		}
		return out, nil
	}
	return &ldap.SearchResult{}, nil
}
func TestADServiceDiscoveryIncludesNonAdminWithoutInventingRightsA267(t *testing.T) {
	fixture := &serviceAccountDirectoryFixture{}
	backend := &LDAPBackend{activeDirectory: true, usersDN: "OU=services,DC=lab,DC=test", roleGroups: map[string]string{"service": "CN=nonadmin-service,OU=services,DC=lab,DC=test"}}
	accounts, err := backend.discoverDirectoryAccounts(context.Background(), fixture)
	if err != nil || len(accounts) != 1 {
		t.Fatal("non-admin service account omitted", err)
	}
	account := accounts[0]
	if account.Name != "nonadmin-service" || len(account.Privileges) != 0 || account.Details["native_sid"] != "S-1-5-21-1-2-3-1001" || len(account.Details["native_guid"]) != 32 || account.Details["service_account"] != "true" {
		t.Fatal("service identity or actual privilege evidence differs")
	}
	for _, query := range fixture.queries {
		for _, attr := range query.Attributes {
			switch strings.ToLower(attr) {
			case "unicodepwd", "userpassword", "supplementalcredentials", "ntpwdhistory":
				t.Fatal("credential attribute requested")
			}
		}
	}
}
func TestADServiceDiscoveryRefusesIncompleteOrReferredIdentityA267(t *testing.T) {
	for _, kind := range []string{"identity", "referral"} {
		t.Run(kind, func(t *testing.T) {
			fixture := &serviceAccountDirectoryFixture{badIdentity: kind == "identity", referral: kind == "referral"}
			backend := &LDAPBackend{activeDirectory: true, usersDN: "OU=services,DC=lab,DC=test"}
			if _, err := backend.discoverDirectoryAccounts(context.Background(), fixture); err == nil {
				t.Fatal("incomplete or foreign directory observation admitted")
			}
		})
	}
}
func TestADServiceSIDMetadataReferenceA267(t *testing.T) {
	if err := quick.Check(func(a, b, c, rid uint32) bool {
		raw := make([]byte, 28)
		raw[0] = 1
		raw[1] = 5
		raw[7] = 5
		for i, v := range []uint32{21, a, b, c, rid} {
			binary.LittleEndian.PutUint32(raw[8+i*4:], v)
		}
		text, err := adDiscoverySID(raw)
		return err == nil && text == fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", a, b, c, rid)
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func FuzzADServiceSIDMetadataA267(f *testing.F) {
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128 {
			return
		}
		text, err := adDiscoverySID(raw)
		if err == nil && (len(raw) != 8+4*int(raw[1]) || !strings.HasPrefix(text, "S-1-")) {
			t.Fatal("noncanonical native SID")
		}
	})
}

func TestADServiceDiscoveryRejectsAmbiguousPublicAccountStateA267(t *testing.T) {
	for _, attr := range []string{"sAMAccountName", "userAccountControl"} {
		t.Run(attr, func(t *testing.T) {
			entry := fixtureServiceEntry("nonadmin-service")
			entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: attr, Values: []string{"different"}, ByteValues: [][]byte{[]byte("different")}})
			account := &pamdiscovery.Account{Name: "nonadmin-service", Details: map[string]string{"dn": entry.DN}}
			if err := addADDiscoveryIdentity(account, entry, true); err == nil {
				t.Fatal("ambiguous public native account state admitted")
			}
		})
	}
}
