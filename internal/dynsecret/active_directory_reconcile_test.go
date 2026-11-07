// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestADReconcileNativePrincipalPinsBeforeResetA267(t *testing.T) {
	const targetDN = "CN=service,OU=services,DC=lab,DC=test"
	const writerDN = "CN=reconcile,OU=operators,DC=lab,DC=test"
	const ordinaryDN = "CN=rotation,OU=operators,DC=lab,DC=test"
	writerSID := "010500000000000515000000010000000200000003000000ea030000"
	ordinarySID := "010500000000000515000000010000000200000003000000f4010000"
	target := adNativeResetIdentity{adNativeIdentity: adNativeIdentity{Name: "service", GUID: strings.Repeat("a", 32), SID: "010500000000000515000000010000000200000003000000e9030000"}}
	authority := &ADReconcileAuthority{Principal: ADReconcilePrincipal{DN: writerDN, SID: "S-1-5-21-1-2-3-1002", GUID: strings.Repeat("b", 32)}, RotationBindDN: ordinaryDN}
	backend := &LDAPBackend{activeDirectory: true, bindDN: writerDN, reconcile: authority}
	entry := func(dn, guid, sid string) *ldap.Entry {
		rawGUID, e := hex.DecodeString(guid)
		if e != nil {
			t.Fatal(e)
		}
		rawSID, e := hex.DecodeString(sid)
		if e != nil {
			t.Fatal(e)
		}
		return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{rawGUID}}, {Name: "objectSid", ByteValues: [][]byte{rawSID}}}}
	}
	rows := map[string]*ldap.Entry{writerDN: entry(writerDN, strings.Repeat("b", 32), writerSID), ordinaryDN: entry(ordinaryDN, strings.Repeat("c", 32), ordinarySID)}
	read := func(dn string) (*ldap.Entry, error) {
		if v := rows[dn]; v != nil {
			return v, nil
		}
		return nil, errors.New("owned exact principal unavailable")
	}
	current, err := backend.bindADReconcilePrincipal(targetDN, target, read)
	if err != nil || current.ResetPrincipalGUID != authority.Principal.GUID || current.ResetPrincipalSID != writerSID || current.ResetPrincipalDN != writerDN {
		t.Fatal("exact designated native writer unavailable", err)
	}
	for name, replace := range map[string]*ldap.Entry{
		"same DN replacement": entry(writerDN, strings.Repeat("d", 32), writerSID),
		"same DN other SID":   entry(writerDN, strings.Repeat("b", 32), ordinarySID),
		"target GUID":         entry(writerDN, target.GUID, writerSID),
		"target SID":          entry(writerDN, strings.Repeat("b", 32), target.SID),
		"ordinary SID":        entry(writerDN, strings.Repeat("b", 32), ordinarySID),
		"wrong returned DN":   entry(targetDN, strings.Repeat("b", 32), writerSID),
	} {
		t.Run(name, func(t *testing.T) {
			rows[writerDN] = replace
			candidate := *backend
			grant := *authority
			candidate.reconcile = &grant
			if name == "target GUID" {
				grant.Principal.GUID = target.GUID
			}
			if name == "target SID" {
				grant.Principal.SID = "S-1-5-21-1-2-3-1001"
			}
			if name == "ordinary SID" {
				grant.Principal.SID = "S-1-5-21-1-2-3-500"
			}
			if _, err := candidate.bindADReconcilePrincipal(targetDN, target, read); err == nil {
				t.Fatal("substituted native reset authority accepted")
			}
		})
	}
	rows[writerDN] = entry(writerDN, strings.Repeat("b", 32), writerSID)
	rows[ordinaryDN] = entry(ordinaryDN, strings.Repeat("b", 32), writerSID)
	if _, err := backend.bindADReconcilePrincipal(targetDN, target, read); err == nil {
		t.Fatal("ordinary and designated native principal aliases accepted")
	}
	delete(rows, ordinaryDN)
	if _, err := backend.bindADReconcilePrincipal(targetDN, target, read); err == nil {
		t.Fatal("missing ordinary identity allowed ambiguous authority")
	}
}

func TestADReconcileBackendFreezesNativeAuthorityA267(t *testing.T) {
	grant := &ADReconcileAuthority{Principal: ADReconcilePrincipal{DN: "CN=reconcile,OU=operators,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1002", GUID: strings.Repeat("b", 32)}, RotationBindDN: "CN=rotation,OU=operators,DC=lab,DC=test"}
	cfg := LDAPConfig{DirectoryMode: "active_directory", Addr: "127.0.0.1:1", TLSServerName: "directory.example", BindDN: grant.Principal.DN, BindPassword: []byte("constructor-only-owned-fixture"), UsersDN: "OU=services,DC=lab,DC=test", RoleGroups: map[string]string{"directory/service": "CN=service,OU=services,DC=lab,DC=test"}, ADReconcile: grant}
	b, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.reconcile == nil {
		t.Fatal("LDAP constructor discarded the designated native authority")
	}
	for _, operation := range []func() error{
		func() error {
			_, _, e := b.CreateCredential(t.Context(), GenerateRequest{Role: "directory/service", Static: true, LeaseID: "owned", Predecessor: cfg.RoleGroups["directory/service"]})
			return e
		},
		func() error { return b.Revoke(t.Context(), cfg.RoleGroups["directory/service"]) },
		func() error {
			return b.RestoreStaticCredential(t.Context(), "directory/service", cfg.RoleGroups["directory/service"], []byte(`{}`))
		},
	} {
		if e := operation(); e == nil || !strings.Contains(e.Error(), "sealed preparation") {
			t.Fatal("unprepared designated effect reached another path", e)
		}
	}
	grant.Principal.GUID = strings.Repeat("c", 32)
	if b.reconcile.Principal.GUID != strings.Repeat("b", 32) {
		t.Fatal("caller changed frozen native authority")
	}
	cfg.ADReconcile = &ADReconcileAuthority{Principal: b.reconcile.Principal, RotationBindDN: b.bindDN}
	if other, err := NewLDAPBackend(cfg); err == nil {
		other.Close()
		t.Fatal("LDAP constructor accepted aliased ordinary authority")
	}
}
