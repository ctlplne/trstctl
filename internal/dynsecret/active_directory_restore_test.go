// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestADRestoreRefusesChangedAuthorityBeforeNetworkA267(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var calls atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			_ = conn.Close()
		}
	}()
	const account = "CN=service,OU=services,DC=example,DC=test"
	cfg := LDAPConfig{DirectoryMode: "active_directory", Addr: listener.Addr().String(), TLSServerName: "owned.test", BindDN: "CN=admin,DC=example,DC=test", BindPassword: []byte("owned-test-administrator"), UsersDN: "OU=services,DC=example,DC=test", RoleGroups: map[string]string{"service": account}}
	backend, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	value := func(dn string, password []byte) []byte {
		raw, e := json.Marshal(struct {
			DN       string           `json:"bind_dn"`
			Password secret.JSONBytes `json:"password"`
		}{dn, password}) // #nosec G117 -- byte-backed synthetic credential DTO exercises rejected native recovery; never logged or persisted (CWE-200)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	for _, test := range []struct {
		role, ref, dn string
		password      []byte
	}{{"unknown", account, account, []byte("Owned1!restored-password")}, {"service", "CN=foreign,OU=services,DC=example,DC=test", account, []byte("Owned1!restored-password")}, {"service", account, "CN=foreign,OU=services,DC=example,DC=test", []byte("Owned1!restored-password")}, {"service", account, account, []byte("short")}} {
		raw := value(test.dn, test.password)
		if err := backend.RestoreStaticCredential(t.Context(), test.role, test.ref, raw); err == nil {
			t.Fatal("unbound restoration admitted")
		}
		secret.Wipe(raw)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid restoration reached native network")
	}
}

func FuzzADRestoreCredentialA267(f *testing.F) {
	const account = "CN=service,OU=services,DC=example,DC=test"
	backend, err := NewLDAPBackend(LDAPConfig{DirectoryMode: "active_directory", Addr: "127.0.0.1:1", TLSServerName: "owned.test", BindDN: "CN=admin,DC=example,DC=test", BindPassword: []byte("owned-test-administrator"), UsersDN: "OU=services,DC=example,DC=test", RoleGroups: map[string]string{"service": account}})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(backend.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.Add([]byte(`{"bind_dn":"CN=service,OU=services,DC=example,DC=test","password":"Owned1!restored-password"}`))
	f.Add([]byte(`{"bind_dn":"CN=foreign,OU=services,DC=example,DC=test","password":"Owned1!restored-password"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		if err := backend.RestoreStaticCredential(ctx, "service", account, raw); err == nil {
			t.Fatal("invalid/canceled native restoration succeeded")
		}
	})
}
