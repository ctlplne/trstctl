// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"strings"
	"testing"
)

// A240: the local-account rotator refuses an unsafe or ambiguous
// configuration, issues no leases, retires nothing for an in-place
// (single-phase) rotation and refuses references to accounts it does not
// rotate — all before contacting the host.
func TestUnixAccountsBackendRefusesBeforeContactingTheHost(t *testing.T) {
	good := UnixAccountsConfig{Address: "127.0.0.1:1", AdminUser: "root", AdminKey: []byte("not used here"),
		HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43),
		RoleAccounts:       map[string]string{"host/single": "orders-single"},
		RotationAccounts:   map[string][2]string{"host/orders": {"orders-svc-a", "orders-svc-b"}}}
	backend, err := NewUnixAccountsBackend(good)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ctx := context.Background()
	if _, _, err := backend.CreateCredential(ctx, GenerateRequest{Role: "host/single"}); err == nil || !strings.Contains(err.Error(), "rotated, not leased") {
		t.Fatalf("a lease was issued: %v", err)
	}
	if err := backend.Revoke(ctx, "orders-single/cmd-1"); err != nil {
		t.Fatalf("an in-place rotation's predecessor has nothing left to retire: %v", err)
	}
	for _, ref := range []string{"root", "nobody/cmd-1", "orders-svc-c"} {
		if err := backend.Revoke(ctx, ref); err == nil || !strings.Contains(err.Error(), "names no account this provider rotates") {
			t.Errorf("revoke %q: %v", ref, err)
		}
	}
	for name, mutate := range map[string]func(*UnixAccountsConfig){
		"no pin":        func(c *UnixAccountsConfig) { c.HostKeyFingerprint = "" },
		"bad admin":     func(c *UnixAccountsConfig) { c.AdminUser = "Root" },
		"no key":        func(c *UnixAccountsConfig) { c.AdminKey = nil },
		"bad address":   func(c *UnixAccountsConfig) { c.Address = "host" },
		"unsafe name":   func(c *UnixAccountsConfig) { c.RoleAccounts = map[string]string{"host/single": "root:0:0"} },
		"same pair":     func(c *UnixAccountsConfig) { c.RotationAccounts = map[string][2]string{"host/orders": {"a", "a"}} },
		"shared":        func(c *UnixAccountsConfig) { c.RoleAccounts = map[string]string{"host/single": "orders-svc-a"} },
		"nothing bound": func(c *UnixAccountsConfig) { c.RoleAccounts, c.RotationAccounts = nil, nil },
	} {
		c := good
		mutate(&c)
		if _, err := NewUnixAccountsBackend(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
