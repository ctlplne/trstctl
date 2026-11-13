// SPDX-License-Identifier: BUSL-1.1

package pamdiscovery

import (
	"reflect"
	"testing"
)

func TestHostAccountsA260(t *testing.T) {
	inv := HostInventory{
		Passwd: []string{
			"root:x:0:0:root:/root:/bin/bash",
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			"alice:x:1000:1000::/home/alice:/bin/bash",
			"bob:x:1001:1001::/home/bob:/bin/bash",
			"carol:x:1002:27::/home/carol:/bin/bash",
			"deploy:x:1003:1003::/home/deploy:/bin/sh",
			"ops1:x:1004:1004::/home/ops1:/bin/bash",
			"svc:x:1005:1005::/home/svc:/usr/sbin/nologin",
			"plain:x:1006:1006::/home/plain:/bin/bash",
		},
		Group: []string{"root:x:0:", "sudo:x:27:alice", "ops:x:1100:ops1", "plain:x:1006:"},
		Sudoers: []SudoersFile{
			{Path: "/etc/sudoers", Readable: true, Lines: []string{
				"Defaults env_reset",
				"# comment alice ALL=(ALL) ALL",
				"root ALL=(ALL:ALL) ALL",
				"%sudo ALL=(ALL:ALL) ALL",
				"@includedir /etc/sudoers.d",
			}},
			{Path: "/etc/sudoers.d/deploy", Readable: true, Lines: []string{
				"User_Alias DEPLOYERS = deploy, %ops",
				"Cmnd_Alias RESTART = /usr/bin/systemctl restart app",
				"DEPLOYERS ALL=(root) NOPASSWD: RESTART",
				"svc, \\",
				"  bob ALL = (ALL) NOPASSWD: ALL",
			}},
		},
		Keys: []AccountKeys{
			{Account: "alice", Readable: true, Keys: []AuthorizedKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:aaa"}}},
			{Account: "bob", Readable: true, Keys: []AuthorizedKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:bbb", Restricted: true}, {Type: "ssh-rsa", Fingerprint: "SHA256:ccc"}}},
			{Account: "plain", Readable: true, Keys: []AuthorizedKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:ppp"}}},
		},
	}
	got := map[string]Account{}
	for _, a := range HostAccounts(inv) {
		got[a.Name] = a
	}
	want := map[string][]string{
		"root":   {"group:root", "sudo:ALL", "uid0"},
		"alice":  {"authorized_keys:1", "group:sudo", "sudo:ALL"},
		"bob":    {"authorized_keys:2", "sudo:ALL"},
		"carol":  {"group:sudo", "sudo:ALL"},
		"deploy": {"sudo:commands"},
		"ops1":   {"sudo:commands"},
		"svc":    {"sudo:ALL"},
	}
	if len(got) != len(want) {
		t.Fatalf("privileged accounts = %v", got)
	}
	for name, privileges := range want {
		if !reflect.DeepEqual(got[name].Privileges, privileges) {
			t.Fatalf("%s privileges = %v, want %v", name, got[name].Privileges, privileges)
		}
	}
	if !got["svc"].Disabled || got["alice"].Disabled {
		t.Fatalf("disabled flags: svc %v alice %v", got["svc"].Disabled, got["alice"].Disabled)
	}
	if got["bob"].Details["authorized_keys"] != "ssh-ed25519 SHA256:bbb restricted; ssh-rsa SHA256:ccc" {
		t.Fatalf("bob's keys = %q", got["bob"].Details["authorized_keys"])
	}
	if _, ok := got["plain"]; ok {
		t.Fatal("an account with keys but no privilege was reported")
	}

	// An unreadable sudoers file leaves sudo rights unknown, not absent.
	inv.Sudoers = append(inv.Sudoers, SudoersFile{Path: "/etc/sudoers.d/secret"})
	for _, a := range HostAccounts(inv) {
		if a.Details["sudoers"] != "unreadable" {
			t.Fatalf("%s does not say a sudoers file was unreadable", a.Name)
		}
	}
}

func TestDiffA260(t *testing.T) {
	before := Normalize([]Account{
		{Key: "role:a", Name: "a", Kind: KindDatabaseRole, Privileges: []string{"superuser"}},
		{Key: "role:b", Name: "b", Kind: KindDatabaseRole, Privileges: []string{"createrole"}},
		{Key: "role:c", Name: "c", Kind: KindDatabaseRole, Privileges: []string{"replication"}},
	})
	after := Normalize([]Account{
		{Key: "role:a", Name: "a", Kind: KindDatabaseRole, Privileges: []string{"superuser"}},
		{Key: "role:c", Name: "c", Kind: KindDatabaseRole, Privileges: []string{"replication", "bypassrls"}},
		{Key: "role:d", Name: "d", Kind: KindDatabaseRole, Privileges: []string{"superuser"}},
	})
	var got []string
	for _, c := range Diff(before, after) {
		got = append(got, c.Account.Key+" "+c.Change)
	}
	if want := []string{"role:b removed", "role:c changed", "role:d added"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %v, want %v", got, want)
	}
}

// TestHostAccountsNameTheirKeyFilesA260L2: an account found on a host whose
// sshd reads keys from somewhere other than its defaults says where, and a
// configured AuthorizedKeysCommand is named: keys it returns are not in any
// file the scan read. A host on sshd's defaults says neither.
func TestHostAccountsNameTheirKeyFilesA260L2(t *testing.T) {
	inv := HostInventory{
		Passwd:      []string{"root:x:0:0:root:/root:/bin/bash"},
		KeyFiles:    []string{"/etc/ssh/keys.d/%u", "%h/.ssh/authorized_keys"},
		KeysCommand: true,
	}
	accounts := HostAccounts(inv)
	if len(accounts) != 1 || accounts[0].Details["authorized_keys_files"] != "/etc/ssh/keys.d/%u %h/.ssh/authorized_keys" ||
		accounts[0].Details["authorized_keys_command"] != "configured" {
		t.Fatalf("accounts = %+v", accounts)
	}
	inv.KeyFiles, inv.KeysCommand = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}, false
	if details := HostAccounts(inv)[0].Details; details["authorized_keys_files"] != "" || details["authorized_keys_command"] != "" {
		t.Fatalf("a host on sshd's defaults = %+v", details)
	}
}

// A260-L3 Done-when (rules): a non-root administrator cannot read the sudoers
// files, so sudo's own listing (`sudo -n -l -U`) stands in for them: a rule
// running any command grants sudo:ALL, one naming commands sudo:commands, the
// list pseudo-command or no rules grant nothing; the accounts say their rights
// were listed by sudo. With the files readable the listing is not used.
func TestHostAccountsUseSudoListingWhenSudoersAreHiddenA260L3(t *testing.T) {
	inv := HostInventory{
		Passwd: []string{
			"root:x:0:0:root:/root:/bin/bash",
			"discover-admin:x:999:999::/home/discover-admin:/bin/bash",
			"orders-svc-a:x:1000:1000::/home/orders-svc-a:/bin/bash",
			"orders-single:x:1002:1002::/home/orders-single:/bin/bash",
			"plain:x:1003:1003::/home/plain:/bin/bash",
			"ops-unlisted:x:1004:1004::/home/ops-unlisted:/bin/bash",
		},
		Group:   []string{"root:x:0:", "sudo:x:27:orders-svc-a,ops-unlisted"},
		Sudoers: []SudoersFile{{Path: "/etc/sudoers", Readable: false}, {Path: "/etc/sudoers.d/deploy", Readable: false}},
		SudoList: map[string][]string{
			"root": {"Matching Defaults entries for root on lab:", "    env_reset, mail_badpass",
				"User root may run the following commands on lab:", "    (ALL : ALL) ALL"},
			"discover-admin": {"User discover-admin may run the following commands on lab:", "    (root) NOPASSWD: list"},
			"orders-svc-a":   {"User orders-svc-a may run the following commands on lab:", "    (ALL : ALL) ALL"},
			"orders-single": {"Matching Defaults entries for orders-single on lab:", "    secure_path=/usr/sbin\\:/usr/bin",
				"User orders-single may run the following commands on lab:", "    (root) NOPASSWD: /usr/bin/systemctl restart app"},
			"plain": {"User plain is not allowed to run sudo on lab."},
		},
	}
	got := map[string]Account{}
	for _, a := range HostAccounts(inv) {
		got[a.Name] = a
	}
	want := map[string][]string{
		"root":          {"group:root", "sudo:ALL", "uid0"},
		"orders-svc-a":  {"group:sudo", "sudo:ALL"},
		"orders-single": {"sudo:commands"},
	}
	// sudo refused to list ops-unlisted: its group shows, its sudo rights
	// stay unknown.
	if a := got["ops-unlisted"]; !reflect.DeepEqual(a.Privileges, []string{"group:sudo"}) || a.Details["sudoers"] != "unreadable" {
		t.Fatalf("an account sudo would not list reads %v %v", a.Privileges, a.Details)
	}
	delete(got, "ops-unlisted")
	if len(got) != len(want) {
		t.Fatalf("privileged accounts = %v", got)
	}
	for name, privileges := range want {
		if !reflect.DeepEqual(got[name].Privileges, privileges) || got[name].Details["sudoers"] != "listed by sudo" {
			t.Fatalf("%s = %v %v, want %v listed by sudo", name, got[name].Privileges, got[name].Details, privileges)
		}
	}
	// Without a listing the rights stay unknown; with readable files the
	// listing is not read.
	inv.SudoList = nil
	if a := accountNamed(HostAccounts(inv), "orders-svc-a"); a.Details["sudoers"] != "unreadable" || slicesContain(a.Privileges, "sudo:ALL") {
		t.Fatalf("without a listing orders-svc-a reads %v %v", a.Privileges, a.Details)
	}
}

func accountNamed(accounts []Account, name string) Account {
	for _, a := range accounts {
		if a.Name == name {
			return a
		}
	}
	return Account{}
}

func slicesContain(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
