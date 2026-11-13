// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseSSHAccountInventoryA260: the inventory's framed sections become
// account and group lines, sudoers files (or that one was unreadable) and
// each account's authorized keys as type and fingerprint only; output that
// stops before its end marker is refused.
func TestParseSSHAccountInventoryA260(t *testing.T) {
	raw := strings.Join([]string{
		"=== passwd",
		"root:x:0:0:root:/root:/bin/bash",
		"alice:x:1000:1000::/home/alice:/bin/bash",
		"=== group",
		"sudo:x:27:alice",
		"=== sudoers",
		"--- /etc/sudoers",
		"root ALL=(ALL:ALL) ALL",
		"",
		"--- /etc/sudoers.d/locked unreadable",
		"=== keys",
		"--- alice",
		"# a comment",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEONBEKOQaw/bt2mEQDmf9AQ68I5RY375vL/1Fe94Slh alice@lab",
		`from="10.0.0.0/8",no-pty ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6UiOzCUKMXMPaGQ3pH7FQEjY4DgBzEvVSIgotafOnSo4ZQfbmLQDHFsQI8Z0jczvlg9mZiJL2AULsQD9dsQ+k= ops`,
		"not a key",
		"--- bob unreadable",
		"=== end",
	}, "\n")
	inv, err := parseSSHAccountInventory([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Passwd) != 2 || len(inv.Group) != 1 {
		t.Fatalf("passwd %v group %v", inv.Passwd, inv.Group)
	}
	wantSudoers := []SSHSudoersFile{
		{Path: "/etc/sudoers", Readable: true, Lines: []string{"root ALL=(ALL:ALL) ALL"}},
		{Path: "/etc/sudoers.d/locked"},
	}
	if !reflect.DeepEqual(inv.Sudoers, wantSudoers) {
		t.Fatalf("sudoers = %+v", inv.Sudoers)
	}
	wantKeys := []SSHAccountKeys{
		{Account: "alice", Readable: true, Keys: []SSHAuthorizedKey{
			{Type: "ssh-ed25519", Fingerprint: "SHA256:ZUpKtGMGRETPHM0PB9T33QPyS819RJFBPoNlAV+BA3Q"},
			{Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:xZ/3t6If1k25Lw1juRgX41DYQ3VVjNpgd4ZA+LSlzPE", Restricted: true},
		}},
		{Account: "bob"},
	}
	if !reflect.DeepEqual(inv.Keys, wantKeys) {
		t.Fatalf("keys = %+v", inv.Keys)
	}
	if _, err := parseSSHAccountInventory([]byte("=== passwd\nroot:x:0:0::/root:/bin/sh\n")); err == nil {
		t.Fatal("an inventory with no end marker was accepted")
	}
}

// TestParseSSHAccountInventoryKeyFilesA260L2: the inventory names the
// AuthorizedKeysFile patterns sshd reads and whether an
// AuthorizedKeysCommand is set; an older host's inventory without that
// section still parses.
func TestParseSSHAccountInventoryKeyFilesA260L2(t *testing.T) {
	inv, err := parseSSHAccountInventory([]byte(strings.Join([]string{
		"=== passwd", "alice:x:1000:1000::/home/alice:/bin/bash",
		"=== sshd", "files /etc/ssh/keys.d/%u   %h/.ssh/authorized_keys", "command",
		"=== keys", "--- alice",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEONBEKOQaw/bt2mEQDmf9AQ68I5RY375vL/1Fe94Slh alice@central",
		"=== end",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inv.KeyFiles, []string{"/etc/ssh/keys.d/%u", "%h/.ssh/authorized_keys"}) || !inv.KeysCommand || len(inv.Keys) != 1 || len(inv.Keys[0].Keys) != 1 {
		t.Fatalf("inventory = %+v", inv)
	}
	older, err := parseSSHAccountInventory([]byte("=== passwd\nroot:x:0:0::/root:/bin/sh\n=== keys\n=== end\n"))
	if err != nil || older.KeyFiles != nil || older.KeysCommand {
		t.Fatalf("an inventory without the sshd section = %+v, %v", older, err)
	}
}

// A260-L3: the inventory's sudo-list section carries sudo's own listing per
// login account, kept apart from the sudoers files it stands in for; an
// inventory from before it has none.
func TestParseSSHAccountInventorySudoListA260L3(t *testing.T) {
	inv, err := parseSSHAccountInventory([]byte(strings.Join([]string{
		"=== passwd", "orders-single:x:1002:1002::/home/orders-single:/bin/bash",
		"=== sudoers", "--- /etc/sudoers unreadable",
		"=== sudo-list",
		"--- orders-single",
		"User orders-single may run the following commands on lab:",
		"    (root) NOPASSWD: /usr/bin/systemctl restart app",
		"",
		"--- plain",
		"User plain is not allowed to run sudo on lab.",
		"--- refused unlisted",
		"=== end",
	}, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, refused := inv.SudoList["refused"]; refused || len(inv.SudoList) != 2 || len(inv.SudoList["orders-single"]) != 2 ||
		inv.SudoList["plain"][0] != "User plain is not allowed to run sudo on lab." {
		t.Fatalf("sudo list = %#v", inv.SudoList)
	}
	if len(inv.Sudoers) != 1 || inv.Sudoers[0].Readable {
		t.Fatalf("sudoers = %+v", inv.Sudoers)
	}
	older, err := parseSSHAccountInventory([]byte("=== passwd\nroot:x:0:0::/root:/bin/sh\n=== end\n"))
	if err != nil || older.SudoList != nil {
		t.Fatalf("an inventory without the section: %#v %v", older.SudoList, err)
	}
	// Every sudo the script runs reads /dev/null: the script itself is on
	// stdin.
	for _, line := range strings.Split(sshAccountInventoryScript, "\n") {
		if strings.Contains(line, "sudo -n") && !strings.Contains(line, "</dev/null") {
			t.Fatalf("a sudo call that could read the script from stdin: %q", line)
		}
	}
}
