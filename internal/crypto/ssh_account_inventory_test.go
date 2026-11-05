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
