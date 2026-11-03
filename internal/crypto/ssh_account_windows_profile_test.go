// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// A240: the Windows profile's command line names only the account, inside
// its encoded Set-LocalUser script; the password goes to stdin.
func TestSSHWindowsCommandNamesOnlyTheAccountA240(t *testing.T) {
	const prefix = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	command := sshWindowsCommand("orders_app_a")
	encoded, ok := strings.CutPrefix(command, prefix)
	if !ok || strings.ContainsAny(encoded, " \t") {
		t.Fatalf("command = %q", command)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("the script is not base64 UTF-16LE: %v", err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	script := string(utf16.Decode(units))
	for _, want := range []string{"Set-LocalUser -Name 'orders_app_a' -Password $password", "[Console]::In.ReadToEnd()", "$ErrorActionPreference = 'Stop'"} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q:\n%s", want, script)
		}
	}
}

// A Windows local account name has at most 20 characters; a longer one is
// refused before any connection.
func TestSSHWindowsAccountNamesAreBoundedA240(t *testing.T) {
	target := SSHAccountTarget{Address: "127.0.0.1:1", AdminUser: "trstctl_admin", HostKeyFingerprint: "SHA256:x", Windows: true}
	err := SetSSHAccountPassword(context.Background(), target, []byte("unused"), "a_windows_name_over_20", []byte("Abc123"))
	if err == nil || !strings.Contains(err.Error(), "at most 20 characters") {
		t.Fatalf("a 22-character Windows account: %v", err)
	}
}
