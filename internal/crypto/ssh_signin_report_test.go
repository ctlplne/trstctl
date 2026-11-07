// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// TestSSHSignInScriptA274: the sign-in report's scripts name the accounts as
// fixed strings or quoted literals only, refuse a name that could break out
// of them, and read nothing but sign-in records.
func TestSSHSignInScriptA274(t *testing.T) {
	since := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	script, err := SSHSignInScript(false, []string{"orders-single", "app.reader"}, since)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"grep -F -e 'for orders-single from ' -e 'for app.reader from '", "--since '@1794074400'", "/var/log/auth.log", "=== end"} {
		if !strings.Contains(script, want) {
			t.Fatalf("the Linux script lacks %q:\n%s", want, script)
		}
	}
	for _, forbidden := range []string{"/etc/shadow", "authorized_keys", "history", "chpasswd"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the Linux script reads %q", forbidden)
		}
	}
	command, err := SSHSignInScript(true, []string{"svc-sql"}, since)
	if err != nil {
		t.Fatal(err)
	}
	encoded, ok := strings.CutPrefix(command, "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ")
	if !ok {
		t.Fatalf("the Windows command: %s", command)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw)%2 != 0 {
		t.Fatal("not UTF-16LE base64")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	decoded := string(utf16.Decode(units))
	for _, want := range []string{"$accounts = @('svc-sql')", "Id=4624", "'2026-11-07T18:00:00Z'", "=== end"} {
		if !strings.Contains(decoded, want) {
			t.Fatalf("the Windows script lacks %q:\n%s", want, decoded)
		}
	}
	for _, bad := range [][]string{nil, {"a'b"}, {"a b"}, {"$(id)"}, {"a;b"}, {"a`b"}} {
		if _, err := SSHSignInScript(false, bad, since); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
