// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/base64"
	"os/exec"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
)

func TestServedADImportedUnicodeRecoveryA267(t *testing.T) {
	testServedADStaticRotationRollbackA267(t, true)
}

// Seed independently through a stock LDAPS client. No password is passed in
// argv, the environment or a file; only the existing admin reference is named.
func seedADUnicodePredecessor(t *testing.T, dn string, password []byte) {
	t.Helper()
	quoted, err := secret.New(4 + len(password)*2)
	if err != nil {
		t.Fatal(err)
	}
	defer quoted.Destroy()
	raw := quoted.Bytes()
	raw[0] = '"'
	used := 2
	put := func(v uint16) { raw[used] = byte(v & 0xff); raw[used+1] = byte(v >> 8); used += 2 }
	for cursor := 0; cursor < len(password); {
		r, n := utf8.DecodeRune(password[cursor:])
		if r == utf8.RuneError && n == 1 {
			t.Fatal("invalid fixture UTF-8")
		}
		cursor += n
		if r <= 0xffff {
			put(uint16(r & 0xffff))
		} else {
			r -= 0x10000
			put(0xd800 | uint16((r>>10)&0x3ff))
			put(uint16(0xdc00 + (r & 0x3ff)))
		}
	}
	put('"')
	prefix := []byte("dn: " + dn + "\nchangetype: modify\nreplace: unicodePwd\nunicodePwd:: ")
	encoded, err := secret.New(len(prefix) + base64.StdEncoding.EncodedLen(used) + 3)
	if err != nil {
		t.Fatal(err)
	}
	defer encoded.Destroy()
	wire := encoded.Bytes()
	copy(wire, prefix)
	base64.StdEncoding.Encode(wire[len(prefix):len(wire)-3], raw[:used])
	copy(wire[len(wire)-3:], []byte("\n-\n"))
	cmd := exec.CommandContext(t.Context(), "/usr/bin/ldapmodify", "-x", "-H", "ldaps://ad263:636", "-D", "CN=Administrator,CN=Users,DC=a263,DC=test", "-y", "/run/ad-admin-password")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LDAPTLS_CACERT=/run/ad-ca.pem"}
	cmd.Stdin = bytes.NewReader(wire)
	if err := cmd.Run(); err != nil {
		t.Fatal("stock native Unicode seed failed")
	}
	if output, err := servedADStockRead(t.Context(), password, dn); err != nil || !bytes.Contains(bytes.ToLower(output), []byte("a267-served")) {
		t.Fatal("stock native Unicode sign-in failed before rotation")
	}
}
