// SPDX-License-Identifier: BUSL-1.1

package sshkeys_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

func wireBlob(t testing.TB, authorized string) []byte {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(strings.Fields(authorized)[1])
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// ParseWireKey reads the wire-format blob a KRL carries for an explicitly
// revoked key, and refuses bytes that are not a key.
func TestParseWireKey(t *testing.T) {
	for _, tc := range []struct{ authorized, typ, fp string }{
		{edPub, "ssh-ed25519", edFP}, {rsaPub, "ssh-rsa", rsaFP}, {ecPub, "ecdsa-sha2-nistp256", ecFP},
	} {
		info, err := sshkeys.ParseWireKey(wireBlob(t, tc.authorized))
		if err != nil || info.Type != tc.typ || info.FingerprintSHA256 != tc.fp {
			t.Fatalf("ParseWireKey(%s) = %+v, %v", tc.typ, info, err)
		}
	}
	for _, bad := range [][]byte{nil, []byte("not a key"), wireBlob(t, edPub)[:20]} {
		if _, err := sshkeys.ParseWireKey(bad); err == nil {
			t.Fatalf("ParseWireKey accepted %q", bad)
		}
	}
}
