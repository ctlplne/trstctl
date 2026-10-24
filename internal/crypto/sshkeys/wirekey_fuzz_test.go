// SPDX-License-Identifier: BUSL-1.1

package sshkeys

import (
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzParseWireKey(f *testing.F) {
	// ssh-ed25519 and ecdsa-sha2-nistp256 wire blobs, then a bare length.
	for _, encoded := range []string{
		"AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt",
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCTRiePj3JSBO27Q7RQcNOhLFvuJVqXzGAJAradHGDPH3fXi2KBp0c2FK8o5YYdngfTuUexh06+qAZXDqkxVmbY=",
	} {
		blob, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(blob)
	}
	f.Add([]byte{0, 0, 0, 11})
	f.Fuzz(func(t *testing.T, blob []byte) {
		if info, err := ParseWireKey(blob); err == nil && (info.Type == "" || !strings.HasPrefix(info.FingerprintSHA256, "SHA256:")) {
			t.Fatalf("parsed key without type or fingerprint: %+v", info)
		}
	})
}
