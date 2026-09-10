// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func FuzzParsePublicPEMChain(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"), []byte("abc"))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, raw, expected []byte) {
		out, err := certinfo.ParsePublicPEMChain(raw, expected)
		if err != nil {
			return
		}
		leaf, leafErr := certinfo.LeafDER(out)
		if leafErr != nil || !bytes.Equal(leaf, expected) || len(out) > certinfo.MaxPublicChainBytes {
			t.Fatal("public chain success changed exact bounded leaf identity")
		}
	})
}
