// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"encoding/pem"
	"testing"
)

// FuzzParsePublicKeyPEM exercises the exact boundary used by broker and
// workload issuance, not merely another parser in the same package.
func FuzzParsePublicKeyPEM(f *testing.F) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	public := MarshalPublicKeyPEM(key.Public().DER)
	key.Destroy()
	for _, seed := range [][]byte{
		{}, []byte("not a key"), public,
		append(append([]byte{}, public...), public...),
		append([]byte("junk\n"), public...),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := ParsePublicKeyPEM(input)
		if err != nil {
			return
		}
		block, rest := pem.Decode(bytes.TrimSpace(input))
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(got.DER, block.Bytes) {
			t.Fatal("accepted public key lost its exact single-block meaning")
		}
		canonical := MarshalPublicKeyPEM(got.DER)
		roundTrip, err := ParsePublicKeyPEM(canonical)
		if err != nil || roundTrip.Algorithm != got.Algorithm || !bytes.Equal(roundTrip.DER, got.DER) {
			t.Fatal("valid key changed during canonical round trip")
		}
		for _, ambiguous := range [][]byte{
			append([]byte("untrusted prelude\n"), input...),
			append(append([]byte{}, canonical...), canonical...),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Untrusted": "header"}, Bytes: got.DER}),
		} {
			if _, err := ParsePublicKeyPEM(ambiguous); err == nil {
				t.Fatal("ambiguous key envelope accepted")
			}
		}
	})
}
