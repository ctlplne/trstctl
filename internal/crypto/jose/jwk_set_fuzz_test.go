// SPDX-License-Identifier: BUSL-1.1

package jose

import "testing"

func FuzzParseJWKSet(f *testing.F) {
	key, err := GenerateRSASigningKey("public-verification-fuzz")
	if err != nil {
		f.Fatal(err)
	}
	public, err := key.PublicJWKS()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(public)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"invalid","n":"AQ","e":"AQAB"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		set, err := ParseJWKSet(wire)
		if err != nil {
			return
		}
		if set == nil || len(set.keys) == 0 || len(set.keys) > maxJWKSKeys {
			t.Fatal("accepted public trust has no bounded key set")
		}
		for kid, public := range set.keys {
			encoded, err := MarshalPublicJWKS(kid, public)
			if err != nil {
				t.Fatalf("accepted public trust cannot be exported: %v", err)
			}
			again, err := ParseJWKSet(encoded)
			if err != nil {
				t.Fatalf("exported public trust cannot be parsed: %v", err)
			}
			recovered := again.keys[kid]
			if len(again.keys) != 1 || recovered == nil || recovered.E != public.E || recovered.N.Cmp(public.N) != 0 {
				t.Fatal("public trust changed identity during export and parse")
			}
		}
	})
}
