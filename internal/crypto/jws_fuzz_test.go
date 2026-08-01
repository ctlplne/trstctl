// SPDX-License-Identifier: MPL-2.0

package crypto

import "testing"

// These fuzz the untrusted-input parsers added for SPIFFE/JWT-SVID and the OIDC/
// SAT attesters (TEST-FUZZASSERT-001: fuzz every parser that touches untrusted input). The
// property under test is "never panics on arbitrary input" — a malformed token
// from a hostile client must fail closed, not crash the process.

func FuzzVerifyJWT(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add("not-a-jwt")
	f.Add("eyJ.eyJ.")
	jwks := JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k", N: "AQAB", E: "AQAB"}}}
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = VerifyJWT(token, jwks)
	})
}

func FuzzParseSPIFFEID(f *testing.F) {
	f.Add("spiffe://example.org/ns/default/sa/web")
	f.Add("")
	f.Add("://bad")
	f.Add("spiffe://")
	f.Fuzz(func(t *testing.T, id string) {
		_, _ = ParseSPIFFEID(id)
	})
}

func FuzzParseJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		jwks, err := ParseJWKS(b)
		if err != nil {
			return
		}
		if len(jwks.Keys) > jwksMaxKeys {
			t.Fatalf("ParseJWKS accepted %d keys, cap is %d", len(jwks.Keys), jwksMaxKeys)
		}
		for i, k := range jwks.Keys {
			if err := k.validatePublicKey(); err != nil {
				t.Fatalf("ParseJWKS returned unvalidated key %d: %v", i, err)
			}
		}
	})
}
