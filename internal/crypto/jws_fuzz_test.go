// SPDX-License-Identifier: BUSL-1.1

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
	f.Add("spiffe://example.org/ns%2Fqa")
	f.Add("spiffe://example.org:443/a")
	f.Add("spiffe://example.org/a/../b")
	f.Add("spiffe://example.org/a?")
	f.Fuzz(func(t *testing.T, id string) {
		u, err := ParseSPIFFEID(id)
		if err != nil {
			return
		}
		if u.String() != id || len(id) > MaxSPIFFEIDLength || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || u.Opaque != "" {
			t.Fatal("accepted SPIFFE identity is not an unchanged canonical wire value")
		}
		again, err := ParseSPIFFEID(u.String())
		if err != nil || *again != *u {
			t.Fatal("canonical SPIFFE parser is not stable")
		}
	})
}

func FuzzDecodeWorkloadSPIFFESegment(f *testing.F) {
	for _, seed := range []string{"", "web", "trstctl-hex-613a62", "trstctl-hex-7472737463746c2d6865782d61", "trstctl-hex-2e", "a/b", "trstctl-hex-776562"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		raw, err := DecodeWorkloadSPIFFESegment(wire)
		if err != nil {
			return
		}
		encoded, err := EncodeWorkloadSPIFFESegment(raw)
		if err != nil || encoded != wire {
			t.Fatal("accepted workload segment does not round-trip byte-for-byte")
		}
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
