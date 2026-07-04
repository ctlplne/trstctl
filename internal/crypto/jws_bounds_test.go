// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func jwksBoundsDoc(t *testing.T, keys ...map[string]string) []byte {
	t.Helper()
	doc := map[string]any{"keys": keys}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jwksRSADoc(t *testing.T, kid string, n, e []byte) []byte {
	t.Helper()
	return jwksBoundsDoc(t, map[string]string{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(n),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	})
}

func jwksECKey(crv string, x, y []byte) map[string]string {
	return map[string]string{
		"kty": "EC",
		"kid": "ec",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

func rsaModulusBits(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	return n.Bytes()
}

// TestParseJWKSRejectsOversized is the FUZZ-008 acceptance for the top-level
// workload JWT helper: a JWK whose modulus is far larger than any accepted RSA key
// is rejected at parse time instead of being retained for later big-int work.
func TestParseJWKSRejectsOversized(t *testing.T) {
	huge := rsaModulusBits(16384)
	doc := jwksRSADoc(t, "big", huge, big.NewInt(65537).Bytes())
	if _, err := ParseJWKS(doc); err == nil {
		t.Fatal("ParseJWKS accepted a 16384-bit RSA modulus")
	} else if !strings.Contains(err.Error(), "modulus") {
		t.Fatalf("ParseJWKS error = %v, want modulus-size rejection", err)
	}
}

func TestParseJWKSRejectsTinyRSA(t *testing.T) {
	doc := jwksRSADoc(t, "small", rsaModulusBits(1024), big.NewInt(65537).Bytes())
	if _, err := ParseJWKS(doc); err == nil {
		t.Fatal("ParseJWKS accepted a 1024-bit RSA modulus")
	}
}

func TestParseJWKSRejectsBadRSAExponent(t *testing.T) {
	n := rsaModulusBits(2048)
	for _, tc := range []struct {
		name string
		e    *big.Int
	}{
		{name: "one", e: big.NewInt(1)},
		{name: "even", e: big.NewInt(4)},
		{name: "huge", e: new(big.Int).Lsh(big.NewInt(1), 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJWKS(jwksRSADoc(t, tc.name, n, tc.e.Bytes())); err == nil {
				t.Fatalf("ParseJWKS accepted RSA exponent %s", tc.e.String())
			}
		})
	}

	if _, err := ParseJWKS(jwksRSADoc(t, "ok", n, big.NewInt(65537).Bytes())); err != nil {
		t.Fatalf("ParseJWKS rejected a bounded RSA JWK: %v", err)
	}
}

// TestParseJWKSRejectsHugeKeyCount is the FUZZ-008 acceptance for key-count
// amplification: the parser rejects over-cap documents before doing per-key work.
func TestParseJWKSRejectsHugeKeyCount(t *testing.T) {
	keys := make([]map[string]string, 0, jwksMaxKeys+1)
	for i := 0; i < jwksMaxKeys+1; i++ {
		keys = append(keys, map[string]string{
			"kty": "RSA",
			"kid": fmt.Sprintf("k%d", i),
			"n":   "AQAB",
			"e":   "AQAB",
		})
	}
	if _, err := ParseJWKS(jwksBoundsDoc(t, keys...)); err == nil {
		t.Fatal("ParseJWKS accepted a JWKS over the key-count cap")
	} else if !strings.Contains(err.Error(), "key cap") {
		t.Fatalf("ParseJWKS error = %v, want key-count rejection", err)
	}
}

func TestParseJWKSRejectsInvalidECPoint(t *testing.T) {
	if _, err := ParseJWKS(jwksBoundsDoc(t, jwksECKey("P-256", []byte{1}, []byte{2}))); err == nil {
		t.Fatal("ParseJWKS accepted undersized EC coordinates")
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	x[31] = 1
	y[31] = 1
	if _, err := ParseJWKS(jwksBoundsDoc(t, jwksECKey("P-256", x, y))); err == nil {
		t.Fatal("ParseJWKS accepted an EC point that is not on the declared curve")
	}

	curve, size := ecCurve("P-256")
	//nolint:staticcheck // This bounds test needs a deterministic valid legacy ECDSA affine point.
	vx, vy := curve.ScalarBaseMult([]byte{1})
	xb := make([]byte, size)
	yb := make([]byte, size)
	vx.FillBytes(xb)
	vy.FillBytes(yb)
	if _, err := ParseJWKS(jwksBoundsDoc(t, jwksECKey("P-256", xb, yb))); err != nil {
		t.Fatalf("ParseJWKS rejected a valid P-256 JWK: %v", err)
	}
}
