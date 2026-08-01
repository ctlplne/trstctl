// SPDX-License-Identifier: MPL-2.0

package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// jwksDoc renders a JWKS document with one RSA key from raw modulus/exponent bytes,
// so a test can present an out-of-bounds key without rsa.GenerateKey refusing to
// build it.
func jwksDoc(t *testing.T, kid string, nb, eb []byte) []byte {
	t.Helper()
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(nb),
		"e": base64.RawURLEncoding.EncodeToString(eb),
	}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParseJWKSetRejectsOversizedModulus is the FUZZ-006 acceptance: a JWK whose
// modulus is far larger than any real RSA key is rejected, so an attacker-supplied
// giant modulus cannot turn every verification into an unbounded big-int CPU sink.
// Pre-fix ParseJWKSet built the key with no bit-length bound and accepted it.
func TestParseJWKSetRejectsOversizedModulus(t *testing.T) {
	// A 16384-bit modulus (2x the cap).
	huge := new(big.Int).Lsh(big.NewInt(1), 16384-1)
	huge.SetBit(huge, 0, 1) // make it odd
	doc := jwksDoc(t, "big", huge.Bytes(), big.NewInt(65537).Bytes())
	if _, err := ParseJWKSet(doc); err == nil {
		t.Error("ParseJWKSet accepted a 16384-bit modulus (no upper bound)")
	} else if !strings.Contains(err.Error(), "bits") {
		t.Errorf("unexpected error %v; want a modulus-size rejection", err)
	}
}

// TestParseJWKSetRejectsTinyModulus: a sub-2048-bit modulus is too weak to trust
// and is rejected.
func TestParseJWKSetRejectsTinyModulus(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- deliberately undersized key; the test proves the verifier refuses it (CWE-326)
	if err != nil {
		t.Fatal(err)
	}
	doc := jwksDoc(t, "small", small.N.Bytes(), big.NewInt(int64(small.E)).Bytes())
	if _, err := ParseJWKSet(doc); err == nil {
		t.Error("ParseJWKSet accepted a 1024-bit modulus (below the floor)")
	}
}

// TestParseJWKSetRejectsBadExponent is the FUZZ-006 acceptance for the exponent: an
// even exponent and an oversized exponent (which the old int(...Int64()) cast could
// silently truncate) are both rejected.
func TestParseJWKSetRejectsBadExponent(t *testing.T) {
	good, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Even exponent.
	if _, err := ParseJWKSet(jwksDoc(t, "even", good.N.Bytes(), big.NewInt(4).Bytes())); err == nil {
		t.Error("ParseJWKSet accepted an even RSA exponent")
	}

	// Exponent = 1 (too small).
	if _, err := ParseJWKSet(jwksDoc(t, "one", good.N.Bytes(), big.NewInt(1).Bytes())); err == nil {
		t.Error("ParseJWKSet accepted exponent 1")
	}

	// Oversized exponent (2^40): must be rejected, not truncated into a small odd int.
	big40 := new(big.Int).Lsh(big.NewInt(1), 40)
	if _, err := ParseJWKSet(jwksDoc(t, "huge-e", good.N.Bytes(), big40.Bytes())); err == nil {
		t.Error("ParseJWKSet accepted an oversized exponent (would truncate via Int64)")
	}

	// A normal key still parses.
	if _, err := ParseJWKSet(jwksDoc(t, "ok", good.N.Bytes(), big.NewInt(int64(good.E)).Bytes())); err != nil {
		t.Errorf("ParseJWKSet rejected a valid 2048-bit/65537 key: %v", err)
	}
}

// TestParseJWKSetRejectsHugeKeyCount is the FUZZ-006 acceptance: a JWKS that
// declares an absurd number of keys is rejected before iteration, so allocation is
// not tied to attacker-controlled document size.
func TestParseJWKSetRejectsHugeKeyCount(t *testing.T) {
	var keys []map[string]any
	for i := 0; i < maxJWKSKeys+50; i++ {
		keys = append(keys, map[string]any{"kty": "RSA", "kid": fmt.Sprintf("k%d", i), "n": "AQAB", "e": "AQAB"})
	}
	doc, _ := json.Marshal(map[string]any{"keys": keys})
	if _, err := ParseJWKSet(doc); err == nil {
		t.Error("ParseJWKSet accepted a JWKS far over the key-count cap")
	}
}

// TestACMEKeyFromJWKBoundsRSA is the FUZZ-006 acceptance on the ACME account-key
// path: ACMEKeyFromJWK enforces the same modulus/exponent bounds, so an ACME client
// cannot register an absurd RSA account key. A valid 2048-bit/65537 key still parses.
func TestACMEKeyFromJWKBoundsRSA(t *testing.T) {
	rsaJWK := func(n, e *big.Int) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`,
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
			base64.RawURLEncoding.EncodeToString(e.Bytes())))
	}

	// Oversized modulus (16384 bits) -> rejected.
	huge := new(big.Int).Lsh(big.NewInt(1), 16384-1)
	huge.SetBit(huge, 0, 1)
	if _, err := ACMEKeyFromJWK(rsaJWK(huge, big.NewInt(65537))); err == nil {
		t.Error("ACMEKeyFromJWK accepted a 16384-bit RSA account key")
	}

	// Even exponent -> rejected.
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ACMEKeyFromJWK(rsaJWK(good.N, big.NewInt(4))); err == nil {
		t.Error("ACMEKeyFromJWK accepted an even RSA exponent")
	}

	// Valid key -> accepted.
	if _, err := ACMEKeyFromJWK(rsaJWK(good.N, big.NewInt(int64(good.E)))); err != nil {
		t.Errorf("ACMEKeyFromJWK rejected a valid 2048-bit/65537 account key: %v", err)
	}
}
