package jose

// PROTECT track (sprint R11): permanent regression guards that LOCK the soundness of
// the JOSE/JWS verifier (SEC-009 / INTEROP-S4 / PKIGOV-INFO). The audit confirmed the
// verifier is sound — it hard-pins alg==RS256, rejects alg=none and alg-confusion,
// and returns the rsa.VerifyPKCS1v15 error directly — but the SEC-009 fix-spec asks
// for alg=none and alg-confusion to be encoded as *permanent* negative tests so the
// soundness cannot silently regress (the original tamper test only mutated the
// signature/payload). These add NO behavior; they fail if the verifier ever stops
// rejecting an unsigned or wrong-algorithm token.
//
// The names are deliberately distinct from jose_test.go's so this guard can be added
// without touching that file.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var algB64 = base64.RawURLEncoding

// craftJWS assembles a compact JWS with an attacker-chosen header and a signature
// segment supplied verbatim, so a test can forge alg=none / alg-confusion tokens the
// way a real attacker would (the production signer never produces these).
func craftJWS(t *testing.T, header map[string]any, payload []byte, sig []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return algB64.EncodeToString(hb) + "." + algB64.EncodeToString(payload) + "." + algB64.EncodeToString(sig)
}

// TestJOSEVerifierRejectsAlgNone is the SEC-009 lock for the classic "alg":"none"
// downgrade: a token whose header declares no signature algorithm (with an empty
// signature) must be rejected, never accepted as authentic. The verifier pins
// alg==RS256, so this must fail closed.
func TestJOSEVerifierRejectsAlgNone(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set, _ := NewJWKSet("k", key.Public())

	payload := []byte(`{"sub":"attacker","admin":true}`)
	for _, alg := range []string{"none", "None", "NONE", ""} {
		token := craftJWS(t, map[string]any{"alg": alg, "kid": "k"}, payload, []byte{})
		if _, err := set.Verify(token); err == nil {
			t.Errorf("Verify accepted an alg=%q (unsigned) token — the alg=none downgrade is not rejected", alg)
		}
	}
}

// TestJOSEVerifierRejectsHS256Confusion is the SEC-009 lock for the RS256->HS256
// algorithm-confusion attack: an attacker who knows the RSA *public* key forges an
// HS256 MAC using the public key bytes as the HMAC secret and labels the token
// HS256. A verifier that branched on the header alg and treated the RSA public key as
// an HMAC secret would accept it. trustctl's verifier pins alg==RS256, so the forged
// HS256 token (even with a valid MAC under the public key) must be rejected.
func TestJOSEVerifierRejectsHS256Confusion(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set, _ := NewJWKSet("k", key.Public())

	payload := []byte(`{"sub":"attacker"}`)
	// Forge an HS256 MAC using the RSA public modulus bytes as the "secret" — the
	// canonical confusion-attack construction.
	header := map[string]any{"alg": "HS256", "kid": "k"}
	hb, _ := json.Marshal(header)
	signingInput := algB64.EncodeToString(hb) + "." + algB64.EncodeToString(payload)
	mac := hmac.New(sha256.New, key.PublicKey.N.Bytes())
	mac.Write([]byte(signingInput))
	token := signingInput + "." + algB64.EncodeToString(mac.Sum(nil))

	if _, err := set.Verify(token); err == nil {
		t.Error("Verify accepted an HS256-labelled token MAC'd with the RSA public key — RS256->HS256 confusion is not rejected")
	}
	// The rejection must be on algorithm grounds (the verifier never reaches a MAC
	// check), so the error mentions the unsupported alg.
	_, err := set.Verify(token)
	if err == nil || !strings.Contains(err.Error(), "unsupported alg") {
		t.Errorf("HS256-confusion rejection should cite the unsupported alg; got %v", err)
	}
}

// TestJOSEVerifierRejectsUnknownAlg is the SEC-009 lock against a header advertising
// any algorithm other than RS256 (e.g. ES256, PS256, RS512): the verifier must
// reject rather than silently accept or attempt a different scheme.
func TestJOSEVerifierRejectsUnknownAlg(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	set, _ := NewJWKSet("k", key.Public())

	// Take a genuinely-valid RS256 token, then swap only its header alg to something
	// else. The signature stays valid for RS256, so the ONLY thing that can save us is
	// the alg pin.
	valid, err := SignRS256(key, "k", []byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWS, got %d", len(parts))
	}
	for _, alg := range []string{"ES256", "PS256", "RS384", "RS512", "rs256"} {
		hb, _ := json.Marshal(map[string]any{"alg": alg, "kid": "k"})
		forged := algB64.EncodeToString(hb) + "." + parts[1] + "." + parts[2]
		if _, err := set.Verify(forged); err == nil {
			t.Errorf("Verify accepted a token with alg=%q (only RS256 must be honored)", alg)
		}
	}
}

// TestACMEJOSEVerifierRejectsAlgConfusion locks the SAME soundness for the ACME JWS
// account-key path (INTEROP-S4 / SEC-009): with an RSA account key, the verifier
// pins alg==RS256 (acme.go), so alg=none and an HS256-confusion attempt must both be
// rejected rather than authenticated. It drives the real served API surface:
// ParseACMEJWS -> ACMEKeyFromJWK -> ACMEMessage.Verify.
func TestACMEJOSEVerifierRejectsAlgConfusion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := json.RawMessage(jwkJSON(&key.PublicKey)) // RSA JWK, reusing acme_test.go's helper
	akey, err := ACMEKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("ACMEKeyFromJWK: %v", err)
	}
	payload := []byte(`{"termsOfServiceAgreed":true}`)

	// alg=none: an unsigned flattened JWS must not verify against the RSA key.
	{
		ph, _ := json.Marshal(map[string]any{"alg": "none", "jwk": jwk, "nonce": "n", "url": "u"})
		body := acmeFlattenedRaw(algB64.EncodeToString(ph), algB64.EncodeToString(payload), "")
		msg, perr := ParseACMEJWS(body)
		if perr != nil {
			t.Fatalf("ParseACMEJWS(alg=none): %v", perr)
		}
		if verr := msg.Verify(akey); verr == nil {
			t.Error("ACME Verify accepted an alg=none account-key JWS")
		}
	}

	// HS256 confusion: forge an HMAC under the RSA public modulus and label it HS256.
	{
		ph, _ := json.Marshal(map[string]any{"alg": "HS256", "jwk": jwk, "nonce": "n", "url": "u"})
		phB64 := algB64.EncodeToString(ph)
		plB64 := algB64.EncodeToString(payload)
		mac := hmac.New(sha256.New, key.PublicKey.N.Bytes())
		mac.Write([]byte(phB64 + "." + plB64))
		body := acmeFlattenedRaw(phB64, plB64, algB64.EncodeToString(mac.Sum(nil)))
		msg, perr := ParseACMEJWS(body)
		if perr != nil {
			t.Fatalf("ParseACMEJWS(HS256): %v", perr)
		}
		if verr := msg.Verify(akey); verr == nil {
			t.Error("ACME Verify accepted an HS256-confusion account-key JWS (RSA key + HS256 alg)")
		}
	}
}

// acmeFlattenedRaw assembles the flattened JWS JSON from already-encoded segments.
func acmeFlattenedRaw(protectedB64, payloadB64, sigB64 string) []byte {
	body, _ := json.Marshal(map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": sigB64,
	})
	return body
}
