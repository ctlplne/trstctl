package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRS256RoundTripViaJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"sub":"alice","iss":"https://idp.example"}`)
	token, err := SignRS256(key, "kid-1", payload)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}

	set, err := NewJWKSet("kid-1", key.Public())
	if err != nil {
		t.Fatalf("NewJWKSet: %v", err)
	}
	got, err := set.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}

	// A JWKS that does not contain the signing key must reject the token.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrong, _ := NewJWKSet("kid-1", other.Public())
	if _, err := wrong.Verify(token); err == nil {
		t.Error("Verify accepted a token signed by a key absent from the JWKS")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token, _ := SignRS256(key, "k", []byte(`{"sub":"alice"}`))
	set, _ := NewJWKSet("k", key.Public())

	// Flip the last character of the payload segment.
	bad := token[:len(token)-30] + "x" + token[len(token)-29:]
	if _, err := set.Verify(bad); err == nil {
		t.Error("Verify accepted a tampered token")
	}
}

func TestParseJWKSetAndVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token, _ := SignRS256(key, "kid-9", []byte(`{"sub":"carol"}`))

	jwks, err := MarshalPublicJWKS("kid-9", key.Public())
	if err != nil {
		t.Fatalf("MarshalPublicJWKS: %v", err)
	}
	set, err := ParseJWKSet(jwks)
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if _, err := set.Verify(token); err != nil {
		t.Errorf("Verify against parsed JWKS: %v", err)
	}
}

// TestSigningKeyWrapper exercises the crypto-free API that callers outside the
// crypto boundary (e.g. internal/auth tests) use to simulate an IdP.
func TestSigningKeyWrapper(t *testing.T) {
	sk, err := GenerateRSASigningKey("idp-kid")
	if err != nil {
		t.Fatalf("GenerateRSASigningKey: %v", err)
	}
	token, err := sk.Sign([]byte(`{"sub":"dora"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := sk.JWKS().Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != `{"sub":"dora"}` {
		t.Errorf("payload = %s", got)
	}
}

func TestHS256SessionRoundTrip(t *testing.T) {
	secret := []byte("a-32-byte-server-session-secret!")
	payload := []byte(`{"sub":"alice","exp":9999999999}`)
	token := SignHS256(secret, payload)
	got, err := VerifyHS256(secret, token)
	if err != nil {
		t.Fatalf("VerifyHS256: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
	if _, err := VerifyHS256([]byte("different-secret-different-secret"), token); err == nil {
		t.Error("VerifyHS256 accepted a token signed with a different secret")
	}
}
