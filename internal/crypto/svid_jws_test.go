package crypto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignSVIDCarriesURISANAndChains(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := SelfSignedCACert(ca, "SVID Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Destroy()

	const id = "spiffe://example.org/ns/default/sa/web"
	svid, err := SignSVID(caDER, ca, leaf.Public().DER, id, time.Hour)
	if err != nil {
		t.Fatalf("SignSVID: %v", err)
	}
	if err := VerifyLeafSignedByCA(svid, caDER); err != nil {
		t.Fatalf("SVID does not chain to CA: %v", err)
	}
	got, err := SPIFFEIDFromCert(svid)
	if err != nil {
		t.Fatalf("SPIFFEIDFromCert: %v", err)
	}
	if got != id {
		t.Errorf("SPIFFE ID = %q, want %q", got, id)
	}
}

func TestSignSVIDRejectsBadID(t *testing.T) {
	ca, _ := GenerateLockedKey(ECDSAP256)
	defer ca.Destroy()
	caDER, _ := SelfSignedCACert(ca, "CA", time.Hour)
	leaf, _ := GenerateLockedKey(ECDSAP256)
	defer leaf.Destroy()
	for _, bad := range []string{"https://example.org/x", "spiffe:///path", "not a uri", "spiffe://example.org/p?q=1"} {
		if _, err := SignSVID(caDER, ca, leaf.Public().DER, bad, time.Hour); err == nil {
			t.Errorf("SignSVID accepted invalid SPIFFE ID %q", bad)
		}
	}
}

func TestJWTRoundTripES256(t *testing.T) {
	signer, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	jwk, err := PublicJWK(signer.Public(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	jwks := JWKS{Keys: []JWK{jwk}}

	claims := map[string]any{"sub": "spiffe://example.org/svc", "aud": "trstctl", "exp": time.Now().Add(time.Hour).Unix()}
	tok, err := SignJWT(signer, "k1", claims)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	raw, err := VerifyJWT(tok, jwks)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out["sub"] != "spiffe://example.org/svc" {
		t.Errorf("sub = %v", out["sub"])
	}
}

func TestJWTRoundTripRS256(t *testing.T) {
	signer, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	jwk, _ := PublicJWK(signer.Public(), "rsa1")
	jwks := JWKS{Keys: []JWK{jwk}}
	tok, err := SignJWT(signer, "rsa1", map[string]any{"sub": "abc"})
	if err != nil {
		t.Fatalf("SignJWT RS256: %v", err)
	}
	if _, err := VerifyJWT(tok, jwks); err != nil {
		t.Fatalf("VerifyJWT RS256: %v", err)
	}
}

func TestJWTRejectsForgedAndTampered(t *testing.T) {
	signer, _ := GenerateLockedKey(ECDSAP256)
	defer signer.Destroy()
	attacker, _ := GenerateLockedKey(ECDSAP256)
	defer attacker.Destroy()
	jwk, _ := PublicJWK(signer.Public(), "k1")
	jwks := JWKS{Keys: []JWK{jwk}}

	// Token signed by the attacker but presenting kid k1 → must fail.
	forged, _ := SignJWT(attacker, "k1", map[string]any{"sub": "evil"})
	if _, err := VerifyJWT(forged, jwks); err == nil {
		t.Error("VerifyJWT accepted a token signed by the wrong key")
	}
	// Tamper the payload of a genuine token.
	good, _ := SignJWT(signer, "k1", map[string]any{"sub": "good"})
	parts := strings.Split(good, ".")
	parts[1] = b64url([]byte(`{"sub":"tampered"}`))
	if _, err := VerifyJWT(strings.Join(parts, "."), jwks); err == nil {
		t.Error("VerifyJWT accepted a tampered payload")
	}
}
