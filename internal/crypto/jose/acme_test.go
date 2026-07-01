package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"
)

// signFlattenedJWS builds an ACME-style flattened JWS the way x/crypto/acme does:
// RS256 over base64url(protected)+"."+base64url(payload), with the RSA public key
// embedded as a jwk.
func signFlattenedJWS(t *testing.T, key *rsa.PrivateKey, nonce, url string, payload []byte) []byte {
	t.Helper()
	jwk := jwkJSON(key.Public().(*rsa.PublicKey))
	ph, _ := json.Marshal(map[string]any{"alg": "RS256", "jwk": json.RawMessage(jwk), "nonce": nonce, "url": url})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	plB64 := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(phB64 + "." + plB64))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"protected": phB64, "payload": plB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	return body
}

func jwkJSON(pub *rsa.PublicKey) []byte {
	eb := big2bytes(pub.E)
	return []byte(`{"e":"` + base64.RawURLEncoding.EncodeToString(eb) +
		`","kty":"RSA","n":"` + base64.RawURLEncoding.EncodeToString(pub.N.Bytes()) + `"}`)
}

func big2bytes(e int) []byte {
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}

// FuzzParseACMEJWS is the parser fuzz target: ParseACMEJWS must never panic on
// arbitrary client input.
func FuzzParseACMEJWS(f *testing.F) {
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"protected":"!!!","payload":"x","signature":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseACMEJWS(data)
	})
}

func TestACMEJWSVerifyAndThumbprint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := signFlattenedJWS(t, key, "nonce-1", "https://ca/acme/new-account", []byte(`{"termsOfServiceAgreed":true}`))

	msg, err := ParseACMEJWS(body)
	if err != nil {
		t.Fatalf("ParseACMEJWS: %v", err)
	}
	if msg.Protected.Nonce != "nonce-1" || msg.Protected.URL != "https://ca/acme/new-account" {
		t.Errorf("protected header = %+v", msg.Protected)
	}

	ak, err := ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		t.Fatalf("ACMEKeyFromJWK: %v", err)
	}
	if err := msg.Verify(ak); err != nil {
		t.Errorf("Verify of a valid JWS failed: %v", err)
	}
	if ak.Thumbprint() == "" {
		t.Error("empty thumbprint")
	}

	// A tampered payload must not verify.
	bad := signFlattenedJWS(t, key, "nonce-1", "https://ca/acme/new-account", []byte(`{"termsOfServiceAgreed":true}`))
	tampered := append([]byte{}, bad...)
	tampered[len(tampered)/2] ^= 0xff
	if m, err := ParseACMEJWS(tampered); err == nil {
		if err := m.Verify(ak); err == nil {
			t.Error("Verify accepted a tampered JWS")
		}
	}

	// A different key must not verify the original message.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := ACMEKeyFromJWK(jwkJSON(&other.PublicKey))
	if err := msg.Verify(otherKey); err == nil {
		t.Error("Verify accepted a signature from a different key")
	}
}

func TestACMEExternalAccountBindingVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkJSON(&key.PublicKey)
	accountKey, err := ACMEKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("ACMEKeyFromJWK: %v", err)
	}
	const (
		kid = "customer-issuer-01"
		url = "https://ca.example/acme/new-account"
	)
	secret := []byte("external-account-binding-secret")
	body := signFlattenedHMACJWS(t, secret, kid, url, jwk)
	msg, err := ParseACMEJWS(body)
	if err != nil {
		t.Fatalf("ParseACMEJWS: %v", err)
	}
	if err := msg.VerifyExternalAccountBinding(secret, kid, url, accountKey.Thumbprint()); err != nil {
		t.Fatalf("VerifyExternalAccountBinding: %v", err)
	}
	if err := msg.VerifyExternalAccountBinding([]byte("wrong-external-account-secret"), kid, url, accountKey.Thumbprint()); err == nil {
		t.Fatal("VerifyExternalAccountBinding accepted a wrong HMAC key")
	}
	if err := msg.VerifyExternalAccountBinding(secret, kid, "https://ca.example/acme/other", accountKey.Thumbprint()); err == nil {
		t.Fatal("VerifyExternalAccountBinding accepted a wrong protected URL")
	}
}

func signFlattenedHMACJWS(t *testing.T, key []byte, kid, url string, payload []byte) []byte {
	t.Helper()
	ph, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": kid, "url": url})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	plB64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(phB64 + "." + plB64))
	body, _ := json.Marshal(map[string]string{
		"protected": phB64,
		"payload":   plB64,
		"signature": base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	return body
}

// --- ECDSA / Ed25519 account-key support (INTEROP-003) ----------------------

// ecJWK renders an ECDSA public key as a JWK the way x/crypto/acme does, with
// fixed-width coordinates (RFC 7518 §6.2.1.2). Coordinate width is ceil(bits/8).
func ecJWK(pub *ecdsa.PublicKey, crv string) []byte {
	size := (pub.Curve.Params().BitSize + 7) / 8
	//nolint:staticcheck // ACME reference JWK fixtures are encoded from legacy ECDSA affine coordinates.
	x := leftPad(pub.X.Bytes(), size)
	//nolint:staticcheck // ACME reference JWK fixtures are encoded from legacy ECDSA affine coordinates.
	y := leftPad(pub.Y.Bytes(), size)
	return []byte(`{"crv":"` + crv + `","kty":"EC","x":"` +
		base64.RawURLEncoding.EncodeToString(x) + `","y":"` +
		base64.RawURLEncoding.EncodeToString(y) + `"}`)
}

func okpJWK(pub ed25519.PublicKey) []byte {
	return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}`)
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// signFlattenedECDSA builds an ACME flattened JWS signed with ECDSA, encoding the
// signature as the JOSE fixed-width R||S concatenation (RFC 7518 §3.4), exactly as
// a stock certbot/acme.sh client does.
func signFlattenedECDSA(t *testing.T, key *ecdsa.PrivateKey, alg, crv, nonce, url string, payload []byte) []byte {
	t.Helper()
	jwk := ecJWK(&key.PublicKey, crv)
	ph, _ := json.Marshal(map[string]any{"alg": alg, "jwk": json.RawMessage(jwk), "nonce": nonce, "url": url})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	plB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := phB64 + "." + plB64

	var h hash.Hash
	switch alg {
	case "ES256":
		h = sha256.New()
	case "ES384":
		h = sha512.New384()
	case "ES512":
		h = sha512.New()
	default:
		t.Fatalf("unsupported alg %q", alg)
	}
	h.Write([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	rs := append(leftPad(r.Bytes(), size), leftPad(s.Bytes(), size)...)
	body, _ := json.Marshal(map[string]string{
		"protected": phB64, "payload": plB64,
		"signature": base64.RawURLEncoding.EncodeToString(rs),
	})
	return body
}

func signFlattenedEd25519(t *testing.T, key ed25519.PrivateKey, nonce, url string, payload []byte) []byte {
	t.Helper()
	jwk := okpJWK(key.Public().(ed25519.PublicKey))
	ph, _ := json.Marshal(map[string]any{"alg": "EdDSA", "jwk": json.RawMessage(jwk), "nonce": nonce, "url": url})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	plB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(key, []byte(phB64+"."+plB64))
	body, _ := json.Marshal(map[string]string{
		"protected": phB64, "payload": plB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	return body
}

// TestACMEAcceptsECDSAAccountKey is the INTEROP-003 acceptance at the crypto
// boundary: a stock ECDSA-default account key (the certbot/acme.sh default) must be
// accepted at JWK parse AND verify a real ES256 JWS. Before the fix, ACMEKeyFromJWK
// rejected any kty != "RSA" with badPublicKey, so this failed at the first step.
func TestACMEAcceptsECDSAAccountKey(t *testing.T) {
	cases := []struct {
		name  string
		alg   string
		crv   string
		curve elliptic.Curve
	}{
		{"ES256/P-256", "ES256", "P-256", elliptic.P256()},
		{"ES384/P-384", "ES384", "P-384", elliptic.P384()},
		{"ES512/P-521", "ES512", "P-521", elliptic.P521()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			body := signFlattenedECDSA(t, key, tc.alg, tc.crv, "nonce-ec", "https://ca/acme/new-account",
				[]byte(`{"termsOfServiceAgreed":true}`))
			msg, err := ParseACMEJWS(body)
			if err != nil {
				t.Fatalf("ParseACMEJWS: %v", err)
			}
			ak, err := ACMEKeyFromJWK(msg.Protected.JWK)
			if err != nil {
				t.Fatalf("ACMEKeyFromJWK rejected an ECDSA account key (INTEROP-003 regression): %v", err)
			}
			if err := msg.Verify(ak); err != nil {
				t.Fatalf("Verify of a valid %s JWS failed: %v", tc.alg, err)
			}
			if ak.Thumbprint() == "" {
				t.Error("empty EC thumbprint")
			}

			// A tampered payload must still fail closed.
			tampered := signFlattenedECDSA(t, key, tc.alg, tc.crv, "nonce-ec", "https://ca/acme/new-account",
				[]byte(`{"termsOfServiceAgreed":true}`))
			tm, _ := ParseACMEJWS(tampered)
			tm.payloadB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"termsOfServiceAgreed":false}`))
			if err := tm.Verify(ak); err == nil {
				t.Error("Verify accepted a tampered ECDSA JWS")
			}
		})
	}
}

// TestACMEAcceptsEd25519AccountKey proves the EdDSA/OKP path: an Ed25519 account key
// parses and verifies an EdDSA JWS.
func TestACMEAcceptsEd25519AccountKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	body := signFlattenedEd25519(t, priv, "nonce-ed", "https://ca/acme/new-account",
		[]byte(`{"termsOfServiceAgreed":true}`))
	msg, err := ParseACMEJWS(body)
	if err != nil {
		t.Fatalf("ParseACMEJWS: %v", err)
	}
	ak, err := ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		t.Fatalf("ACMEKeyFromJWK rejected an Ed25519 account key: %v", err)
	}
	if err := msg.Verify(ak); err != nil {
		t.Fatalf("Verify of a valid EdDSA JWS failed: %v", err)
	}
	if ak.Thumbprint() == "" {
		t.Error("empty Ed25519 thumbprint")
	}
}

// TestACMEKeyAlgMismatchRejected proves alg/key-type binding: an ECDSA key may not
// be used to claim an RS256 JWS, and a signature for the wrong curve is rejected —
// so the alg cannot be downgraded or confused.
func TestACMEKeyAlgMismatchRejected(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Forge a header claiming RS256 over an EC jwk.
	jwk := ecJWK(&ecKey.PublicKey, "P-256")
	ph, _ := json.Marshal(map[string]any{"alg": "RS256", "jwk": json.RawMessage(jwk), "nonce": "n", "url": "u"})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	body, _ := json.Marshal(map[string]string{"protected": phB64, "payload": "", "signature": "AAAA"})
	msg, err := ParseACMEJWS(body)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.Verify(ak); err == nil {
		t.Error("Verify accepted an RS256-claimed JWS over an ECDSA account key")
	}

	// A valid ES256 signature but a forged ES384 alg header must be rejected
	// (curve/alg must agree), not silently verified.
	good := signFlattenedECDSA(t, ecKey, "ES256", "P-256", "n", "u", []byte(`{}`))
	gm, _ := ParseACMEJWS(good)
	gm.Protected.Alg = "ES384"
	if err := gm.Verify(ak); err == nil {
		t.Error("Verify accepted an ES256 signature under a forged ES384 alg")
	}
}
