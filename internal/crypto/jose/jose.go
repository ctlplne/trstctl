// Package jose implements the minimal JOSE the platform needs — compact JWS
// signing and verification (RS256 for OIDC id_tokens, HS256 for sessions) and
// JWK Set parsing — inside the AN-3 crypto boundary (a subpackage of
// internal/crypto, so it alone may import crypto/*). Callers outside the boundary
// use the crypto-free wrappers (SigningKey, JWKSet, the HS256 helpers) and never
// name a crypto/* type.
package jose

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func encodeSegment(b []byte) string { return b64.EncodeToString(b) }

// ---- RS256 (asymmetric, for id_tokens) ------------------------------------

// SignRS256 produces a compact JWS over payload using key, tagged with kid.
func SignRS256(key *rsa.PrivateKey, kid string, payload []byte) (string, error) {
	hdr, err := json.Marshal(jwsHeader{Alg: "RS256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	signingInput := encodeSegment(hdr) + "." + encodeSegment(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + encodeSegment(sig), nil
}

func verifyRS256(pub *rsa.PublicKey, signingInput, sig string) error {
	raw, err := b64.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("jose: bad signature encoding: %w", err)
	}
	sum := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], raw)
}

// ---- JWK Set --------------------------------------------------------------

// JWKSet is a set of public keys keyed by "kid", used to verify JWTs.
type JWKSet struct {
	keys map[string]*rsa.PublicKey
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKSet parses a JWK Set document (as served at an OIDC jwks_uri). Only
// RSA keys are supported.
func ParseJWKSet(doc []byte) (*JWKSet, error) {
	var set jwks
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("jose: parse jwks: %w", err)
	}
	out := &JWKSet{keys: make(map[string]*rsa.PublicKey, len(set.Keys))}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jose: jwk %q modulus: %w", k.Kid, err)
		}
		eb, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jose: jwk %q exponent: %w", k.Kid, err)
		}
		out.keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
	}
	if len(out.keys) == 0 {
		return nil, errors.New("jose: jwks contains no usable RSA keys")
	}
	return out, nil
}

// NewJWKSet builds a JWK Set from a single public key. The key must be an RSA
// public key.
func NewJWKSet(kid string, pub crypto.PublicKey) (*JWKSet, error) {
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jose: only RSA public keys are supported")
	}
	return &JWKSet{keys: map[string]*rsa.PublicKey{kid: rp}}, nil
}

// MarshalPublicJWKS renders a single RSA public key as a JWK Set document.
func MarshalPublicJWKS(kid string, pub crypto.PublicKey) ([]byte, error) {
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jose: only RSA public keys are supported")
	}
	eb := big.NewInt(int64(rp.E)).Bytes()
	return json.Marshal(jwks{Keys: []jwk{{
		Kty: "RSA", Kid: kid,
		N: b64.EncodeToString(rp.N.Bytes()),
		E: b64.EncodeToString(eb),
	}}})
}

// Verify checks a compact JWS against the set (selecting the key by "kid", or the
// sole key if the token carries no kid) and returns the decoded payload.
func (s *JWKSet) Verify(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jose: token is not a compact JWS")
	}
	hdrRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jose: bad header encoding: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, fmt.Errorf("jose: bad header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("jose: unsupported alg %q", hdr.Alg)
	}
	pub, err := s.selectKey(hdr.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyRS256(pub, parts[0]+"."+parts[1], parts[2]); err != nil {
		return nil, fmt.Errorf("jose: signature verification failed: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jose: bad payload encoding: %w", err)
	}
	return payload, nil
}

func (s *JWKSet) selectKey(kid string) (*rsa.PublicKey, error) {
	if kid != "" {
		if k, ok := s.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("jose: no key with kid %q in the set", kid)
	}
	if len(s.keys) == 1 {
		for _, k := range s.keys {
			return k, nil
		}
	}
	return nil, errors.New("jose: token has no kid and the set is not singular")
}

// ---- crypto-free signing wrapper (for IdP simulation / token signing) ------

// SigningKey is an opaque RSA signing key plus its kid, so callers outside the
// crypto boundary can sign and publish a JWK Set without naming crypto/* types.
type SigningKey struct {
	key *rsa.PrivateKey
	kid string
}

// GenerateRSASigningKey generates a 2048-bit RSA signing key tagged with kid.
func GenerateRSASigningKey(kid string) (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &SigningKey{key: key, kid: kid}, nil
}

// Sign produces a compact JWS over payload (RS256).
func (k *SigningKey) Sign(payload []byte) (string, error) { return SignRS256(k.key, k.kid, payload) }

// JWKS returns the public JWK Set that verifies tokens from this key.
func (k *SigningKey) JWKS() *JWKSet {
	return &JWKSet{keys: map[string]*rsa.PublicKey{k.kid: &k.key.PublicKey}}
}

// ---- HS256 (symmetric, for session tokens) --------------------------------

// SignHS256 produces a compact JWS over payload using an HMAC-SHA256 secret.
func SignHS256(secret, payload []byte) string {
	hdr, _ := json.Marshal(jwsHeader{Alg: "HS256", Typ: "JWT"})
	signingInput := encodeSegment(hdr) + "." + encodeSegment(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + encodeSegment(mac.Sum(nil))
}

// VerifyHS256 verifies a compact HS256 JWS and returns the payload.
func VerifyHS256(secret []byte, token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jose: token is not a compact JWS")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jose: bad signature encoding: %w", err)
	}
	if !hmac.Equal(want, got) {
		return nil, errors.New("jose: session signature mismatch")
	}
	return b64.DecodeString(parts[1])
}
