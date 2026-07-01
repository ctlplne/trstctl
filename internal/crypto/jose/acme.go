package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// This file adds the JOSE primitives the built-in ACME server (RFC 8555) needs:
// verifying a client's flattened-JSON JWS against its account key and computing
// the RFC 7638 key thumbprint. It stays in the crypto boundary so the ACME server
// never handles crypto/* itself.
//
// Account-key algorithms accepted (RFC 8555 §6.2 / RFC 7518): RSA (RS256), ECDSA
// over P-256/P-384/P-521 (ES256/ES384/ES512), and Ed25519 (EdDSA). Stock
// certbot/acme.sh default to ECDSA P-256, so ECDSA support is what lets an
// unmodified client register; RSA remains supported for older clients.

// ACMEProtected is the protected header of an ACME JWS.
type ACMEProtected struct {
	Alg   string          `json:"alg"`
	Kid   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	Nonce string          `json:"nonce,omitempty"`
	URL   string          `json:"url"`
}

// ACMEMessage is a parsed flattened-JSON ACME JWS.
type ACMEMessage struct {
	Protected ACMEProtected
	Payload   []byte // base64url-decoded payload ("" for POST-as-GET)

	protectedB64 string
	payloadB64   string
	signatureB64 string
}

// ParseACMEJWS parses a flattened-JSON ACME JWS body without verifying it.
func ParseACMEJWS(body []byte) (*ACMEMessage, error) {
	var raw struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("jose: parse acme jws: %w", err)
	}
	phJSON, err := b64.DecodeString(raw.Protected)
	if err != nil {
		return nil, fmt.Errorf("jose: acme protected header: %w", err)
	}
	var ph ACMEProtected
	if err := json.Unmarshal(phJSON, &ph); err != nil {
		return nil, fmt.Errorf("jose: acme protected header: %w", err)
	}
	var payload []byte
	if raw.Payload != "" {
		if payload, err = b64.DecodeString(raw.Payload); err != nil {
			return nil, fmt.Errorf("jose: acme payload: %w", err)
		}
	}
	return &ACMEMessage{
		Protected: ph, Payload: payload,
		protectedB64: raw.Protected, payloadB64: raw.Payload, signatureB64: raw.Signature,
	}, nil
}

// acmeKeyKind is the account-key algorithm family.
type acmeKeyKind int

const (
	keyRSA acmeKeyKind = iota
	keyECDSA
	keyEd25519
)

// ACMEKey is an ACME account public key (RSA, ECDSA, or Ed25519), used to verify a
// client's JWS and to derive the key authorization for challenges. Construct it via
// ACMEKeyFromJWK; the concrete crypto/* types stay inside this boundary.
type ACMEKey struct {
	kind acmeKeyKind

	rsaPub *rsa.PublicKey
	ecPub  *ecdsa.PublicKey
	edPub  ed25519.PublicKey

	// thumbInput is the RFC 7638 canonical JWK JSON (lexicographically-ordered
	// required members, no whitespace) whose SHA-256 is the key thumbprint.
	thumbInput string
}

// ACMEKeyFromJWK builds an account key from a JWK (the jwk member of a new-account
// request's protected header). RSA, EC (P-256/384/521), and OKP (Ed25519) keys are
// supported; anything else is rejected as badPublicKey by the caller.
func ACMEKeyFromJWK(jwk json.RawMessage) (*ACMEKey, error) {
	var k struct {
		Kty string `json:"kty"`
		// RSA
		N string `json:"n"`
		E string `json:"e"`
		// EC / OKP
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(jwk, &k); err != nil {
		return nil, fmt.Errorf("jose: parse jwk: %w", err)
	}
	switch k.Kty {
	case "RSA":
		return rsaACMEKey(k.N, k.E)
	case "EC":
		return ecACMEKey(k.Crv, k.X, k.Y)
	case "OKP":
		return okpACMEKey(k.Crv, k.X)
	default:
		return nil, fmt.Errorf("jose: unsupported ACME account key type %q (want RSA, EC, or OKP)", k.Kty)
	}
}

func rsaACMEKey(n, e string) (*ACMEKey, error) {
	if n == "" || e == "" {
		return nil, errors.New("jose: RSA jwk missing n or e")
	}
	nb, err := b64.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk modulus: %w", err)
	}
	eb, err := b64.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk exponent: %w", err)
	}
	// Enforce the same modulus-size/exponent bounds the JWKS path uses (FUZZ-006), so
	// an ACME client cannot register an absurd account key (giant modulus → CPU sink,
	// or an oversized exponent that truncates via int()).
	pub, err := rsaPublicFromJWK(nb, eb)
	if err != nil {
		return nil, err
	}
	return &ACMEKey{
		kind:   keyRSA,
		rsaPub: pub,
		// RFC 7638 §3.2: RSA required members are e, kty, n (lexicographic order).
		thumbInput: fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n),
	}, nil
}

func ecACMEKey(crv, x, y string) (*ACMEKey, error) {
	curve, ok := ecCurveByName(crv)
	if !ok {
		return nil, fmt.Errorf("jose: unsupported EC curve %q (want P-256/P-384/P-521)", crv)
	}
	if x == "" || y == "" {
		return nil, errors.New("jose: EC jwk missing x or y")
	}
	xb, err := b64.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk EC x: %w", err)
	}
	yb, err := b64.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk EC y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	//nolint:staticcheck // ACME JWK parsing receives legacy ECDSA affine coordinates on the wire.
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("jose: EC jwk point is not on the curve")
	}
	return &ACMEKey{
		kind:  keyECDSA,
		ecPub: pub,
		// RFC 7638 §3.2: EC required members are crv, kty, x, y (lexicographic order).
		thumbInput: fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y),
	}, nil
}

func okpACMEKey(crv, x string) (*ACMEKey, error) {
	if crv != "Ed25519" {
		return nil, fmt.Errorf("jose: unsupported OKP curve %q (want Ed25519)", crv)
	}
	if x == "" {
		return nil, errors.New("jose: OKP jwk missing x")
	}
	xb, err := b64.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk OKP x: %w", err)
	}
	if len(xb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jose: Ed25519 jwk x is %d bytes (want %d)", len(xb), ed25519.PublicKeySize)
	}
	return &ACMEKey{
		kind:  keyEd25519,
		edPub: ed25519.PublicKey(xb),
		// RFC 8037 §2: OKP thumbprint required members are crv, kty, x.
		thumbInput: fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, crv, x),
	}, nil
}

func ecCurveByName(crv string) (elliptic.Curve, bool) {
	switch crv {
	case "P-256":
		return elliptic.P256(), true
	case "P-384":
		return elliptic.P384(), true
	case "P-521":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

// Verify checks the JWS signature against key. The JWS alg must match the key type:
// RS256 for RSA, ES256/ES384/ES512 for ECDSA, EdDSA for Ed25519.
func (m *ACMEMessage) Verify(key *ACMEKey) error {
	if key == nil {
		return errors.New("jose: no account key")
	}
	signingInput := m.protectedB64 + "." + m.payloadB64
	sig, err := b64.DecodeString(m.signatureB64)
	if err != nil {
		return fmt.Errorf("jose: bad signature encoding: %w", err)
	}
	switch key.kind {
	case keyRSA:
		if m.Protected.Alg != "RS256" {
			return fmt.Errorf("jose: ACME JWS alg %q does not match an RSA account key (want RS256)", m.Protected.Alg)
		}
		return verifyRS256(key.rsaPub, signingInput, m.signatureB64)
	case keyECDSA:
		return verifyACMEECDSA(key.ecPub, m.Protected.Alg, signingInput, sig)
	case keyEd25519:
		if m.Protected.Alg != "EdDSA" {
			return fmt.Errorf("jose: ACME JWS alg %q does not match an Ed25519 account key (want EdDSA)", m.Protected.Alg)
		}
		if !ed25519.Verify(key.edPub, []byte(signingInput), sig) {
			return errors.New("jose: Ed25519 signature verification failed")
		}
		return nil
	default:
		return errors.New("jose: unknown account key kind")
	}
}

// VerifyExternalAccountBinding verifies the RFC 8555 §7.3.4 externalAccountBinding
// JWS. The outer ACME new-account request selects the HMAC key by kid; this method
// pins HS256, checks the protected kid/url, verifies the HMAC in constant time, and
// proves the EAB payload is the same account key as the outer request by comparing
// RFC 7638 thumbprints.
func (m *ACMEMessage) VerifyExternalAccountBinding(hmacKey []byte, expectedKid, expectedURL, accountThumbprint string) error {
	if m == nil {
		return errors.New("jose: no external account binding")
	}
	if len(hmacKey) == 0 {
		return errors.New("jose: no external account binding HMAC key")
	}
	if m.Protected.Alg != "HS256" {
		return fmt.Errorf("jose: external account binding alg %q is not supported (want HS256)", m.Protected.Alg)
	}
	if m.Protected.Kid != expectedKid {
		return errors.New("jose: external account binding kid mismatch")
	}
	if m.Protected.URL != expectedURL {
		return errors.New("jose: external account binding url mismatch")
	}
	if m.Protected.Nonce != "" || len(m.Protected.JWK) != 0 {
		return errors.New("jose: external account binding protected header must not carry nonce or jwk")
	}
	boundKey, err := ACMEKeyFromJWK(m.Payload)
	if err != nil {
		return fmt.Errorf("jose: external account binding payload key: %w", err)
	}
	if boundKey.Thumbprint() != accountThumbprint {
		return errors.New("jose: external account binding payload does not match account key")
	}
	signingInput := m.protectedB64 + "." + m.payloadB64
	got, err := b64.DecodeString(m.signatureB64)
	if err != nil {
		return fmt.Errorf("jose: external account binding signature encoding: %w", err)
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(signingInput))
	if !hmac.Equal(mac.Sum(nil), got) {
		return errors.New("jose: external account binding signature mismatch")
	}
	return nil
}

// verifyACMEECDSA verifies a JOSE ECDSA signature (RFC 7518 §3.4): the signature is
// the fixed-width R||S concatenation (NOT ASN.1 DER), and alg pins both the hash and
// the curve. A signature whose alg does not match the key's curve is rejected.
func verifyACMEECDSA(pub *ecdsa.PublicKey, alg, signingInput string, sig []byte) error {
	var h hash.Hash
	var wantCurve elliptic.Curve
	switch alg {
	case "ES256":
		h, wantCurve = sha256.New(), elliptic.P256()
	case "ES384":
		h, wantCurve = sha512.New384(), elliptic.P384()
	case "ES512":
		h, wantCurve = sha512.New(), elliptic.P521()
	default:
		return fmt.Errorf("jose: ACME JWS alg %q does not match an ECDSA account key (want ES256/ES384/ES512)", alg)
	}
	if pub.Curve != wantCurve {
		return fmt.Errorf("jose: ACME JWS alg %q does not match the account key's curve", alg)
	}
	// The R||S pair is two fixed-width big-endian integers, each ceil(bits/8) wide.
	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keyBytes {
		return fmt.Errorf("jose: ECDSA signature length %d does not match curve (want %d)", len(sig), 2*keyBytes)
	}
	r := new(big.Int).SetBytes(sig[:keyBytes])
	s := new(big.Int).SetBytes(sig[keyBytes:])
	h.Write([]byte(signingInput))
	if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
		return errors.New("jose: ECDSA signature verification failed")
	}
	return nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256), used as the
// stable account identifier and in challenge key authorizations. The canonical
// input is the key's required JWK members in lexicographic order (RSA: e,kty,n;
// EC: crv,kty,x,y; OKP: crv,kty,x).
func (k *ACMEKey) Thumbprint() string {
	sum := sha256.Sum256([]byte(k.thumbInput))
	return b64.EncodeToString(sum[:])
}
