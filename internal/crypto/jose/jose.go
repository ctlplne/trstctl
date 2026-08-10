// SPDX-License-Identifier: MPL-2.0

// Package jose implements the minimal JOSE the platform needs — compact JWS
// signing and verification (RS256 for OIDC id_tokens, HS256 for sessions) and
// JWK Set parsing — inside the AN-3 crypto boundary (a subpackage of
// internal/crypto, so it alone may import crypto/*). Callers outside the boundary
// use the crypto-free wrappers (SigningKey, JWKSet, the HS256 helpers) and never
// name a crypto/* type.
package jose

import (
	stdcrypto "crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var b64 = base64.RawURLEncoding

type jwsHeader struct {
	Alg            string `json:"alg"`
	Typ            string `json:"typ,omitempty"`
	Kid            string `json:"kid,omitempty"`
	ArtifactDomain string `json:"trstctl_artifact,omitempty"`
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
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, stdcrypto.SHA256, sum[:])
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
	return rsa.VerifyPKCS1v15(pub, stdcrypto.SHA256, sum[:], raw)
}

// ---- JWK Set --------------------------------------------------------------

const (
	// minRSABits / maxRSABits bound an accepted RSA modulus (FUZZ-006). Below the
	// minimum a key is too weak to trust; above the maximum a (possibly attacker-
	// supplied) modulus turns every verification into an unbounded big-int CPU sink.
	minRSABits = 2048
	maxRSABits = 8192
	// maxRSAExponent caps the public exponent. RSA public exponents are small (3,
	// 17, 65537); an oversized e is nonsensical and, decoded via Int64()/int, could
	// silently overflow. We require 3 <= e <= maxRSAExponent and e odd.
	maxRSAExponent = 1 << 31
	// maxJWKSKeys caps how many keys a single JWKS document may declare (FUZZ-006):
	// a huge document otherwise drives allocation straight off attacker-controlled
	// input. A real OIDC jwks_uri carries a handful of keys.
	maxJWKSKeys = 32
)

// rsaPublicFromJWK builds and validates an RSA public key from the raw big-endian
// modulus (nb) and exponent (eb) bytes of a JWK, enforcing the modulus-size and
// exponent-sanity bounds (FUZZ-006). It is the single chokepoint both the JWKS and
// the ACME-account-key paths use, so neither can construct an out-of-bounds key.
func rsaPublicFromJWK(nb, eb []byte) (*rsa.PublicKey, error) {
	n := new(big.Int).SetBytes(nb)
	if n.Sign() <= 0 {
		return nil, errors.New("jose: RSA jwk modulus is zero")
	}
	if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, fmt.Errorf("jose: RSA jwk modulus is %d bits, outside the accepted %d–%d range", bits, minRSABits, maxRSABits)
	}
	e := new(big.Int).SetBytes(eb)
	// Reject an exponent that does not fit our sane cap before narrowing to int, so
	// Int64()/int() can never truncate an oversized value into a small one.
	if e.Sign() <= 0 || e.Cmp(big.NewInt(maxRSAExponent)) > 0 {
		return nil, fmt.Errorf("jose: RSA jwk exponent out of range (want 3..%d)", maxRSAExponent)
	}
	ei := int(e.Int64())
	if ei < 3 || ei%2 == 0 {
		return nil, fmt.Errorf("jose: RSA jwk exponent %d invalid (must be odd and >= 3)", ei)
	}
	return &rsa.PublicKey{N: n, E: ei}, nil
}

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
	// Cap the declared key count before iterating so a huge document cannot drive
	// unbounded work/allocation off attacker-controlled input (FUZZ-006).
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("jose: jwks declares %d keys, exceeds the %d-key cap", len(set.Keys), maxJWKSKeys)
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
		pub, err := rsaPublicFromJWK(nb, eb)
		if err != nil {
			return nil, fmt.Errorf("jose: jwk %q: %w", k.Kid, err)
		}
		out.keys[k.Kid] = pub
	}
	if len(out.keys) == 0 {
		return nil, errors.New("jose: jwks contains no usable RSA keys")
	}
	return out, nil
}

// NewJWKSet builds a JWK Set from a single public key. The key must be an RSA
// public key.
func NewJWKSet(kid string, pub stdcrypto.PublicKey) (*JWKSet, error) {
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jose: only RSA public keys are supported")
	}
	return &JWKSet{keys: map[string]*rsa.PublicKey{kid: rp}}, nil
}

// MarshalPublicJWKS renders a single RSA public key as a JWK Set document.
func MarshalPublicJWKS(kid string, pub stdcrypto.PublicKey) ([]byte, error) {
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

// SigningKey is an opaque RSA signing capability plus its kid, so callers outside
// the crypto boundary can sign and publish a JWK Set without naming crypto/*
// types. Production audit/evidence code supplies a remote DigestSigner: the
// control plane therefore retains only the public key and opaque signer handle,
// while the private operation runs in trstctl-signer (AUD-63 / AN-4).
type SigningKey struct {
	key      *rsa.PrivateKey
	signer   boundarycrypto.DigestSigner
	artifact ArtifactSigner
	public   *rsa.PublicKey
	kid      string
}

// ArtifactSigner is the crypto-free client side of the signer's narrow evidence
// RPC. It returns a complete compact JWS whose protected header binds kind.
type ArtifactSigner interface {
	SignArtifact(kind string, payload []byte) (string, error)
}

// Stable artifact-kind domains admitted by the core audit-evidence signer.
const (
	ArtifactAuditExport        = "trstctl.audit-evidence/audit-export/v1"
	ArtifactAuditRetention     = "trstctl.audit-evidence/audit-retention/v1"
	ArtifactHistoryContinuity  = "trstctl.audit-evidence/history-continuity/v1"
	ArtifactBillingInvoice     = "trstctl.audit-evidence/billing-invoice/v1"
	ArtifactDoctorReceipt      = "trstctl.audit-evidence/doctor-receipt/v1"
	ArtifactPQCCampaignClosure = "trstctl.audit-evidence/pqc-campaign-closure/v1"
)

// GenerateRSASigningKey generates a 2048-bit RSA signing key tagged with kid.
func GenerateRSASigningKey(kid string) (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &SigningKey{key: key, public: &key.PublicKey, kid: kid}, nil
}

// NewDigestSigningKey wraps an RSA DigestSigner without importing or exporting
// its private key. A RemoteSigner is the production implementation; LockedSigner
// remains useful to exercise the exact boundary-neutral contract in tests.
func NewDigestSigningKey(kid string, signer boundarycrypto.DigestSigner) (*SigningKey, error) {
	if signer == nil {
		return nil, errors.New("jose: digest signer is required")
	}
	switch signer.Algorithm() {
	case boundarycrypto.RSA2048, boundarycrypto.RSA3072, boundarycrypto.RSA4096:
	default:
		return nil, fmt.Errorf("jose: RS256 requires an RSA signer, got %s", signer.Algorithm())
	}
	parsed, err := x509.ParsePKIXPublicKey(signer.Public().DER)
	if err != nil {
		return nil, fmt.Errorf("jose: parse signer public key: %w", err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: RS256 signer published %T, want RSA", parsed)
	}
	return &SigningKey{signer: signer, public: public, kid: kid}, nil
}

// NewArtifactSigningKey returns a public-key wrapper whose signatures can be
// produced only through the narrow artifact RPC. Sign without an explicit kind
// fails closed, preventing a production caller from falling back to the generic
// digest-signing surface (AUD-63).
func NewArtifactSigningKey(kid string, publicKey boundarycrypto.PublicKey, signer ArtifactSigner) (*SigningKey, error) {
	if signer == nil {
		return nil, errors.New("jose: artifact signer is required")
	}
	switch publicKey.Algorithm {
	case boundarycrypto.RSA2048, boundarycrypto.RSA3072, boundarycrypto.RSA4096:
	default:
		return nil, fmt.Errorf("jose: RS256 requires an RSA signer, got %s", publicKey.Algorithm)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey.DER)
	if err != nil {
		return nil, fmt.Errorf("jose: parse artifact signer public key: %w", err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: RS256 artifact signer published %T, want RSA", parsed)
	}
	return &SigningKey{artifact: signer, public: public, kid: kid}, nil
}

// Sign produces a compact JWS over payload (RS256).
func (k *SigningKey) Sign(payload []byte) (string, error) {
	if k == nil {
		return "", errors.New("jose: signing key is nil")
	}
	if k.signer == nil {
		if k.artifact != nil {
			return "", errors.New("jose: artifact signing key requires an explicit artifact kind")
		}
		if k.key == nil {
			return "", errors.New("jose: signing key has no signer")
		}
		return SignRS256(k.key, k.kid, payload)
	}
	return k.signDigestJWS("", payload)
}

// SignArtifact produces a compact RS256 JWS whose protected header binds the
// admitted artifact kind. Production wrappers dispatch this into trstctl-signer;
// local keys retain the same semantic helper for focused tests and offline tools.
func (k *SigningKey) SignArtifact(kind string, payload []byte) (string, error) {
	if k == nil {
		return "", errors.New("jose: signing key is nil")
	}
	if kind == "" {
		return "", errors.New("jose: artifact kind is required")
	}
	if k.artifact != nil {
		return k.artifact.SignArtifact(kind, payload)
	}
	if k.signer == nil && k.key != nil {
		return k.signLocalJWS(kind, payload)
	}
	return k.signDigestJWS(kind, payload)
}

func (k *SigningKey) signLocalJWS(kind string, payload []byte) (string, error) {
	hdr, err := json.Marshal(jwsHeader{Alg: "RS256", Typ: "JWT", Kid: k.kid, ArtifactDomain: kind})
	if err != nil {
		return "", err
	}
	signingInput := encodeSegment(hdr) + "." + encodeSegment(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, stdcrypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + encodeSegment(sig), nil
}

func (k *SigningKey) signDigestJWS(kind string, payload []byte) (string, error) {
	if k.signer == nil {
		return "", errors.New("jose: signing key has no digest signer")
	}
	hdr, err := json.Marshal(jwsHeader{Alg: "RS256", Typ: "JWT", Kid: k.kid, ArtifactDomain: kind})
	if err != nil {
		return "", err
	}
	signingInput := encodeSegment(hdr) + "." + encodeSegment(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := k.signer.SignDigest(sum[:], boundarycrypto.SignOptions{
		Hash:       boundarycrypto.SHA256,
		RSAPadding: boundarycrypto.RSAPKCS1v15,
	})
	if err != nil {
		return "", fmt.Errorf("jose: remote RS256 sign: %w", err)
	}
	return signingInput + "." + encodeSegment(sig), nil
}

// KeyID reports the kid this key signs as, so a caller embedding the kid in a
// signature envelope cannot drift from the kid inside the JWS header.
func (k *SigningKey) KeyID() string { return k.kid }

// MarshalPrivateKey returns the signing key as a PKCS#8 PEM document so a caller
// can persist it (so a key — for example the audit export key — survives a
// restart instead of rotating each boot). The kid is not part of the PEM; the
// caller supplies it again to ParseRSASigningKey.
func (k *SigningKey) MarshalPrivateKey() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, errors.New("jose: opaque signing key has no exportable private material")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, fmt.Errorf("jose: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseRSASigningKey parses a PKCS#8 PEM private key (as written by
// MarshalPrivateKey) and tags it with kid. It is the reload counterpart that lets
// an export key persist across restarts.
func ParseRSASigningKey(kid string, pemBytes []byte) (*SigningKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("jose: not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jose: parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("jose: PEM is not an RSA private key")
	}
	return &SigningKey{key: key, public: &key.PublicKey, kid: kid}, nil
}

// JWKS returns the public JWK Set that verifies tokens from this key.
func (k *SigningKey) JWKS() *JWKSet {
	return &JWKSet{keys: map[string]*rsa.PublicKey{k.kid: k.public}}
}

// PublicJWKS renders this key's public half as a JWK Set document (the bytes an
// OIDC provider serves at its jwks_uri), so a caller outside the crypto boundary
// can publish the verification keys — e.g. to configure trstctl's OIDC verifier or
// to stand up an IdP simulation — without naming crypto/* types (AN-3).
func (k *SigningKey) PublicJWKS() ([]byte, error) {
	return MarshalPublicJWKS(k.kid, k.public)
}

// ---- HS256 (symmetric, for session tokens) --------------------------------

// SignHS256Bytes produces a compact JWS in an erasable byte buffer. Callers that
// use the JWS as a short-lived authority credential should prefer this form so
// the compact token never needs to exist as an immutable Go string (AN-8).
func SignHS256Bytes(key, payload []byte) []byte {
	hdr, _ := json.Marshal(jwsHeader{Alg: "HS256", Typ: "JWT"})
	encodedLen := b64.EncodedLen(len(hdr)) + 1 + b64.EncodedLen(len(payload))
	signingInput := make([]byte, 0, encodedLen+1+b64.EncodedLen(sha256.Size))
	signingInput = b64.AppendEncode(signingInput, hdr)
	signingInput = append(signingInput, '.')
	signingInput = b64.AppendEncode(signingInput, payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(signingInput)
	signature := mac.Sum(nil)
	signingInput = append(signingInput, '.')
	signingInput = b64.AppendEncode(signingInput, signature)
	secret.Wipe(signature)
	return signingInput
}

// SignHS256 produces a compact JWS string for existing APIs that retain a
// session token as text. New short-lived credential paths should use
// SignHS256Bytes instead.
func SignHS256(key, payload []byte) string {
	token := SignHS256Bytes(key, payload)
	out := string(token)
	secret.Wipe(token)
	return out
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
