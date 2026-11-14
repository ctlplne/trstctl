// SPDX-License-Identifier: BUSL-1.1

package jose

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// JSON Signature Format (JSF 0.82) enveloped signatures for CycloneDX BOMs
// (Q3-L1). CycloneDX 1.6 defines a BOM's "signature" property as a JSF
// signature: the signer puts {"algorithm", "keyId", "publicKey"} under
// "signature", signs the JCS (RFC 8785) form of the whole BOM and adds the
// signature as "value". A verifier removes "value", canonicalizes again and
// checks it, so the signature survives any reformatting of the BOM. trstctl
// writes and accepts only the single-signer form with RS256; "excludes",
// "certificatePath", "extensions", "signers" and "chain" are refused.

// ArtifactCBOMCycloneDXJSF is the audit evidence kind whose signature is a
// BOM's enveloped JSF value instead of a JWS. The isolated signer signs only
// CycloneDX BOMs under it, and only when the signature object names its key.
const ArtifactCBOMCycloneDXJSF = "trstctl.audit-evidence/cbom-cyclonedx-jsf/v1"

// JSFSignature is a JSF signature object as trstctl writes it.
type JSFSignature struct {
	Algorithm string        `json:"algorithm"`
	KeyID     string        `json:"keyId,omitempty"`
	PublicKey *JSFPublicKey `json:"publicKey,omitempty"`
	Value     string        `json:"value,omitempty"`
}

// JSFPublicKey is a JSF RSA public key: a JWK of exactly kty, n and e.
type JSFPublicKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jsfValueEncoding decodes a signature value strictly: base64url without
// padding and with zero trailing bits, so one signature has one spelling.
var jsfValueEncoding = base64.RawURLEncoding.Strict()

// JSFTemplateFromJWKS returns the signature object (no value yet) for the one
// RSA key a published JWK Set holds: RS256, its kid and its public key.
func JSFTemplateFromJWKS(doc []byte) (JSFSignature, error) {
	var set jwks
	if err := json.Unmarshal(doc, &set); err != nil {
		return JSFSignature{}, fmt.Errorf("jose: parse JWK set: %w", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kty != "RSA" || set.Keys[0].Kid == "" {
		return JSFSignature{}, errors.New("jose: a JSF signature template needs a JWK set of one RSA key with a kid")
	}
	k := set.Keys[0]
	if _, err := jsfRSAKey(k.N, k.E); err != nil {
		return JSFSignature{}, err
	}
	return JSFSignature{Algorithm: "RS256", KeyID: k.Kid, PublicKey: &JSFPublicKey{Kty: "RSA", N: k.N, E: k.E}}, nil
}

// signJSF signs a CycloneDX BOM whose "signature" object names this key and
// holds no value yet, and returns the base64url JSF value.
func (k *SigningKey) signJSF(payload []byte) (string, error) {
	if k.public == nil {
		return "", errors.New("jose: signing key has no public key")
	}
	canonical, err := jsfSigningInput(payload, k.kid, k.public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	var sig []byte
	switch {
	case k.signer != nil:
		sig, err = k.signer.SignDigest(sum[:], boundarycrypto.SignOptions{
			Hash:       boundarycrypto.SHA256,
			RSAPadding: boundarycrypto.RSAPKCS1v15,
		})
	case k.key != nil:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.key, stdcrypto.SHA256, sum[:])
	default:
		return "", errors.New("jose: signing key has no signer")
	}
	if err != nil {
		return "", fmt.Errorf("jose: JSF RS256 sign: %w", err)
	}
	return b64.EncodeToString(sig), nil
}

// jsfSigningInput admits a BOM for signing and returns its canonical form:
// a CycloneDX document whose signature object holds RS256, this key's kid and
// optionally this key's public key, and nothing else.
func jsfSigningInput(doc []byte, kid string, pub *rsa.PublicKey) ([]byte, error) {
	root, sig, err := parseJSFDocument(doc)
	if err != nil {
		return nil, err
	}
	for _, name := range sig.keys {
		if name != "algorithm" && name != "keyId" && name != "publicKey" {
			return nil, fmt.Errorf("jose: a BOM to sign carries the signature property %q", name)
		}
	}
	if err := checkJSFAlgorithmAndKey(sig, kid, pub); err != nil {
		return nil, err
	}
	return root.canonical()
}

// VerifyJSF checks a CycloneDX BOM's enveloped JSF signature against the set:
// RS256 by the key its keyId names, its embedded public key (when present)
// that same key, over the JCS form of the BOM without the value. It returns
// the kid that verified. The BOM's own public key is never trusted alone.
func (s *JWKSet) VerifyJSF(doc []byte) (string, error) {
	root, sig, err := parseJSFDocument(doc)
	if err != nil {
		return "", err
	}
	for _, name := range sig.keys {
		if name != "algorithm" && name != "keyId" && name != "publicKey" && name != "value" {
			return "", fmt.Errorf("jose: the JSF signature property %q is not supported", name)
		}
	}
	kid, ok := jsfString(sig, "keyId")
	if !ok || kid == "" {
		return "", errors.New("jose: the JSF signature names no keyId")
	}
	pub, err := s.selectKey(kid)
	if err != nil {
		return "", err
	}
	if err := checkJSFAlgorithmAndKey(sig, kid, pub); err != nil {
		return "", err
	}
	value, ok := jsfString(sig, "value")
	if !ok || value == "" {
		return "", errors.New("jose: the BOM's JSF signature has no value")
	}
	raw, err := jsfValueEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("jose: the JSF signature value is not base64url: %w", err)
	}
	delete(sig.members, "value")
	sig.keys = slices.DeleteFunc(sig.keys, func(name string) bool { return name == "value" })
	canonical, err := root.canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	if err := rsa.VerifyPKCS1v15(pub, stdcrypto.SHA256, sum[:], raw); err != nil {
		return "", fmt.Errorf("jose: JSF signature verification failed: %w", err)
	}
	return kid, nil
}

// parseJSFDocument reads a CycloneDX BOM and its top-level signature object.
func parseJSFDocument(doc []byte) (*jcsValue, *jcsValue, error) {
	root, err := parseIJSON(doc)
	if err != nil {
		return nil, nil, err
	}
	if root.kind != 'o' {
		return nil, nil, errors.New("jose: a JSF-signed BOM is a JSON object")
	}
	if format, ok := jsfString(root, "bomFormat"); !ok || format != "CycloneDX" {
		return nil, nil, errors.New("jose: JSF signatures here cover CycloneDX BOMs only")
	}
	sig, ok := root.members["signature"]
	if !ok || sig.kind != 'o' {
		return nil, nil, errors.New("jose: the BOM has no signature object")
	}
	return root, sig, nil
}

// checkJSFAlgorithmAndKey requires RS256, the expected kid and, when the
// signature embeds a public key, exactly the expected key.
func checkJSFAlgorithmAndKey(sig *jcsValue, kid string, pub *rsa.PublicKey) error {
	if alg, ok := jsfString(sig, "algorithm"); !ok || alg != "RS256" {
		return errors.New("jose: the JSF signature algorithm must be RS256")
	}
	if got, ok := jsfString(sig, "keyId"); !ok || got != kid {
		return fmt.Errorf("jose: the JSF signature names key %q, not %q", got, kid)
	}
	embedded, ok := sig.members["publicKey"]
	if !ok {
		return nil
	}
	if embedded.kind != 'o' || len(embedded.keys) != 3 {
		return errors.New("jose: the JSF public key must hold exactly kty, n and e")
	}
	kty, _ := jsfString(embedded, "kty")
	n, nOK := jsfString(embedded, "n")
	e, eOK := jsfString(embedded, "e")
	if kty != "RSA" || !nOK || !eOK {
		return errors.New("jose: the JSF public key must hold exactly kty, n and e")
	}
	key, err := jsfRSAKey(n, e)
	if err != nil {
		return err
	}
	if key.E != pub.E || key.N.Cmp(pub.N) != 0 {
		return fmt.Errorf("jose: the JSF public key is not key %q", kid)
	}
	return nil
}

func jsfRSAKey(n, e string) (*rsa.PublicKey, error) {
	nb, err := b64.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("jose: bad RSA modulus encoding: %w", err)
	}
	eb, err := b64.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("jose: bad RSA exponent encoding: %w", err)
	}
	return rsaPublicFromJWK(nb, eb)
}

func jsfString(obj *jcsValue, name string) (string, bool) {
	v, ok := obj.members[name]
	if !ok || v.kind != 's' {
		return "", false
	}
	return v.text, true
}
