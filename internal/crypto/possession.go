// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/weakkey"
)

// The key ceremony's two checks (eMudhra, Part 4). eMudhra's account allows
// two readings: a weak key generated inside the HSM, or a certificate naming a
// different key from the one the HSM holds. RefuseWeakKey answers the first;
// ProvePossession answers the second.

// ErrPossessionUnsupported means the key's algorithm has no possession check
// here; a caller records that possession was not proven rather than claim it.
var ErrPossessionUnsupported = errors.New("crypto: no possession check for this key algorithm")

// possessionContext separates the challenge from anything else a CA key signs.
const possessionContext = "trstctl CA key ceremony proof of possession v1\x00"

// ProvePossession signs a fresh, domain-separated 32-byte challenge with
// signer and verifies the signature against want, the exact public key going
// into a certificate. A signer that reports one key but signs with another, or
// cannot sign, fails. The signature follows the convention
// VerifyAlgorithmMessage checks for every signer-held family: the signer
// signs SHA-256 of the challenge (RSA PKCS #1 v1.5 and ECDSA over that digest;
// ML-DSA, SLH-DSA and the Ed25519-Dilithium3 hybrid over its 32 bytes).
// Ed25519 has no digest-signing path, so it yields ErrPossessionUnsupported.
func ProvePossession(signer DigestSigner, want PublicKey) error {
	if signer == nil {
		return errors.New("crypto: no signer to prove possession with")
	}
	if len(want.DER) == 0 {
		return errors.New("crypto: no public key to prove possession of")
	}
	if !possessionAlgorithm(want.Algorithm) {
		return ErrPossessionUnsupported
	}
	challenge, err := RandomBytes(32)
	if err != nil {
		return err
	}
	message := append([]byte(possessionContext), challenge...)
	digest, err := Digest(SHA256, message)
	if err != nil {
		return err
	}
	signature, err := signer.SignDigest(digest, SignOptions{Hash: SHA256})
	if err != nil {
		return fmt.Errorf("crypto: possession challenge could not be signed: %w", err)
	}
	if err := VerifyAlgorithmMessage(want, message, signature); err != nil {
		return fmt.Errorf("crypto: the signer does not hold the private key for the certified public key: %w", err)
	}
	return nil
}

// possessionAlgorithm reports whether ProvePossession can check alg.
func possessionAlgorithm(alg Algorithm) bool {
	switch alg {
	case RSA2048, RSA3072, RSA4096, ECDSAP256, ECDSAP384, ECDSAP521,
		Algorithm("ML-DSA-44"), Algorithm("ML-DSA-65"), Algorithm("ML-DSA-87"), Algorithm("Hybrid-Ed25519-Dilithium3"),
		Algorithm("SLH-DSA-SHA2-128s"), Algorithm("SLH-DSA-SHA2-128f"), Algorithm("SLH-DSA-SHA2-192s"), Algorithm("SLH-DSA-SHA2-256s"):
		return true
	default:
		return false
	}
}

// RefuseWeakKey refuses to certify, generate or import a public key that the
// weak-key checks flag (internal/crypto/weakkey). A post-quantum key (ML-DSA,
// SLH-DSA, the hybrid) has no classical structure to test and passes; a
// classical or unlabeled key that does not parse is refused.
func RefuseWeakKey(pub PublicKey) error {
	if len(pub.DER) == 0 {
		return errors.New("crypto: no public key to check")
	}
	if PureMessageSignatureAlgorithm(pub.Algorithm) || strings.HasPrefix(string(pub.Algorithm), "Hybrid-") {
		return nil
	}
	findings, err := weakkey.Default().CheckSPKI(pub.DER)
	if err != nil {
		return fmt.Errorf("crypto: public key does not parse: %w", err)
	}
	if len(findings) > 0 {
		return fmt.Errorf("crypto: refusing a weak key: %s", weakkey.Reasons(findings))
	}
	return nil
}

// refuseCeremonyCertificate refuses to import, cross-sign or chain to a CA
// certificate whose key is weak or which is on the distrust list.
func refuseCeremonyCertificate(cert *x509.Certificate, label string) error {
	if e, ok := trust.Active().Match(cert); ok {
		return fmt.Errorf("crypto: %s is on the distrust list (%s): %s", label, e.Name, e.Reason)
	}
	if findings := weakkey.Default().CheckPublicKey(cert.PublicKey); len(findings) > 0 {
		return fmt.Errorf("crypto: refusing %s with a weak key: %s", label, weakkey.Reasons(findings))
	}
	return nil
}

// SignIntermediateHierarchyCAForSigner certifies the child signer's key under
// the parent only after the child proves it holds that key, so a signer that
// reports one key and holds another never gets a CA certificate.
func SignIntermediateHierarchyCAForSigner(parentCertDER []byte, parentSigner, child DigestSigner, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	if child == nil {
		return IssuedHierarchyCA{}, errors.New("crypto: no child signer")
	}
	if err := ProvePossession(child, child.Public()); err != nil {
		return IssuedHierarchyCA{}, err
	}
	return SignIntermediateHierarchyCA(parentCertDER, parentSigner, child.Public(), profile)
}

// offlinePossessionContext binds an offline root's possession signature to
// the one-time key ceremony that imports it.
const offlinePossessionContext = "trstctl offline root proof of possession v1\x00"

// OfflinePossessionMessage is what an offline root signs, during its import
// ceremony, to prove its key: the context string, a zero byte, and the
// ceremony id.
func OfflinePossessionMessage(ceremonyID string) []byte {
	return append([]byte(offlinePossessionContext), []byte(ceremonyID)...)
}

// VerifyOfflinePossession checks an offline root's signature over
// OfflinePossessionMessage(ceremonyID) against the root certificate's key,
// with VerifyAlgorithmMessage's convention: RSA (PKCS #1 v1.5) and ECDSA over
// SHA-256 of the message, Ed25519 over the message itself, ML-DSA over the
// SHA-256 digest's 32 bytes. Another key type yields ErrPossessionUnsupported.
func VerifyOfflinePossession(rootDER []byte, ceremonyID string, signature []byte) error {
	if strings.TrimSpace(ceremonyID) == "" {
		return errors.New("crypto: an offline possession signature needs the ceremony id")
	}
	if len(signature) == 0 {
		return errors.New("crypto: the offline possession signature is empty")
	}
	cert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fmt.Errorf("crypto: parse offline root: %w", err)
	}
	pub, err := possessionPublicKeyOfCertificate(cert)
	if err != nil {
		return err
	}
	if err := VerifyAlgorithmMessage(pub, OfflinePossessionMessage(ceremonyID), signature); err != nil {
		return fmt.Errorf("crypto: the offline root's possession signature does not verify: %w", err)
	}
	return nil
}

// possessionPublicKeyOfCertificate names a certificate's key the way
// VerifyAlgorithmMessage needs it: the labelled SubjectPublicKeyInfo for a
// classical key, the raw ML-DSA key for an RFC 9881 certificate.
func possessionPublicKeyOfCertificate(cert *x509.Certificate) (PublicKey, error) {
	if pub, pure, err := purePublicKeyOfCertificate(cert); err != nil {
		return PublicKey{}, err
	} else if pure {
		return pub, nil
	}
	var alg Algorithm
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch k.Params().Name {
		case "P-256":
			alg = ECDSAP256
		case "P-384":
			alg = ECDSAP384
		case "P-521":
			alg = ECDSAP521
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			alg = RSA2048
		case 3072:
			alg = RSA3072
		case 4096:
			alg = RSA4096
		}
	case ed25519.PublicKey:
		alg = Ed25519
	}
	if alg == "" {
		return PublicKey{}, ErrPossessionUnsupported
	}
	return PublicKey{Algorithm: alg, DER: append([]byte(nil), cert.RawSubjectPublicKeyInfo...)}, nil
}
