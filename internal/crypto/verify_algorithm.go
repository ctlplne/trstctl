// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// VerifyAlgorithmMessage verifies a PCAS message signature against the exact
// algorithm named in its signed commitment. RSA and ECDSA verify SHA-256(message);
// signer-held PQC keys sign those digest bytes through their digest-signing
// interface. Ed25519 verifies the message directly. Classical keys use
// SubjectPublicKeyInfo DER; PQC keys use their canonical CIRCL public encoding.
// A mismatched algorithm label or key encoding is refused.
func VerifyAlgorithmMessage(pub PublicKey, message, signature []byte) error {
	switch pub.Algorithm {
	case RSA2048, RSA3072, RSA4096, ECDSAP256, ECDSAP384, ECDSAP521, Ed25519:
		if err := checkClassicalPublicAlgorithm(pub); err != nil {
			return err
		}
		if pub.Algorithm == Ed25519 {
			return VerifyEd25519(pub.DER, message, signature)
		}
		return VerifyMessage(pub.DER, message, signature)
	case Algorithm("ML-DSA-44"), Algorithm("ML-DSA-65"), Algorithm("ML-DSA-87"), Algorithm("Hybrid-Ed25519-Dilithium3"):
		var scheme sign.Scheme
		switch pub.Algorithm {
		case Algorithm("ML-DSA-44"):
			scheme = mldsa44.Scheme()
		case Algorithm("ML-DSA-65"):
			scheme = mldsa65.Scheme()
		case Algorithm("ML-DSA-87"):
			scheme = mldsa87.Scheme()
		case Algorithm("Hybrid-Ed25519-Dilithium3"):
			scheme = eddilithium3.Scheme()
		}
		key, err := scheme.UnmarshalBinaryPublicKey(pub.DER)
		if err != nil {
			return fmt.Errorf("crypto: parse %s public key: %w", pub.Algorithm, err)
		}
		digest := sha256.Sum256(message)
		if !scheme.Verify(key, digest[:], signature, nil) {
			return errors.New("crypto: PQC signature verification failed")
		}
		return nil
	case Algorithm("SLH-DSA-SHA2-128s"), Algorithm("SLH-DSA-SHA2-128f"), Algorithm("SLH-DSA-SHA2-192s"), Algorithm("SLH-DSA-SHA2-256s"):
		id, err := slhdsa.IDByName(string(pub.Algorithm))
		if err != nil {
			return fmt.Errorf("crypto: unknown SLH-DSA parameter set: %w", err)
		}
		key := slhdsa.PublicKey{ID: id}
		if err := key.UnmarshalBinary(pub.DER); err != nil {
			return fmt.Errorf("crypto: parse SLH-DSA public key: %w", err)
		}
		digest := sha256.Sum256(message)
		if !slhdsa.Verify(&key, slhdsa.NewMessage(digest[:]), signature, nil) {
			return errors.New("crypto: SLH-DSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("crypto: unsupported signature algorithm %q", pub.Algorithm)
	}
}

func checkClassicalPublicAlgorithm(pub PublicKey) error {
	parsed, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return fmt.Errorf("crypto: parse public key: %w", err)
	}
	var actual Algorithm
	switch key := parsed.(type) {
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 2048:
			actual = RSA2048
		case 3072:
			actual = RSA3072
		case 4096:
			actual = RSA4096
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			actual = ECDSAP256
		case elliptic.P384():
			actual = ECDSAP384
		case elliptic.P521():
			actual = ECDSAP521
		}
	case ed25519.PublicKey:
		actual = Ed25519
	}
	if actual != pub.Algorithm {
		return fmt.Errorf("crypto: public key algorithm %q differs from commitment %q", actual, pub.Algorithm)
	}
	return nil
}
