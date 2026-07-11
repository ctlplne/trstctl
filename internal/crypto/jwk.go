// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JSONWebKey is the public subset of an RSA or EC JWK. Cloud KMS APIs return
// these base64url-decoded values; converting them to SPKI lives inside the
// crypto boundary so provider packages never import crypto/rsa, crypto/ecdsa,
// elliptic, or x509 (AN-3).
type JSONWebKey struct {
	KeyType string
	Curve   string
	N       []byte
	E       []byte
	X       []byte
	Y       []byte
}

// NormalizeECDSASignature converts the fixed-width IEEE-P1363 r||s form returned
// by Azure Key Vault and several HSM APIs into the ASN.1 DER form Go's X.509
// signer contract requires. Already-DER signatures are validated and preserved.
func NormalizeECDSASignature(algorithm Algorithm, signature []byte) ([]byte, error) {
	var coordinateBytes int
	switch algorithm {
	case ECDSAP256:
		coordinateBytes = 32
	case ECDSAP384:
		coordinateBytes = 48
	case ECDSAP521:
		coordinateBytes = 66
	default:
		return nil, fmt.Errorf("crypto: algorithm %q is not ECDSA", algorithm)
	}
	if len(signature) == 2*coordinateBytes {
		return asn1.Marshal(struct{ R, S *big.Int }{
			R: new(big.Int).SetBytes(signature[:coordinateBytes]),
			S: new(big.Int).SetBytes(signature[coordinateBytes:]),
		})
	}
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, errors.New("crypto: malformed ECDSA signature")
	}
	return append([]byte(nil), signature...), nil
}

// PublicKeyFromJWK validates a cloud-provider public JWK and marshals it as the
// backend-neutral DER SubjectPublicKeyInfo used by DigestSigner.Public.
func PublicKeyFromJWK(jwk JSONWebKey) (PublicKey, error) {
	switch strings.ToUpper(strings.TrimSpace(jwk.KeyType)) {
	case "RSA", "RSA-HSM":
		return rsaPublicKeyFromJWK(jwk)
	case "EC", "EC-HSM":
		return ecPublicKeyFromJWK(jwk)
	default:
		return PublicKey{}, fmt.Errorf("crypto: unsupported JWK key type %q", jwk.KeyType)
	}
}

func rsaPublicKeyFromJWK(jwk JSONWebKey) (PublicKey, error) {
	if len(jwk.N) == 0 || len(jwk.E) == 0 {
		return PublicKey{}, errors.New("crypto: RSA JWK requires n and e")
	}
	n := new(big.Int).SetBytes(jwk.N)
	eBig := new(big.Int).SetBytes(jwk.E)
	if !eBig.IsInt64() || eBig.Sign() <= 0 {
		return PublicKey{}, errors.New("crypto: RSA JWK exponent is invalid")
	}
	e64 := eBig.Int64()
	if e64 > int64(^uint(0)>>1) || e64 < 3 || e64%2 == 0 {
		return PublicKey{}, errors.New("crypto: RSA JWK exponent is invalid")
	}
	var algorithm Algorithm
	switch n.BitLen() {
	case 2048:
		algorithm = RSA2048
	case 3072:
		algorithm = RSA3072
	case 4096:
		algorithm = RSA4096
	default:
		return PublicKey{}, fmt.Errorf("crypto: unsupported RSA JWK modulus size %d", n.BitLen())
	}
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: int(e64)})
	if err != nil {
		return PublicKey{}, fmt.Errorf("crypto: marshal RSA JWK public key: %w", err)
	}
	return PublicKey{Algorithm: algorithm, DER: der}, nil
}

func ecPublicKeyFromJWK(jwk JSONWebKey) (PublicKey, error) {
	if len(jwk.X) == 0 || len(jwk.Y) == 0 {
		return PublicKey{}, errors.New("crypto: EC JWK requires x and y")
	}
	var curve elliptic.Curve
	var algorithm Algorithm
	switch strings.ToUpper(strings.TrimSpace(jwk.Curve)) {
	case "P-256":
		curve, algorithm = elliptic.P256(), ECDSAP256
	case "P-384":
		curve, algorithm = elliptic.P384(), ECDSAP384
	case "P-521":
		curve, algorithm = elliptic.P521(), ECDSAP521
	default:
		return PublicKey{}, fmt.Errorf("crypto: unsupported EC JWK curve %q", jwk.Curve)
	}
	public, err := parseECDSAPublicKeyComponents(curve, jwk.X, jwk.Y)
	if err != nil {
		return PublicKey{}, errors.New("crypto: EC JWK point is not on the declared curve")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return PublicKey{}, fmt.Errorf("crypto: marshal EC JWK public key: %w", err)
	}
	return PublicKey{Algorithm: algorithm, DER: der}, nil
}
