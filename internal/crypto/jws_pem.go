// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// SignJWTWithPEMKey signs claims as a compact JWS with a private key given as
// one unencrypted PEM block (PKCS #8, SEC 1 EC or PKCS #1 RSA), for an API
// client that authenticates with a JWT it signs itself, such as a GitHub App
// (RS256). The key is held locked while it signs and destroyed afterwards; the
// JOSE alg follows the key (RS256 for RSA, ES256/384/512 for EC).
func SignJWTWithPEMKey(privateKeyPEM []byte, kid string, claims any) (string, error) {
	block, rest := pem.Decode(bytes.TrimSpace(privateKeyPEM))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return "", errors.New("crypto: the JWT signing key must be one unencrypted PEM block")
	}
	defer secret.Wipe(block.Bytes)
	signer, err := lockedRetainedHostSigner(block)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()
	return SignJWT(signer, kid, claims)
}

// PublicKeyDERFromPEMKey returns the SubjectPublicKeyInfo DER of a private key
// given as one unencrypted PEM block, for an API that names the signing key by
// its public key's fingerprint (Snowflake's key-pair JWT issuer).
func PublicKeyDERFromPEMKey(privateKeyPEM []byte) ([]byte, error) {
	block, rest := pem.Decode(bytes.TrimSpace(privateKeyPEM))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("crypto: the private key must be one unencrypted PEM block")
	}
	defer secret.Wipe(block.Bytes)
	signer, err := lockedRetainedHostSigner(block)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	return append([]byte(nil), signer.Public().DER...), nil
}

// SignRSASHA256WithPEMKey signs message with RSASSA-PKCS1-v1_5 over SHA-256,
// using an RSA private key given as one unencrypted PEM block, for an API
// client that signs its own requests (OCI request signing, A241). The key is
// held locked while it signs and destroyed afterwards; a non-RSA key is
// refused.
func SignRSASHA256WithPEMKey(privateKeyPEM, message []byte) ([]byte, error) {
	block, rest := pem.Decode(bytes.TrimSpace(privateKeyPEM))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("crypto: the signing key must be one unencrypted PEM block")
	}
	defer secret.Wipe(block.Bytes)
	signer, err := lockedRetainedHostSigner(block)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	switch signer.Algorithm() {
	case RSA2048, RSA3072, RSA4096:
	default:
		return nil, errors.New("crypto: the signing key must be RSA")
	}
	return signer.SignDigest(SHA256Sum(message), SignOptions{Hash: SHA256, RSAPadding: RSAPKCS1v15})
}
