// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// VerifyDKIM checks a DKIM signature (RFC 6376 §3.3; RFC 8463) over the
// SHA-256 hash of the canonical signed header data. keyType is the key
// record's k= tag: "rsa" keys are SubjectPublicKeyInfo DER (or a bare PKCS#1
// RSAPublicKey) verified with PKCS#1 v1.5, and keys under 1024 bits are
// refused (RFC 8301); "ed25519" keys are the raw 32-byte public key, and the
// signature covers the hash itself.
func VerifyDKIM(keyType string, key, headerHash, signature []byte) error {
	if len(headerHash) != 32 {
		return errors.New("crypto: a DKIM header hash is SHA-256")
	}
	switch keyType {
	case "rsa":
		var pub *rsa.PublicKey
		if parsed, err := x509.ParsePKIXPublicKey(key); err == nil {
			pub, _ = parsed.(*rsa.PublicKey)
		} else if pkcs1, err := x509.ParsePKCS1PublicKey(key); err == nil {
			pub = pkcs1
		}
		if pub == nil {
			return errors.New("crypto: the DKIM rsa key does not parse")
		}
		if pub.N.BitLen() < 1024 {
			return fmt.Errorf("crypto: a %d-bit DKIM rsa key is too small", pub.N.BitLen())
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, headerHash, signature)
	case "ed25519":
		if len(key) != ed25519.PublicKeySize {
			return errors.New("crypto: a DKIM ed25519 key is 32 bytes")
		}
		if !ed25519.Verify(ed25519.PublicKey(key), headerHash, signature) {
			return errors.New("crypto: the DKIM ed25519 signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("crypto: DKIM key type %q is not supported", keyType)
	}
}
