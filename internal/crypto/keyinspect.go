// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PrivateKeyInfo is metadata about private-key material. It deliberately carries
// only classification and a fingerprint of the derived public key; it never
// contains the key bytes that were inspected (AN-8).
type PrivateKeyInfo struct {
	Format            string
	Algorithm         Algorithm
	FingerprintSHA256 string
	FingerprintBasis  string
	Encrypted         bool
}

// InspectPrivateKey classifies private-key material behind the crypto boundary
// (AN-3). The returned fingerprint is SHA-256 over the public SubjectPublicKeyInfo
// DER, so inventory can deduplicate keys without hashing or storing private bytes.
func InspectPrivateKey(data []byte) (PrivateKeyInfo, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return PrivateKeyInfo{}, errors.New("crypto: empty private key")
	}
	if block, _ := pem.Decode(trimmed); block != nil {
		return inspectPEMPrivateKey(trimmed, block)
	}
	return inspectDERPrivateKey(trimmed)
}

func inspectPEMPrivateKey(pemBytes []byte, block *pem.Block) (PrivateKeyInfo, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return inspectPKCS8PrivateKey(block.Bytes, "PKCS8")
	case "RSA PRIVATE KEY":
		return inspectPKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return inspectECPrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return inspectOpenSSHPrivateKey(pemBytes)
	case "ENCRYPTED PRIVATE KEY":
		return PrivateKeyInfo{Format: "PKCS8-ENCRYPTED", Encrypted: true}, nil
	default:
		if strings.Contains(block.Type, "PRIVATE KEY") && encryptedPEMBlock(block) {
			return PrivateKeyInfo{Format: block.Type, Encrypted: true}, nil
		}
	}
	return PrivateKeyInfo{}, fmt.Errorf("crypto: unsupported private key PEM block %q", block.Type)
}

func inspectDERPrivateKey(der []byte) (PrivateKeyInfo, error) {
	if info, err := inspectPKCS8PrivateKey(der, "PKCS8-DER"); err == nil {
		return info, nil
	}
	if info, err := inspectPKCS1PrivateKey(der); err == nil {
		info.Format = "PKCS1-RSA-DER"
		return info, nil
	}
	if info, err := inspectECPrivateKey(der); err == nil {
		info.Format = "SEC1-EC-DER"
		return info, nil
	}
	return PrivateKeyInfo{}, errors.New("crypto: data is not a supported private key")
}

func inspectPKCS8PrivateKey(der []byte, format string) (PrivateKeyInfo, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return PrivateKeyInfo{}, err
	}
	defer wipeStdlibKey(key)
	return privateKeyInfoFromParsed(key, format)
}

func inspectPKCS1PrivateKey(der []byte) (PrivateKeyInfo, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return PrivateKeyInfo{}, err
	}
	defer wipeStdlibKey(key)
	return privateKeyInfoFromParsed(key, "PKCS1-RSA")
}

func inspectECPrivateKey(der []byte) (PrivateKeyInfo, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return PrivateKeyInfo{}, err
	}
	defer wipeStdlibKey(key)
	return privateKeyInfoFromParsed(key, "SEC1-EC")
}

func inspectOpenSSHPrivateKey(data []byte) (PrivateKeyInfo, error) {
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		if privateKeyParseLooksEncrypted(err) {
			return PrivateKeyInfo{Format: "OPENSSH-ENCRYPTED", Encrypted: true}, nil
		}
		return PrivateKeyInfo{}, err
	}
	defer wipeStdlibKey(key)
	return privateKeyInfoFromParsed(key, "OPENSSH")
}

func privateKeyInfoFromParsed(key any, format string) (PrivateKeyInfo, error) {
	signer, ok := key.(stdcrypto.Signer)
	if !ok {
		return PrivateKeyInfo{}, fmt.Errorf("crypto: unsupported private key type %T", key)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return PrivateKeyInfo{}, fmt.Errorf("crypto: marshal public key: %w", err)
	}
	return PrivateKeyInfo{
		Format:            format,
		Algorithm:         classifyPrivateKey(key),
		FingerprintSHA256: SHA256Hex(pubDER),
		FingerprintBasis:  "public-spki-sha256",
	}, nil
}

func classifyPrivateKey(key any) Algorithm {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch k.N.BitLen() {
		case 2048:
			return RSA2048
		case 3072:
			return RSA3072
		case 4096:
			return RSA4096
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256
		case elliptic.P384():
			return ECDSAP384
		case elliptic.P521():
			return ECDSAP521
		}
	case ed25519.PrivateKey:
		return Ed25519
	}
	return ""
}

func encryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}
	if _, ok := block.Headers["DEK-Info"]; ok {
		return true
	}
	if _, ok := block.Headers["Proc-Type"]; ok {
		return true
	}
	return false
}

func privateKeyParseLooksEncrypted(err error) bool {
	if err == nil {
		return false
	}
	var passphraseMissing *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissing) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "passphrase") || strings.Contains(msg, "encrypted")
}
