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

	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/pfx"
)

// Keystore inspection (X2). A Java keystore or PKCS#12 file found on a host is
// described by its entries' certificates: alias, key algorithm and size, the
// public-key fingerprint and the chain length. A JKS key entry is never
// decrypted, because JKS stores certificate chains in the clear. A PKCS#12
// file decodes its key on the way to its certificates; the key is wiped at
// once. Only this metadata leaves the crypto boundary.

// KeystoreKeyInfo describes one key entry of a keystore.
type KeystoreKeyInfo struct {
	Alias     string
	Algorithm Algorithm
	// KeyType and KeyBits are the key family (RSA, ECDSA, Ed25519) and its
	// size in bits (the modulus, the curve, 256 for Ed25519).
	KeyType string
	KeyBits int
	// FingerprintSHA256 is SHA-256 over the entry certificate's public key
	// (SubjectPublicKeyInfo), the same basis InspectPrivateKey uses, so a key
	// found in a keystore and in a PEM file correlate.
	FingerprintSHA256 string
	FingerprintBasis  string
	CertificateSHA256 string
	ChainLength       int
	WeakReasons       []string
}

// KeystoreReport is what a keystore yields.
type KeystoreReport struct {
	Format       string // "JKS" or "PKCS12"
	Keys         []KeystoreKeyInfo
	TrustedCerts int
	// IntegrityVerified is true when a supplied password matched the store's
	// integrity check. A JKS lists its entries without one; a PKCS#12 file
	// cannot be read at all without its password.
	IntegrityVerified bool
}

// ErrKeystoreLocked reports a PKCS#12 file that none of the supplied passwords
// opens: nothing in it can be listed.
var ErrKeystoreLocked = errors.New("crypto: no supplied password opens this PKCS#12 file")

// InspectKeystore reads a JKS or PKCS#12 keystore's metadata, trying each
// password in order (and an empty one last). JCEKS and other formats are
// refused.
func InspectKeystore(data []byte, passwords [][]byte) (KeystoreReport, error) {
	if jks.IsJKS(data) {
		return inspectJKS(data, passwords)
	}
	if len(data) >= 4 && data[0] == 0xCE && data[1] == 0xCE && data[2] == 0xCE && data[3] == 0xCE {
		return KeystoreReport{}, errors.New("crypto: JCEKS keystores are not read")
	}
	return inspectPKCS12(data, passwords)
}

func inspectJKS(data []byte, passwords [][]byte) (KeystoreReport, error) {
	entries, verified, err := jks.Entries(data, passwords)
	if err != nil {
		return KeystoreReport{}, err
	}
	report := KeystoreReport{Format: "JKS", IntegrityVerified: verified}
	for _, entry := range entries {
		if !entry.KeyEntry {
			report.TrustedCerts++
			continue
		}
		info, err := keystoreKeyInfo(entry.Alias, entry.ChainDER)
		if err != nil {
			return KeystoreReport{}, err
		}
		report.Keys = append(report.Keys, info)
	}
	return report, nil
}

func inspectPKCS12(data []byte, passwords [][]byte) (KeystoreReport, error) {
	for _, password := range append(append([][]byte(nil), passwords...), nil) {
		chain, hasKey, err := pfx.ChainDER(data, string(password))
		if errors.Is(err, pfx.ErrIncorrectPassword) {
			continue
		}
		if err != nil {
			return KeystoreReport{}, fmt.Errorf("crypto: read PKCS#12: %w", err)
		}
		report := KeystoreReport{Format: "PKCS12", IntegrityVerified: true}
		if !hasKey {
			report.TrustedCerts = len(chain)
			return report, nil
		}
		info, err := keystoreKeyInfo("", chain)
		if err != nil {
			return KeystoreReport{}, err
		}
		report.Keys = []KeystoreKeyInfo{info}
		return report, nil
	}
	return KeystoreReport{Format: "PKCS12"}, ErrKeystoreLocked
}

func keystoreKeyInfo(alias string, chain [][]byte) (KeystoreKeyInfo, error) {
	if len(chain) == 0 {
		return KeystoreKeyInfo{Alias: alias, Algorithm: "unknown"}, nil
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return KeystoreKeyInfo{}, fmt.Errorf("crypto: keystore entry %q certificate: %w", alias, err)
	}
	algorithm, keyType, bits, weak := classifyCertificateKey(cert)
	return KeystoreKeyInfo{
		Alias: alias, Algorithm: algorithm, KeyType: keyType, KeyBits: bits,
		FingerprintSHA256: SHA256Hex(cert.RawSubjectPublicKeyInfo), FingerprintBasis: "public-spki-sha256",
		CertificateSHA256: SHA256Hex(cert.Raw), ChainLength: len(chain), WeakReasons: weak,
	}, nil
}

// classifyCertificateKey names a certificate's public key the way
// classifyPrivateKey names a private key, with the same weak floors.
func classifyCertificateKey(cert *x509.Certificate) (Algorithm, string, int, []string) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		var weak []string
		if bits < minimumRSABits {
			weak = append(weak, fmt.Sprintf("RSA-%d is below the %d-bit minimum", bits, minimumRSABits))
		}
		switch bits {
		case 2048:
			return RSA2048, "RSA", bits, weak
		case 3072:
			return RSA3072, "RSA", bits, weak
		case 4096:
			return RSA4096, "RSA", bits, weak
		}
		return Algorithm(fmt.Sprintf("RSA-%d", bits)), "RSA", bits, weak
	case *ecdsa.PublicKey:
		if pub.Curve == nil {
			return "ECDSA", "ECDSA", 0, nil
		}
		params := pub.Params()
		var weak []string
		if params.BitSize < minimumECBits {
			weak = append(weak, fmt.Sprintf("%s is below the %d-bit curve minimum", params.Name, minimumECBits))
		}
		return Algorithm("ECDSA-" + strings.ReplaceAll(params.Name, "-", "")), "ECDSA", params.BitSize, weak
	case ed25519.PublicKey:
		return Ed25519, "Ed25519", 256, nil
	}
	return Algorithm(cert.PublicKeyAlgorithm.String()), cert.PublicKeyAlgorithm.String(), 0, nil
}
