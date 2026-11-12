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

// Keystore inspection (X2). A Java keystore (JKS, JCEKS) or PKCS#12 file found
// on a host is described by its entries' certificates: alias, key algorithm
// and size, the public-key fingerprint and the chain length. A JKS or JCEKS key
// entry is never decrypted, because both store certificate chains in the
// clear, and a JCEKS secret key is counted, never unsealed. A PKCS#12
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
	Format       string // "JKS", "JCEKS" or "PKCS12"
	Keys         []KeystoreKeyInfo
	TrustedCerts int
	// SecretKeys counts a JCEKS store's secret key entries (X2-L2).
	SecretKeys int
	// IntegrityVerified is true when a supplied password matched the store's
	// integrity check. A JKS lists its entries without one; a PKCS#12 file
	// cannot be read at all without its password.
	IntegrityVerified bool
}

// ErrKeystoreLocked reports a PKCS#12 file that none of the supplied passwords
// opens: nothing in it can be listed.
var ErrKeystoreLocked = errors.New("crypto: no supplied password opens this PKCS#12 file")

// InspectKeystore reads a JKS, JCEKS or PKCS#12 keystore's metadata, trying
// each password in order (and an empty one last). Other formats are refused.
func InspectKeystore(data []byte, passwords [][]byte) (KeystoreReport, error) {
	if jks.IsJKS(data) {
		return inspectJKS(data, passwords)
	}
	if jks.IsJCEKS(data) {
		return inspectJCEKS(data, passwords)
	}
	return inspectPKCS12(data, passwords)
}

// inspectJCEKS reads a JCEKS keystore (X2-L2) like a JKS one: certificates
// are in the clear, so its entries are listed even when no password matches
// its integrity digest; secret key entries are counted.
func inspectJCEKS(data []byte, passwords [][]byte) (KeystoreReport, error) {
	entries, verified, err := jks.JCEKSEntries(data, passwords)
	if err != nil {
		return KeystoreReport{}, err
	}
	report := KeystoreReport{Format: "JCEKS", IntegrityVerified: verified}
	for _, entry := range entries {
		switch {
		case entry.SecretKey:
			report.SecretKeys++
		case entry.KeyEntry:
			info, err := keystoreKeyInfo(entry.Alias, entry.ChainDER)
			if err != nil {
				return KeystoreReport{}, err
			}
			report.Keys = append(report.Keys, info)
		default:
			report.TrustedCerts++
		}
	}
	return report, nil
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

// inspectPKCS12 lists every key bag of a PKCS#12 file (X2-L1: a Java PKCS12
// keystore holds one per key alias) with its alias and chain, and counts the
// certificates outside every key's chain as trusted.
func inspectPKCS12(data []byte, passwords [][]byte) (KeystoreReport, error) {
	for _, password := range append(append([][]byte(nil), passwords...), nil) {
		keys, trusted, err := pfx.KeyEntries(data, string(password))
		if errors.Is(err, pfx.ErrIncorrectPassword) {
			continue
		}
		if err != nil {
			return KeystoreReport{}, fmt.Errorf("crypto: read PKCS#12: %w", err)
		}
		report := KeystoreReport{Format: "PKCS12", IntegrityVerified: true, TrustedCerts: len(trusted)}
		for _, key := range keys {
			info, err := keystoreKeyInfo(key.Alias, key.ChainDER)
			if err != nil {
				return KeystoreReport{}, err
			}
			report.Keys = append(report.Keys, info)
		}
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
