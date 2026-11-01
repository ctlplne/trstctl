// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// A PKCS#11 token's own attestation of a key it holds (A175). Some tokens
// certify each key they generated with a device attestation key that
// chains to the vendor's root — a YubiKey's PIV attestation is the common
// case, exposed through its PKCS#11 module as certificate objects. When the
// host sends that chain with an edge CA request, the control plane verifies
// it against the vendor roots the segment pinned and that it certifies the
// CSR's key; only then is the key recorded as hardware-attested.

const maxTokenAttestationChain = 4

// ErrTokenAttestationRefused marks a token attestation that does not vouch
// for the request key.
var ErrTokenAttestationRefused = errors.New("token attestation refused")

// YubiKey PIV attestation extensions.
var (
	oidYubicoSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidYubicoPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// TokenAttestation is a verified token attestation of one CSR key.
type TokenAttestation struct {
	// RootSHA256 is the pinned vendor root the chain verified to.
	RootSHA256 string
	// Serial is the device serial number the attestation names, when it
	// names one (YubiKey PIV), else empty.
	Serial string
	// PINPolicy and TouchPolicy are the key's use policies the attestation
	// names (YubiKey PIV), else empty.
	PINPolicy, TouchPolicy string
}

// VerifyPKCS11TokenAttestation verifies a token attestation chain (leaf
// first) against the vendor roots, and that the leaf certifies exactly the
// CSR's public key.
func VerifyPKCS11TokenAttestation(chainDER [][]byte, rootsPEM [][]byte, csrDER []byte, now time.Time) (TokenAttestation, error) {
	refuse := func(format string, args ...any) (TokenAttestation, error) {
		return TokenAttestation{}, &EdgeAttestationError{kind: ErrTokenAttestationRefused, msg: "token attestation: " + fmt.Sprintf(format, args...)}
	}
	if len(chainDER) == 0 || len(chainDER) > maxTokenAttestationChain {
		return refuse("the chain must hold 1 to %d certificates", maxTokenAttestationChain)
	}
	if len(rootsPEM) == 0 {
		return refuse("the segment pins no PKCS#11 attestation root")
	}
	roots, err := parseTPMAttestationRoots(rootsPEM)
	if err != nil {
		return refuse("%v", err)
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		if len(der) == 0 || len(der) > maxDeviceAttestationBytes {
			return refuse("certificate %d has an invalid size", i)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return refuse("parse certificate %d: %v", i, err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 {
		return refuse("the chain does not verify to a pinned vendor root: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return refuse("the CSR cannot be read")
	}
	if !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return refuse("the token attests a different key than the CSR's")
	}
	root := chains[0][len(chains[0])-1]
	digest := sha256.Sum256(root.Raw)
	out := TokenAttestation{RootSHA256: hex.EncodeToString(digest[:])}
	for _, ext := range certs[0].Extensions {
		switch {
		case ext.Id.Equal(oidYubicoSerial):
			var serial int64
			if _, err := asn1.Unmarshal(ext.Value, &serial); err == nil {
				out.Serial = fmt.Sprint(serial)
			}
		case ext.Id.Equal(oidYubicoPolicy) && len(ext.Value) == 2:
			out.PINPolicy, out.TouchPolicy = yubicoPINPolicy(ext.Value[0]), yubicoTouchPolicy(ext.Value[1])
		}
	}
	return out, nil
}

func yubicoPINPolicy(b byte) string {
	switch b {
	case 1:
		return "never"
	case 2:
		return "once"
	case 3:
		return "always"
	default:
		return "default"
	}
}

func yubicoTouchPolicy(b byte) string {
	switch b {
	case 1:
		return "never"
	case 2:
		return "always"
	case 3:
		return "cached"
	default:
		return "default"
	}
}

// TokenAttestationCertifiesCSR checks, without any root, that an
// attestation leaf certifies exactly the CSR's public key: the host's check
// before it sends a chain.
func TokenAttestationCertifiesCSR(leafDER, csrDER []byte) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("token attestation: parse leaf: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("token attestation: parse CSR: %w", err)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return errors.New("token attestation: the token's attestation certifies a different key than the CSR's")
	}
	return nil
}
