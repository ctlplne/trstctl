// SPDX-License-Identifier: LicenseRef-trstctl-EE

package issuer

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// x509leaf.go issues REAL end-entity certificates that carry the issuer-level
// succession tuple as an X.509 extension (claim 27, INT-14), and reads it back for the
// relying party. The tuple binds the issuing authority's algorithm-epoch and the leaf's
// (algorithm-invariant) rotation version into the certificate itself, so a leaf issued
// under a superseded issuer authority is detectable from the certificate alone — an
// openssl-parseable extension, not an out-of-band record. All crypto (issuance,
// certificate parsing) routes through the internal/crypto AN-3 boundary.

// AuthorityEpochExtensionOID is the trstctl PCAS succession-authority-epoch extension
// (private enterprise arc 1.3.6.1.4.1.59551). It carries the (authority id, issuer
// epoch, rotation version) tuple on an end-entity leaf.
const AuthorityEpochExtensionOID = "1.3.6.1.4.1.59551.2.27"

// ErrNoAuthorityEpoch is returned when a certificate carries no succession-authority
// epoch extension.
var ErrNoAuthorityEpoch = errors.New("issuer: certificate carries no succession-authority-epoch extension")

// authorityEpochExtn is the ASN.1 shape of the extension value.
type authorityEpochExtn struct {
	AuthorityID     string
	IssuerEpoch     *big.Int
	RotationVersion *big.Int
}

// AuthorityEpochExtension builds the non-critical X.509 extension carrying the
// issuer-succession tuple for a leaf issued under posture at the given rotation
// version. The extension is non-critical so a legacy verifier still parses the
// certificate; a PCAS-aware relying party reads and enforces the tuple.
func AuthorityEpochExtension(authorityID string, issuerEpoch, rotationVersion uint64) (crypto.CertificateExtension, error) {
	value, err := asn1.Marshal(authorityEpochExtn{
		AuthorityID:     authorityID,
		IssuerEpoch:     new(big.Int).SetUint64(issuerEpoch),
		RotationVersion: new(big.Int).SetUint64(rotationVersion),
	})
	if err != nil {
		return crypto.CertificateExtension{}, fmt.Errorf("issuer: marshal authority-epoch extension: %w", err)
	}
	return crypto.CertificateExtension{OID: AuthorityEpochExtensionOID, Critical: false, Value: value}, nil
}

// IssueLeafCertificate issues a REAL end-entity certificate from csrDER under the
// issuer's CURRENT posture, stamping the succession-authority-epoch extension so the
// leaf carries (issuerID, issuerEpoch, rotationVersion). caSigner is the issuing
// authority's key (in production, the succession-managed issuer key held behind the
// signer's DigestSigner boundary). The returned certificate is DER and verifies
// against caCertDER.
func IssueLeafCertificate(caCertDER []byte, caSigner crypto.DigestSigner, csrDER []byte, posture IssuerPosture, rotationVersion uint64, ttl time.Duration) ([]byte, error) {
	ext, err := AuthorityEpochExtension(posture.IssuerID, posture.Epoch, rotationVersion)
	if err != nil {
		return nil, err
	}
	return crypto.SignLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, ttl, crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{ext},
	})
}

// ParseAuthorityEpoch reads the succession-authority-epoch tuple from a real leaf
// certificate. It returns ErrNoAuthorityEpoch when the certificate carries no such
// extension, so a policy that requires the extension can treat its absence as a
// failure (claim 27).
func ParseAuthorityEpoch(certDER []byte) (authorityID string, issuerEpoch, rotationVersion uint64, err error) {
	value, _, found, err := crypto.LeafExtensionValue(certDER, AuthorityEpochExtensionOID)
	if err != nil {
		return "", 0, 0, err
	}
	if !found {
		return "", 0, 0, ErrNoAuthorityEpoch
	}
	var extn authorityEpochExtn
	rest, err := asn1.Unmarshal(value, &extn)
	if err != nil {
		return "", 0, 0, fmt.Errorf("issuer: parse authority-epoch extension: %w", err)
	}
	if len(rest) != 0 {
		return "", 0, 0, errors.New("issuer: trailing bytes after authority-epoch extension")
	}
	if extn.IssuerEpoch == nil || extn.RotationVersion == nil || extn.IssuerEpoch.Sign() < 0 || extn.RotationVersion.Sign() < 0 {
		return "", 0, 0, errors.New("issuer: malformed authority-epoch extension")
	}
	if !extn.IssuerEpoch.IsUint64() || !extn.RotationVersion.IsUint64() {
		return "", 0, 0, errors.New("issuer: authority-epoch extension value out of range")
	}
	return extn.AuthorityID, extn.IssuerEpoch.Uint64(), extn.RotationVersion.Uint64(), nil
}
