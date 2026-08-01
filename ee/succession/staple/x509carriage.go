// SPDX-License-Identifier: LicenseRef-trstctl-EE

package staple

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// x509carriage.go makes the succession attachment a REAL X.509 certificate extension
// (PCAS-claim-32, INT-15): a presenter issues an end-entity certificate carrying the
// attachment, and a relying party extracts and verifies it from the parsed certificate
// inline — no out-of-band resolution. A required-but-absent attachment on a real
// certificate is a verification failure. This is the certificate-extension carriage
// limb; the live-TLS-handshake-extension limb is a separate transport concern. All
// crypto (issuance, certificate parsing) routes through the internal/crypto AN-3
// boundary; the attachment payload is wrapped in a DER OCTET STRING so the extension
// value is well-formed.

// AttachmentCertExtension builds a real, DER-encoded X.509 extension carrying the
// attachment under CertExtensionOID. The JSON attachment payload is wrapped in an
// OCTET STRING so the certificate's extnValue is valid DER.
func AttachmentCertExtension(att Attachment) (crypto.CertificateExtension, error) {
	payload, err := att.Encode()
	if err != nil {
		return crypto.CertificateExtension{}, err
	}
	der, err := asn1.Marshal(payload)
	if err != nil {
		return crypto.CertificateExtension{}, fmt.Errorf("staple: marshal attachment extension: %w", err)
	}
	return crypto.CertificateExtension{OID: CertExtensionOID, Critical: false, Value: der}, nil
}

// IssueStapledLeaf issues a REAL end-entity certificate from csrDER carrying the
// succession attachment as an X.509 extension. caSigner is the issuing authority's key
// (behind the signer's DigestSigner boundary). The returned certificate is DER and
// verifies against caCertDER.
func IssueStapledLeaf(caCertDER []byte, caSigner crypto.DigestSigner, csrDER []byte, att Attachment, ttl time.Duration) ([]byte, error) {
	ext, err := AttachmentCertExtension(att)
	if err != nil {
		return nil, err
	}
	return crypto.SignLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, ttl, crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{ext},
	})
}

// AttachmentFromCertificate extracts the succession attachment from a real leaf
// certificate. found is false when the certificate carries no attachment extension —
// a required-attachment policy treats that as a failure (PCAS-claim-32).
func AttachmentFromCertificate(certDER []byte) (att Attachment, found bool, err error) {
	value, _, ok, err := crypto.LeafExtensionValue(certDER, CertExtensionOID)
	if err != nil {
		return Attachment{}, false, err
	}
	if !ok {
		return Attachment{}, false, nil
	}
	var payload []byte
	rest, err := asn1.Unmarshal(value, &payload)
	if err != nil {
		return Attachment{}, false, fmt.Errorf("staple: parse attachment extension: %w", err)
	}
	if len(rest) != 0 {
		return Attachment{}, false, errors.New("staple: trailing bytes after attachment extension")
	}
	a, err := Decode(payload)
	if err != nil {
		return Attachment{}, false, err
	}
	return a, true, nil
}

// VerifyStapledCertificate extracts the attachment from a REAL certificate and verifies
// it inline under p. Absence of the extension is a failure when p.RequireAttachment
// (PCAS-claim-32: a required-but-absent attachment fails verification), so a presenter
// cannot strip the proof to force a downgrade.
func VerifyStapledCertificate(certDER []byte, p Policy) (Result, error) {
	att, found, err := AttachmentFromCertificate(certDER)
	if err != nil {
		return Result{}, err
	}
	if !found {
		if p.RequireAttachment {
			return Result{}, ErrAttachmentRequired
		}
		return Result{}, ErrNoLimb
	}
	return VerifyStapled(&att, p)
}
