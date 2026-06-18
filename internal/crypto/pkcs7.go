package crypto

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
)

// PKCS#7 "certs-only" (degenerate SignedData) encoding, used by EST (RFC 7030):
// /cacerts and the enrollment responses ship the CA chain / issued certificate as
// a certificate-only PKCS#7. This lives inside the crypto boundary (AN-3) so the
// protocol servers never touch ASN.1 directly.

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     signedData `asn1:"explicit,tag:0"`
}

// DegeneratePKCS7 encodes one or more DER certificates as a certs-only PKCS#7
// SignedData (no signers, no content). The certificate order is preserved.
func DegeneratePKCS7(certsDER [][]byte) ([]byte, error) {
	if len(certsDER) == 0 {
		return nil, errors.New("crypto: DegeneratePKCS7 requires at least one certificate")
	}
	var concat []byte
	for _, c := range certsDER {
		concat = append(concat, c...)
	}
	return pkcs7.DegenerateCertificate(concat)
}

// CertsFromPKCS7 extracts the DER certificates from a certs-only PKCS#7
// SignedData (the inverse of DegeneratePKCS7 — used by the EST client side and by
// tests). It does not verify signatures (a degenerate PKCS#7 carries none).
func CertsFromPKCS7(der []byte) ([][]byte, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("crypto: parse PKCS#7 ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("crypto: not a PKCS#7 SignedData (oid %v)", ci.ContentType)
	}
	sd := ci.Content
	if !sd.ContentInfo.ContentType.Equal(oidData) {
		return nil, fmt.Errorf("crypto: PKCS#7 SignedData carried unsupported content type %v", sd.ContentInfo.ContentType)
	}
	// Walk the certificates [0] IMPLICIT field, splitting concatenated DER SEQUENCEs.
	var out [][]byte
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var one asn1.RawValue
		next, err := asn1.Unmarshal(rest, &one)
		if err != nil {
			return nil, fmt.Errorf("crypto: split PKCS#7 certificates: %w", err)
		}
		out = append(out, one.FullBytes)
		rest = next
	}
	if len(out) == 0 {
		return nil, errors.New("crypto: PKCS#7 carried no certificates")
	}
	return out, nil
}
