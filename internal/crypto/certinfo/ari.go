package certinfo

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ARICertID builds the ACME Renewal Information (RFC 9773) certificate identifier
// for a certificate (DER): base64url(AuthorityKeyIdentifier) "."
// base64url(SerialNumber), the path component of a renewalInfo request. It lives
// in the crypto boundary because it parses the certificate.
func ARICertID(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("certinfo: certificate has no authority key identifier (required for ARI)")
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(cert.AuthorityKeyId) + "." + enc.EncodeToString(serialDERContent(cert.SerialNumber)), nil
}

// serialDERContent returns the DER INTEGER content octets of a serial number (the
// big-endian bytes, with a leading 0x00 when the high bit is set to keep it
// positive) — what appears in the certificate's serialNumber field.
func serialDERContent(n *big.Int) []byte {
	if n == nil {
		return []byte{0}
	}
	b := n.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	if b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}
