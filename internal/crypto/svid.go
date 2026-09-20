// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// MaxSPIFFEIDLength is our wire-size limit, including scheme, trust domain and
// path. SPIFFE requires support through 2048 bytes and discourages longer IDs.
const MaxSPIFFEIDLength = 2048

// SignSVID issues an X.509-SVID (SPIFFE) leaf certificate: its only SAN is the
// SPIFFE ID URI, and it carries the key usage SPIFFE requires (digitalSignature
// + keyEncipherment on the leaf, with serverAuth and clientAuth so a single SVID
// authenticates both ends of an mTLS connection). leafPubDER is the workload's
// PKIX-encoded public key; the CA key never leaves the DigestSigner (AN-4). The
// issued certificate is verified against the CA before return, so a misbehaving
// signer fails closed instead of emitting an unverifiable SVID.
func SignSVID(caCertDER []byte, caSigner DigestSigner, leafPubDER []byte, spiffeID string, ttl time.Duration) ([]byte, error) {
	id, err := ParseSPIFFEID(spiffeID)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(leafPubDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SVID public key: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		URIs:                  []*url.URL{id},
		NotBefore:             IssuanceNotBefore(now),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
	}
	if len(caCert.SubjectKeyId) > 0 {
		leaf.AuthorityKeyId = caCert.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, pub, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign SVID: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued SVID: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued SVID failed verification (signer misbehaved): %w", err)
	}
	return der, nil
}

// CertValidity returns the NotBefore/NotAfter window of a DER certificate. It is
// the boundary helper callers use to reason about expiry and rotation without
// importing crypto/x509 themselves (AN-3).
func CertValidity(der []byte) (notBefore, notAfter time.Time, err error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("crypto: parse cert: %w", err)
	}
	return c.NotBefore, c.NotAfter, nil
}

// SPIFFEIDFromCert extracts the single SPIFFE ID URI SAN from an X.509-SVID.
func SPIFFEIDFromCert(certDER []byte) (string, error) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("crypto: parse SVID: %w", err)
	}
	if len(c.URIs) != 1 {
		return "", fmt.Errorf("crypto: SVID certificate must contain exactly one URI SAN")
	}
	id, err := ParseSPIFFEID(c.URIs[0].String())
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// ParseSPIFFEID accepts canonical SPIFFE wire identities. The scheme and trust
// domain must already be lowercase; the path keeps its case. We do not decode,
// trim, normalize or clean an identity used in exact authorization comparisons.
// The byte grammar rejects percent escapes, ports, queries (even empty ones),
// fragments, userinfo and empty/relative path segments before URL construction.
// This intentionally requires canonical input, like the stock go-spiffe parser,
// rather than accepting alternative casing permitted by generic URI parsing.
func ParseSPIFFEID(id string) (*url.URL, error) {
	if len(id) > MaxSPIFFEIDLength {
		return nil, fmt.Errorf("crypto: SPIFFE ID exceeds %d bytes", MaxSPIFFEIDLength)
	}
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return nil, fmt.Errorf("crypto: SPIFFE ID requires the canonical spiffe:// scheme")
	}
	domain, suffix, hasPath := strings.Cut(rest, "/")
	if len(domain) == 0 || len(domain) > 255 {
		return nil, fmt.Errorf("crypto: SPIFFE trust domain must contain 1–255 bytes")
	}
	for i := range len(domain) {
		c := domain[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		return nil, fmt.Errorf("crypto: SPIFFE trust domain requires lowercase letters, digits, dots, dashes or underscores")
	}
	path := ""
	if hasPath {
		for _, segment := range strings.Split(suffix, "/") {
			if err := ValidateSPIFFEPathSegment(segment); err != nil {
				return nil, err
			}
		}
		path = "/" + suffix
	}
	return &url.URL{Scheme: "spiffe", Host: domain, Path: path}, nil
}

// ValidateSPIFFEPathSegment checks one segment without URI normalization or a
// synthetic trust domain. Constructors use the same grammar as the signer;
// ParseSPIFFEID separately bounds the length of the complete wire identity.
func ValidateSPIFFEPathSegment(segment string) error {
	if segment == "" || segment == "." || segment == ".." {
		return fmt.Errorf("crypto: SPIFFE path must not contain empty or relative segments")
	}
	for i := range len(segment) {
		c := segment[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		return fmt.Errorf("crypto: SPIFFE path requires letters, digits, dots, dashes or underscores")
	}
	return nil
}
