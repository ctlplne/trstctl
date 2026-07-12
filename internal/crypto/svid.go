// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"
)

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
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" {
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("crypto: no SPIFFE ID URI SAN in certificate")
}

// ParseSPIFFEID validates a SPIFFE ID (spiffe://<trust-domain>/<path>) and
// returns it as a *url.URL. A SPIFFE ID with no scheme, no trust domain, a
// query, or a fragment is rejected per the SPIFFE specification.
func ParseSPIFFEID(id string) (*url.URL, error) {
	u, err := url.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid SPIFFE ID %q: %w", id, err)
	}
	if u.Scheme != "spiffe" || u.Host == "" {
		return nil, fmt.Errorf("crypto: invalid SPIFFE ID %q: want spiffe://trust-domain/path", id)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("crypto: SPIFFE ID %q must not carry query, fragment, or userinfo", id)
	}
	return u, nil
}
