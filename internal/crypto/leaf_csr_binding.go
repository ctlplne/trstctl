// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// VerifyLeafBoundToCSR checks that a recovered certificate really certifies
// the key and all identities from the signed CSR, within the approved lifetime.
// Chain verification is a separate caller obligation.
func VerifyLeafBoundToCSR(certDER, csrDER []byte, issuedAt time.Time, ttl time.Duration) error {
	if ttl <= 0 || issuedAt.IsZero() {
		return errors.New("crypto: certificate binding needs issuance time and positive TTL")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("crypto: parse approved CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("crypto: approved CSR signature: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("crypto: parse emergency leaf: %w", err)
	}
	csrPub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(csrPub, certPub) || cert.Subject.CommonName != csr.Subject.CommonName ||
		!slices.Equal(cert.DNSNames, csr.DNSNames) || !slices.Equal(cert.EmailAddresses, csr.EmailAddresses) ||
		!slices.Equal(ipStrings(cert.IPAddresses), ipStrings(csr.IPAddresses)) ||
		!slices.Equal(uriStrings(cert.URIs), uriStrings(csr.URIs)) {
		return errors.New("crypto: emergency leaf key or identity differs from approved CSR")
	}
	// The X.509 issuer backdates NotBefore for clock skew. The forward expiry
	// remains bounded by the signed TTL, with a minute for issue/receipt timing.
	if cert.NotAfter.After(issuedAt.Add(ttl+time.Minute)) || cert.NotAfter.Before(issuedAt) ||
		cert.NotBefore.After(issuedAt.Add(time.Minute)) {
		return errors.New("crypto: emergency leaf validity exceeds approved lifetime")
	}
	return nil
}
