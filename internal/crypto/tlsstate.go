// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// ErrCSRNotBoundToIdentity is returned when a CSR requests an identifier that the
// authenticated enrollment certificate does not itself assert.
var ErrCSRNotBoundToIdentity = errors.New("crypto: CSR identifiers are not authorized by the authenticated identity")

// CSRBoundToCertificateIdentity is the shared enrollment binding: every
// identifier a CSR requests (CN, DNS, IP, email, URI) must already be asserted by
// authority — the authenticated certificate whose holder is enrolling. An
// authenticated credential may re-key its OWN identity but must never mint a
// different name the issuance profile happens to admit, or one stolen credential
// is tenant-wide in blast radius. CMP's protection-identity binding and EST's RFC
// 7030 §4.2.2 re-enrollment check are the same rule; it lives here so no
// enrollment front-end can skip it (AN-3, AUD-201 follow-up).
func CSRBoundToCertificateIdentity(csrDER []byte, authority *x509.Certificate) error {
	if authority == nil {
		return errors.New("crypto: no authenticated certificate to bind the CSR to")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("crypto: parse CSR for identity binding: %w", err)
	}
	authorized := map[string]bool{}
	if cn := strings.TrimSpace(authority.Subject.CommonName); cn != "" {
		authorized["dns:"+strings.ToLower(cn)] = true
		authorized["cn:"+strings.ToLower(cn)] = true
	}
	for _, dns := range authority.DNSNames {
		authorized["dns:"+strings.ToLower(dns)] = true
	}
	for _, ip := range authority.IPAddresses {
		authorized["ip:"+ip.String()] = true
	}
	for _, email := range authority.EmailAddresses {
		authorized["email:"+strings.ToLower(email)] = true
	}
	for _, uri := range authority.URIs {
		authorized["uri:"+uri.String()] = true
	}

	var requested []string
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		requested = append(requested, "cn:"+strings.ToLower(cn))
	}
	for _, dns := range csr.DNSNames {
		requested = append(requested, "dns:"+strings.ToLower(dns))
	}
	for _, ip := range csr.IPAddresses {
		requested = append(requested, "ip:"+ip.String())
	}
	for _, email := range csr.EmailAddresses {
		requested = append(requested, "email:"+strings.ToLower(email))
	}
	for _, uri := range csr.URIs {
		requested = append(requested, "uri:"+uri.String())
	}
	if len(requested) == 0 {
		// Nothing to authorize is not authorization: an identifier-free CSR under
		// the binding policy is refused rather than minted blind.
		return fmt.Errorf("%w: the CSR requests no identifiers", ErrCSRNotBoundToIdentity)
	}
	for _, want := range requested {
		if authorized[want] {
			continue
		}
		// A CSR CN is also satisfied by a matching SAN (cn: falls back to dns:
		// above); anything else is a cross-identity request.
		if strings.HasPrefix(want, "cn:") && authorized["dns:"+strings.TrimPrefix(want, "cn:")] {
			continue
		}
		return fmt.Errorf("%w: %q is not asserted by the authenticated certificate", ErrCSRNotBoundToIdentity, want)
	}
	return nil
}

// CSRBoundToTLSClientIdentity binds a CSR to the certificate the peer
// authenticated with on a TLS request. EST re-enrollment uses it so an mTLS
// credential can re-key only its own name (RFC 7030 §4.2.2), keeping x509 inside
// the crypto boundary (AN-3).
func CSRBoundToTLSClientIdentity(state *tls.ConnectionState, csrDER []byte) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("crypto: TLS client certificate required to bind the CSR")
	}
	return CSRBoundToCertificateIdentity(csrDER, state.PeerCertificates[0])
}

// TLSConnectionState is a small wrapper for tests and protocol packages that
// need a TLS peer state without importing crypto/tls outside the crypto boundary.
type TLSConnectionState struct {
	state *tls.ConnectionState
}

// ConnectionState exposes the wrapped TLS state for net/http request wiring.
func (s *TLSConnectionState) ConnectionState() *tls.ConnectionState {
	if s == nil {
		return nil
	}
	return s.state
}

// TLSStateWithPeerCertificates builds a TLS peer state from DER certificates.
// It is used by protocol tests and by callers that receive peer chains in a
// boundary-neutral form.
func TLSStateWithPeerCertificates(certsDER [][]byte) (*TLSConnectionState, error) {
	certs, err := parseCertificates(certsDER)
	if err != nil {
		return nil, err
	}
	return &TLSConnectionState{state: &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  certs,
		VerifiedChains:    [][]*x509.Certificate{certs},
	}}, nil
}

// VerifyTLSClientCertificate verifies the peer certificate chain on a TLS request
// against DER trust anchors. It keeps x509 verification inside internal/crypto
// (AN-3) while EST/KMIP-style protocols consume only request state and DER roots.
func VerifyTLSClientCertificate(state *tls.ConnectionState, rootsDER [][]byte) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("crypto: TLS client certificate required")
	}
	roots, err := certPoolFromDER(rootsDER)
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("crypto: verify TLS client certificate: %w", err)
	}
	return nil
}

func parseCertificates(certsDER [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(certsDER))
	for i, der := range certsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func certPoolFromDER(certsDER [][]byte) (*x509.CertPool, error) {
	if len(certsDER) == 0 {
		return nil, errors.New("crypto: at least one trust anchor is required")
	}
	roots := x509.NewCertPool()
	certs, err := parseCertificates(certsDER)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		roots.AddCert(cert)
	}
	return roots, nil
}
