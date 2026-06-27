package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

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
