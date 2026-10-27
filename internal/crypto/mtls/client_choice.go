// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// A listener for clients that are not all issued by one CA (A197's tenant
// self-service KMIP clients). TLS 1.3 still requires the client to present a
// certificate and prove it holds the certificate's key; which certificates are
// served is the protocol's decision, made after the handshake, so the listener
// checks only that the certificate parses and is inside its validity period.
// Session tickets are off, so every connection presents its certificate again.

// SelfAuthorizingClientTLSServerListenerFromFiles wraps ln in TLS 1.3 that
// requires a client certificate with proof of possession but leaves the
// decision to serve it to the caller (see PeerCertificateChainDER).
func SelfAuthorizingClientTLSServerListenerFromFiles(ln net.Listener, certFile, keyFile string) (net.Listener, error) {
	reload, err := newReloadingServerCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := serverTLSConfig(*reload.current.Load(), nil)
	cfg.Certificates = nil
	cfg.GetCertificate = reload.GetCertificate
	cfg.ClientAuth = tls.RequireAnyClientCert
	cfg.SessionTicketsDisabled = true
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("mtls: the client presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("mtls: client certificate: %w", err)
		}
		if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return errors.New("mtls: client certificate is outside its validity period")
		}
		return nil
	}
	return tls.NewListener(ln, cfg), nil
}

// PeerCertificateChainDER returns the chain a TLS peer presented, leaf first,
// after the handshake. On a self-authorizing listener it is not yet trusted:
// the caller decides.
func PeerCertificateChainDER(conn net.Conn) ([][]byte, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("mtls: connection is %T, not TLS", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("mtls: handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("mtls: no peer certificate")
	}
	chain := make([][]byte, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		chain = append(chain, append([]byte(nil), cert.Raw...))
	}
	return chain, nil
}

// ClientChainVerifier checks a presented client chain against a CA bundle,
// for a listener that also serves CA-issued clients.
type ClientChainVerifier struct {
	roots *x509.CertPool
}

// NewClientChainVerifier loads caFile.
func NewClientChainVerifier(caFile string) (*ClientChainVerifier, error) {
	roots, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &ClientChainVerifier{roots: roots}, nil
}

// Verifies reports whether chain's leaf is a client certificate the CA bundle
// issued, through the intermediates the chain carries.
func (v *ClientChainVerifier) Verifies(chain [][]byte) bool {
	if v == nil || len(chain) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, raw := range chain[1:] {
		if cert, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(cert)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: v.roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}
