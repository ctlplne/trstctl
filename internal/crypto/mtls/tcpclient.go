// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// DialVerifiedTCP verifies a service identity before any application bytes are
// sent. A nil CA PEM uses system roots; a supplied CA replaces them rather
// than silently adding broad trust to an operator-pinned private service.
func DialVerifiedTCP(ctx context.Context, addr, serverName string, caPEM []byte) (net.Conn, error) {
	return dialVerifiedTCP(ctx, addr, serverName, caPEM, &net.Dialer{})
}

func dialVerifiedTCP(ctx context.Context, addr, serverName string, caPEM []byte, netDialer *net.Dialer) (net.Conn, error) {
	if serverName == "" {
		return nil, errors.New("mtls: expected TCP server name required")
	}
	var roots *x509.CertPool
	if len(caPEM) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("mtls: no CA certificates found in PEM")
		}
	}
	dialer := tls.Dialer{
		NetDialer: netDialer,
		Config: &tls.Config{
			RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12,
		},
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// VerifyClientConnection upgrades an already dialed connection without bypassing
// the gateway's own dialer. Verify roots and the expected name before any auth.
func VerifyClientConnection(ctx context.Context, conn net.Conn, serverName string, caPEM []byte) (net.Conn, error) {
	if serverName == "" {
		_ = conn.Close()
		return nil, errors.New("mtls: expected TCP server name required")
	}
	var roots *x509.CertPool
	if len(caPEM) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			_ = conn.Close()
			return nil, errors.New("mtls: no CA certificates found in PEM")
		}
	}
	secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()
		return nil, err
	}
	return secured, nil
}
