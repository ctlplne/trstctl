// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// DialVerifiedTCP verifies a service identity before any application bytes are
// sent. A nil CA PEM uses system roots; a supplied CA replaces them rather
// than silently adding broad trust to an operator-pinned private service.
func DialVerifiedTCP(ctx context.Context, addr, serverName string, caPEM []byte) (net.Conn, error) {
	return dialVerifiedTCP(ctx, addr, serverName, caPEM, &net.Dialer{})
}

func dialVerifiedTCP(ctx context.Context, addr, serverName string, caPEM []byte, netDialer *net.Dialer) (net.Conn, error) {
	config, err := VerifiedClientTLSConfig(serverName, caPEM)
	if err != nil {
		return nil, err
	}
	dialer := trust.Dialer(netDialer, config)
	return dialer.DialContext(ctx, "tcp", addr)
}

// VerifiedClientTLSConfig is the client configuration DialVerifiedTCP uses,
// for a protocol that upgrades its own connection in band (LDAP StartTLS,
// A239-L3): the expected server name, the pinned CA (or system roots when
// none), TLS 1.2 at least. Nothing authenticates before the handshake
// verifies the server.
func VerifiedClientTLSConfig(serverName string, caPEM []byte) (*tls.Config, error) {
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
	return trust.HardenTLSConfig(&tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}), nil
}

// VerifyClientConnection upgrades an already dialed connection without bypassing
// the gateway's own dialer. Verify roots and the expected name before any auth.
func VerifyClientConnection(ctx context.Context, conn net.Conn, serverName string, caPEM []byte) (net.Conn, error) {
	if serverName == "" {
		_ = conn.Close()
		return nil, errors.New("mtls: expected TCP server name required")
	}
	config, err := VerifiedClientTLSConfig(serverName, caPEM)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	secured := trust.Client(conn, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()
		return nil, err
	}
	return secured, nil
}
