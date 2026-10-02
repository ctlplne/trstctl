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
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12,
		},
	}
	return dialer.DialContext(ctx, "tcp", addr)
}
