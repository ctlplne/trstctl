// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"syscall"
)

// Listener wraps ln in TLS with this server certificate for a plain TLS
// stream — a syslog receiver (RFC 5425) rather than HTTPS — with the same
// floor and certificate reload as ServeHTTPS.
func (s *ServerCert) Listener(ln net.Listener) net.Listener {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: CurvePreferences()}
	if s.AllowTLS12 {
		cfg.MinVersion = tls.VersionTLS12
		cfg.CipherSuites = tls12AEADSuites()
	}
	if s.reload != nil {
		cfg.GetCertificate = s.reload.GetCertificate
	} else {
		cfg.Certificates = []tls.Certificate{s.cert}
	}
	return tls.NewListener(ln, cfg)
}

// DialVerifiedTCPWithControl is DialVerifiedTCP whose dial passes through
// control, so an egress guard can refuse the resolved address before any
// connection is made.
func DialVerifiedTCPWithControl(ctx context.Context, addr, serverName string, caPEM []byte, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	return dialVerifiedTCP(ctx, addr, serverName, caPEM, &net.Dialer{Control: control})
}
