// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"net"
)

// SMTPClientTLSConfig preserves verified STARTTLS for an external SMTP relay.
// System roots and the exact relay hostname remain mandatory. TLS 1.2 is the
// compatibility floor for this external integration, as for directory clients.
func SMTPClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// SMTPStartTLS upgrades an SMTP connection after the server accepted STARTTLS
// and returns the TLS connection (P15-L5): the email channel drives its own
// SMTP exchange over it, so it can write the AUTH PLAIN line from a buffer it
// wipes, and it imports no crypto/* itself (AN-3).
func SMTPStartTLS(conn net.Conn, serverName string) (net.Conn, error) {
	tlsConn := tls.Client(conn, SMTPClientTLSConfig(serverName))
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
