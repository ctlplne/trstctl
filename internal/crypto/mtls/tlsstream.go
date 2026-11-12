// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Listener wraps ln in TLS with this server certificate for a plain TLS
// stream — a syslog receiver (RFC 5425) rather than HTTPS — with the same
// floor and certificate reload as ServeHTTPS.
func (s *ServerCert) Listener(ln net.Listener) net.Listener {
	return tls.NewListener(ln, s.streamTLSConfig())
}

// ServerConn upgrades an accepted connection to TLS with this server
// certificate — SMTP STARTTLS, where the plaintext greeting comes first — with
// the same floor and certificate reload as Listener.
func (s *ServerCert) ServerConn(conn net.Conn) net.Conn {
	return tls.Server(conn, s.streamTLSConfig())
}

// streamTLSConfig is the server TLS configuration for a non-HTTP stream.
func (s *ServerCert) streamTLSConfig() *tls.Config {
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
	return cfg
}

// DialVerifiedTCPWithControl is DialVerifiedTCP whose dial passes through
// control, so an egress guard can refuse the resolved address before any
// connection is made.
func DialVerifiedTCPWithControl(ctx context.Context, addr, serverName string, caPEM []byte, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	return dialVerifiedTCP(ctx, addr, serverName, caPEM, &net.Dialer{Control: control})
}

// DialVerifiedTCPWithClientCert is DialVerifiedTCPWithControl that also
// presents a client certificate: RFC 5425 mutual TLS to a syslog receiver
// (P5-L2). clientPEM holds the certificate chain and its private key in one
// PEM bundle; the caller wipes it once the dial returns. An empty bundle
// presents none.
func DialVerifiedTCPWithClientCert(ctx context.Context, addr, serverName string, caPEM, clientPEM []byte, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	config, err := VerifiedClientTLSConfig(serverName, caPEM)
	if err != nil {
		return nil, err
	}
	if len(clientPEM) > 0 {
		cert, err := tls.X509KeyPair(clientPEM, clientPEM)
		if err != nil {
			return nil, fmt.Errorf("mtls: client certificate bundle: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Control: control}, Config: config}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// The wait for the receiver's verdict scales with the round trip the
	// handshake just took, within bounds.
	wait := min(max(time.Since(started), minVerdictWait), maxVerdictWait)
	if err := awaitServerVerdict(conn.(*tls.Conn), wait); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

const (
	minVerdictWait = 200 * time.Millisecond
	maxVerdictWait = 2 * time.Second
)

// awaitServerVerdict waits, after a TLS 1.3 handshake, for the receiver's
// verdict on the client. In TLS 1.3 the client finishes its handshake before
// the server has checked the client's certificate (or noticed it has none),
// so a receiver that refuses the client answers with an alert the client sees
// only when it reads. A sender that only writes, as a syslog sender does,
// would otherwise count a refused session as delivered (P5-L2). A TLS 1.2
// refusal fails the handshake itself.
func awaitServerVerdict(conn *tls.Conn, wait time.Duration) error {
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		return nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return err
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	if resetErr := conn.SetReadDeadline(time.Time{}); resetErr != nil {
		return resetErr
	}
	if n > 0 {
		return errors.New("mtls: the receiver sent data before the client")
	}
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		return nil // no refusal within the wait: the receiver accepted the session
	}
	return fmt.Errorf("mtls: the receiver refused the session: %w", err)
}

// ListenerRequiringClientCert is Listener for a receiver that requires a
// client certificate verified against clientCAPEM, as an RFC 5425 receiver
// with mutual TLS does (P5-L2's stand-ins and lab receivers).
func (s *ServerCert) ListenerRequiringClientCert(ln net.Listener, clientCAPEM []byte) (net.Listener, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("mtls: no client CA certificates found in PEM")
	}
	cfg := s.streamTLSConfig()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return tls.NewListener(ln, cfg), nil
}

// VerifiedClientCommonName completes the handshake on a connection a
// ListenerRequiringClientCert accepted and returns the common name of the
// client certificate it verified.
func VerifiedClientCommonName(conn net.Conn) (string, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("mtls: not a TLS connection")
	}
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}
	state := tlsConn.ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", errors.New("mtls: the client presented no verified certificate")
	}
	return state.VerifiedChains[0][0].Subject.CommonName, nil
}
