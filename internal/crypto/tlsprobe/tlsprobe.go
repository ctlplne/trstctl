// Package tlsprobe performs a non-invasive TLS handshake to obtain the
// certificate a server presents, for certificate discovery (F2, S6.1). It is
// part of the AN-3 crypto boundary — a subpackage of internal/crypto, so it
// alone may import crypto/tls — and returns the peer certificates as opaque DER
// bytes, so the network scanner that drives it imports no crypto/*.
//
// "Non-invasive" is the contract: Probe completes the TLS handshake and closes,
// sending no application-layer data. It never authenticates the certificate
// (InsecureSkipVerify) because the goal is to inventory whatever is served —
// including expired, self-signed, or otherwise invalid certificates — so it must
// never be used to establish a trusted connection.
package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

const defaultTimeout = 10 * time.Second

// Result is the outcome of a probe.
type Result struct {
	// PeerCertificates is the certificate chain the server presented, DER-encoded,
	// leaf first.
	PeerCertificates [][]byte
	// TLSVersion is the negotiated TLS version (tls.VersionTLS12, etc.).
	TLSVersion uint16
	// NegotiatedProtocol is the ALPN protocol, if any.
	NegotiatedProtocol string
}

type config struct {
	timeout time.Duration
	dialer  *net.Dialer
}

// Option configures a probe.
type Option func(*config)

// WithTimeout bounds the dial and handshake (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// Probe dials addr (host:port), performs a TLS handshake to capture the
// presented certificate chain, and closes without sending application data. The
// host part of addr is sent as SNI. It returns an error if the address is
// malformed, the dial or handshake fails, or no certificate is presented.
func Probe(ctx context.Context, addr string, opts ...Option) (Result, error) {
	cfg := config{timeout: defaultTimeout, dialer: &net.Dialer{}}
	for _, o := range opts {
		o(&cfg)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Result{}, fmt.Errorf("tlsprobe: invalid address %q: %w", addr, err)
	}

	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}

	conn, err := cfg.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("tlsprobe: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// InsecureSkipVerify: we inventory whatever certificate is presented, valid or
	// not — this connection is never used to send or trust data.
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // discovery captures the served cert; it never trusts the connection
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Result{}, fmt.Errorf("tlsprobe: handshake %s: %w", addr, err)
	}

	// Deliberately send no application data — the probe is non-invasive.
	state := tlsConn.ConnectionState()
	res := Result{TLSVersion: state.Version, NegotiatedProtocol: state.NegotiatedProtocol}
	for _, c := range state.PeerCertificates {
		der := make([]byte, len(c.Raw))
		copy(der, c.Raw)
		res.PeerCertificates = append(res.PeerCertificates, der)
	}
	if len(res.PeerCertificates) == 0 {
		return Result{}, fmt.Errorf("tlsprobe: %s presented no certificate", addr)
	}
	return res, nil
}
