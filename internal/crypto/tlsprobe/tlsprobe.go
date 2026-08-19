// SPDX-License-Identifier: MPL-2.0

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
	// ACMEIdentifier is the 32-byte digest carried in the leaf's id-pe-acmeIdentifier
	// extension (RFC 8737), or nil when absent. TLS-ALPN-01 validation compares it to
	// SHA-256 of the key authorization.
	ACMEIdentifier []byte
}

type config struct {
	timeout    time.Duration
	dialer     *net.Dialer
	alpn       []string
	serverName string
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

// WithALPN offers the given ALPN protocols in the handshake (e.g. "acme-tls/1"
// for TLS-ALPN-01 validation). The negotiated protocol is reported in
// Result.NegotiatedProtocol.
func WithALPN(protos ...string) Option {
	return func(c *config) { c.alpn = protos }
}

// WithServerName overrides the address host used for SNI. Verification of a
// virtual host must ask the listener for the same certificate a real client
// would; recording an override only in the transcript while still sending the
// IP address would inspect the wrong virtual host.
func WithServerName(name string) Option {
	return func(c *config) { c.serverName = name }
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
	if cfg.serverName != "" {
		host = cfg.serverName
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
		// lgtm[go/disabled-certificate-check] An inventory probe must capture the
		// presented certificate even when it is expired/untrusted and sends no data.
		InsecureSkipVerify: true, // #nosec G402 -- discovery inventories whatever cert is served; the connection is never trusted and never carries data (CWE-295)
		ServerName:         host,
		// lgtm[go/insecure-tls] Detecting legacy TLS 1.0 is the purpose of this
		// read-only inventory probe; application clients still require TLS 1.2+.
		MinVersion: tls.VersionTLS10,
		NextProtos: cfg.alpn,
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
	if len(state.PeerCertificates) > 0 {
		res.ACMEIdentifier = acmeIdentifierFromCert(state.PeerCertificates[0])
	}
	return res, nil
}
