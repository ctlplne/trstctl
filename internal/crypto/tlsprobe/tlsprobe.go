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

// DefaultTimeout is the maximum time one non-invasive TLS inventory handshake
// may occupy a worker. It is exported so plan previews can state the exact bound
// the probe enforces instead of duplicating a number in user-facing code.
const DefaultTimeout = 10 * time.Second

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
	timeout      time.Duration
	dialer       *net.Dialer
	alpn         []string
	serverName   string
	preHandshake PreHandshake
}

// PreHandshake negotiates an application-level upgrade to TLS on the raw TCP
// connection before the ClientHello is sent (for example PostgreSQL's
// SSLRequest). It must consume exactly the bytes of that negotiation and return
// an error when the peer declines TLS.
type PreHandshake func(ctx context.Context, conn net.Conn) error

// WithPreHandshake runs an application-protocol negotiation (STARTTLS-style)
// on the raw connection before the TLS handshake. See PostgresSSLRequest.
func WithPreHandshake(negotiate PreHandshake) Option {
	return func(c *config) {
		c.preHandshake = negotiate
	}
}

// Option configures a probe.
type Option func(*config)

// Probe stages named by StageError.
const (
	StageDial      = "dial"
	StageNegotiate = "negotiate"
	StageHandshake = "handshake"
)

// StageError reports which stage of a probe failed so callers can tell an
// unreachable listener (dial) from one that is reachable but speaks a protocol
// that needs negotiation before TLS (handshake). Its text is stable:
// "tlsprobe: <stage> <addr>: <cause>".
type StageError struct {
	Stage string
	Addr  string
	Err   error
}

func (e *StageError) Error() string {
	return "tlsprobe: " + e.Stage + " " + e.Addr + ": " + e.Err.Error()
}

func (e *StageError) Unwrap() error { return e.Err }

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
	cfg := config{timeout: DefaultTimeout, dialer: &net.Dialer{}}
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
		return Result{}, &StageError{Stage: StageDial, Addr: addr, Err: err}
	}
	defer func() { _ = conn.Close() }()

	if cfg.preHandshake != nil {
		if err := cfg.preHandshake(ctx, conn); err != nil {
			return Result{}, &StageError{Stage: StageNegotiate, Addr: addr, Err: err}
		}
	}

	// InsecureSkipVerify: we inventory whatever certificate is presented, valid or
	// not — this connection is never used to send or trust data.
	tlsConn := tls.Client(conn, &tls.Config{
		// An inventory probe must capture the presented certificate even when it
		// is expired/untrusted and sends no data.
		// codeql[go/disabled-certificate-check]
		InsecureSkipVerify: true, // #nosec G402 -- discovery inventories whatever cert is served; the connection is never trusted and never carries data (CWE-295)
		ServerName:         host,
		// Detecting legacy TLS 1.0 is the purpose of this read-only inventory
		// probe; application clients still require TLS 1.2+.
		// codeql[go/insecure-tls]
		MinVersion: tls.VersionTLS10,
		NextProtos: cfg.alpn,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Result{}, &StageError{Stage: StageHandshake, Addr: addr, Err: err}
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
