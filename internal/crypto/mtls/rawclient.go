// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
)

// MutualTLSClientConnFromFiles upgrades raw to a TLS 1.3 mutually authenticated
// connection using operator-provided client material and a server trust anchor.
// It is intended for raw protocols such as KMIP: unlike the gRPC credentials in
// this package, the TLS configuration advertises no application protocol (in
// particular, no HTTP/2 ALPN value).
//
// The handshake completes before the connection is returned, including normal
// certificate-chain and server-name verification. On every error this function
// closes raw; after success ownership of the returned connection belongs to the
// caller.
func MutualTLSClientConnFromFiles(
	ctx context.Context,
	raw net.Conn,
	certFile, keyFile, serverCAFile, serverName string,
) (net.Conn, error) {
	if raw == nil {
		return nil, errors.New("mtls: raw client connection is nil")
	}
	fail := func(err error) (net.Conn, error) {
		_ = raw.Close()
		return nil, err
	}
	if ctx == nil {
		return fail(errors.New("mtls: client handshake context is nil"))
	}
	if strings.TrimSpace(serverName) == "" {
		return fail(errors.New("mtls: server name is required"))
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fail(fmt.Errorf("mtls: load client certificate: %w", err))
	}
	serverCAs, err := loadCAPool(serverCAFile)
	if err != nil {
		return fail(err)
	}

	cfg := clientTLSConfig(StaticSource(cert), serverCAs, serverName, nil)
	// Raw protocols must negotiate their own framing directly over TLS. Keeping
	// NextProtos empty prevents accidental HTTP/2 ALPN coupling.
	cfg.NextProtos = nil
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("mtls: client handshake: %w", err))
	}
	return tlsConn, nil
}
