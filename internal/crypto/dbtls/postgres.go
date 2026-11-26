// SPDX-License-Identifier: BUSL-1.1

// Package dbtls builds native database driver TLS profiles from admitted
// public trust material.
package dbtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Postgres returns a TLS configuration for each permitted attempt at the
// same endpoint in libpq's order. A nil configuration selects plaintext.
func Postgres(mode, negotiation, host, serverName string, ca []byte, systemRoots bool) ([]*tls.Config, error) {
	if mode == "" {
		mode = "prefer"
	}
	if negotiation == "direct" {
		if mode == "disable" || mode == "allow" {
			return nil, errors.New("direct PostgreSQL TLS requires an encrypted mode")
		}
		if mode == "prefer" {
			mode = "require"
		}
	}
	hasTrust := serverName != "" || len(ca) != 0 || systemRoots
	if hasTrust && (mode == "disable" || mode == "allow") {
		return nil, errors.New("configured PostgreSQL trust requires TLS")
	}
	if systemRoots || serverName != "" || len(ca) != 0 && mode == "prefer" {
		mode = "verify-full"
	}
	if mode == "disable" {
		return []*tls.Config{nil}, nil
	}
	if serverName == "" {
		serverName = host
	}
	config, err := mtls.VerifiedClientTLSConfig(serverName, ca)
	if err != nil {
		return nil, err
	}
	if negotiation == "direct" {
		config.NextProtos = []string{"postgresql"}
	}
	switch mode {
	case "verify-full", "verify-ca", "require":
		return []*tls.Config{config}, nil
	case "prefer":
		return []*tls.Config{config, nil}, nil
	case "allow":
		return []*tls.Config{nil, config}, nil
	default:
		return nil, errors.New("unsupported PostgreSQL TLS mode")
	}
}

// PostgresPreferDial confines a native driver's plaintext fallback to a
// connection that itself explicitly refuses PostgreSQL's SSL request. A prior
// refusal on another socket cannot authorize plaintext on a concurrent socket.
// The same guard covers pgx's separate connection for a cancellation.
func PostgresPreferDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &postgresPreferConn{Conn: conn}, nil
	}
}

type postgresPreferConn struct {
	net.Conn
	writeOnce sync.Once
	writeErr  error
}

var postgresSSLRequest = []byte{0, 0, 0, 8, 4, 210, 22, 47}

func (c *postgresPreferConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	c.writeOnce.Do(func() {
		if bytes.Equal(payload, postgresSSLRequest) {
			return
		}
		// pgx chose a plaintext fallback. Ask this very connection whether it
		// supports TLS before passing the startup bytes to it. A refusal on a
		// previous connection is not evidence about this one.
		n, err := c.Conn.Write(postgresSSLRequest)
		if err != nil {
			c.writeErr = err
			return
		}
		if n != len(postgresSSLRequest) {
			c.writeErr = io.ErrShortWrite
			return
		}
		answer := []byte{0}
		if _, err := io.ReadFull(c.Conn, answer); err != nil {
			c.writeErr = err
			return
		}
		if answer[0] != 'N' {
			c.writeErr = errors.New("PostgreSQL plaintext fallback refused: server did not reject TLS")
		}
	})
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(payload)
}
