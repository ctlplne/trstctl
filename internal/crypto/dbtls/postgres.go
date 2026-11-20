// SPDX-License-Identifier: BUSL-1.1

// Package dbtls builds native database driver TLS profiles from admitted
// public trust material.
package dbtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"

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

// PostgresPreferDial confines a native driver's plaintext fallback to
// listeners that explicitly refused this attempt's PostgreSQL SSL request.
// The same guard also covers pgx's separate connection for a cancellation.
func PostgresPreferDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	plain := &postgresPlaintextAuthority{refused: make(map[string]bool)}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &postgresPreferConn{Conn: conn, address: address, authority: plain}, nil
	}
}

type postgresPlaintextAuthority struct {
	mu      sync.Mutex
	refused map[string]bool
}

func (a *postgresPlaintextAuthority) allow(address string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refused[address]
}

func (a *postgresPlaintextAuthority) note(address string, refused bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if refused {
		a.refused[address] = true
	} else {
		delete(a.refused, address)
	}
}

type postgresPreferConn struct {
	net.Conn
	address   string
	authority *postgresPlaintextAuthority
	writeOnce sync.Once
	probing   atomic.Bool
	answered  atomic.Bool
	writeErr  error
}

var postgresSSLRequest = []byte{0, 0, 0, 8, 4, 210, 22, 47}

func (c *postgresPreferConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	c.writeOnce.Do(func() {
		if bytes.Equal(payload, postgresSSLRequest) {
			c.authority.note(c.address, false)
			c.probing.Store(true)
			return
		}
		if !c.authority.allow(c.address) {
			c.writeErr = errors.New("PostgreSQL plaintext fallback requires an explicit TLS refusal")
		}
	})
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(payload)
}

func (c *postgresPreferConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if n == 1 && c.probing.Load() && c.answered.CompareAndSwap(false, true) && payload[0] == 'N' {
		c.authority.note(c.address, true)
	}
	return n, err
}
