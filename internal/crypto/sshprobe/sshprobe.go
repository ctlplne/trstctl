// Package sshprobe performs a non-invasive SSH protocol handshake to capture the
// host key a server presents, for SSH host-key discovery (F42, S6.3) — the SSH
// analog of internal/crypto/tlsprobe. It is part of the AN-3 crypto boundary and
// returns crypto-free metadata, so the network scanner that drives it imports no
// SSH crypto.
//
// "Non-invasive" is the contract and is structural: the host key is verified
// during the transport handshake, before authentication, so Probe captures it in
// the host-key callback and aborts there — it never sends a username, never
// attempts authentication, and never opens a session or runs a command.
package sshprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultTimeout = 10 * time.Second

// errCaptured aborts the handshake from the host-key callback once the key is in
// hand, so authentication is never attempted.
var errCaptured = errors.New("sshprobe: host key captured")

// Result is the outcome of a probe.
type Result struct {
	// HostKeyType is the SSH host key type, e.g. "ssh-ed25519".
	HostKeyType string
	// FingerprintSHA256 is the standard OpenSSH fingerprint ("SHA256:<base64>").
	FingerprintSHA256 string
}

type config struct{ timeout time.Duration }

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

// Probe dials addr (host:port), performs an SSH handshake far enough to receive
// the server's host key, and aborts — never authenticating. It returns an error
// if the address is unreachable or the handshake fails before the host key.
func Probe(ctx context.Context, addr string, opts ...Option) (Result, error) {
	cfg := config{timeout: defaultTimeout}
	for _, o := range opts {
		o(&cfg)
	}

	var captured ssh.PublicKey
	clientCfg := &ssh.ClientConfig{
		User: "trstctl-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errCaptured // we have the host key; do not proceed to auth
		},
		Timeout: cfg.timeout,
	}

	dialer := net.Dialer{Timeout: cfg.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("sshprobe: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if cfg.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.timeout))
	}

	sc, chans, reqs, hsErr := ssh.NewClientConn(conn, addr, clientCfg)
	if hsErr == nil {
		// Unexpected (the callback always aborts), but if the handshake fully
		// completed, tear it down without using the connection.
		go ssh.DiscardRequests(reqs)
		go func() {
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "probe")
			}
		}()
		_ = sc.Close()
	}

	if captured == nil {
		return Result{}, fmt.Errorf("sshprobe: %s: handshake failed before host key: %w", addr, hsErr)
	}
	return Result{HostKeyType: captured.Type(), FingerprintSHA256: ssh.FingerprintSHA256(captured)}, nil
}
