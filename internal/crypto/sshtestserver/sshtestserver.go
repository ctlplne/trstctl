// SPDX-License-Identifier: BUSL-1.1

// Package sshtestserver starts a minimal in-process SSH server with a fresh
// ed25519 host key, for tests that need a real SSH endpoint to probe. It lives
// in the crypto boundary (it generates a key with crypto/ed25519), so packages
// outside the boundary can exercise SSH discovery end to end without importing
// crypto themselves — the same role the connector doubles play for HTTP targets.
package sshtestserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// Server is a running test SSH server.
type Server struct {
	ln          net.Listener
	fingerprint string
	authTried   atomic.Bool
}

// Start brings up an SSH server on a loopback port. Close it when done.
func Start() (*Server, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			s.authTried.Store(true)
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	go s.accept(cfg)
	return s, nil
}

func (s *Server) accept(cfg *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return // a non-invasive probe aborts before auth; expected
			}
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "test server")
			}
			_ = sc.Close()
		}(conn)
	}
}

// Addr is the server's host:port.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// FingerprintSHA256 is the host key's OpenSSH fingerprint.
func (s *Server) FingerprintSHA256() string { return s.fingerprint }

// AuthAttempted reports whether any client tried to authenticate — false after a
// non-invasive probe.
func (s *Server) AuthAttempted() bool { return s.authTried.Load() }

// Close stops the server.
func (s *Server) Close() { _ = s.ln.Close() }
