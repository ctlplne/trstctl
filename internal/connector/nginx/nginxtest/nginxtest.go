// SPDX-License-Identifier: BUSL-1.1

// Package nginxtest is a faithful in-process NGINX double for connector tests
// and conformance. It records the files a connector writes, validates the
// certificate when the connector runs `nginx -t`, and activates it on
// `nginx -s reload` — modeling that nginx keeps serving the running
// certificate until a configuration that passes validation is reloaded.
package nginxtest

import (
	"bytes"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/connector"
)

// Server is an in-process stand-in for an nginx host. It satisfies connector.Ops.
type Server struct {
	mu       sync.Mutex
	certPath string
	files    map[string][]byte
	active   []byte
	reloads  int
	reexecs  int
}

var _ connector.Ops = (*Server)(nil)

// New returns a server whose certificate is read from certPath (the
// ssl_certificate path in its configuration).
func New(certPath string) *Server {
	return &Server{certPath: certPath, files: map[string][]byte{}}
}

// WriteFile records a file written to the host.
func (s *Server) WriteFile(path string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = clone(data)
	return nil
}

// Exec models the nginx commands the connector runs: `-t` validates the
// configuration (here, that the certificate file is a PEM certificate) and
// `-s reload` activates the on-disk certificate. A failed `-t` returns an error
// and changes nothing.
func (s *Server) Exec(name string, args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(args) == 1 && args[0] == "-t":
		if !looksLikeCertificate(s.files[s.certPath]) {
			return fmt.Errorf("nginx: [emerg] cannot load certificate %q: PEM_read_bio_X509 failed", s.certPath)
		}
		return nil
	case len(args) >= 2 && args[0] == "-s" && args[1] == "reload":
		s.active = clone(s.files[s.certPath])
		s.reloads++
		return nil
	case name == "nginx-upgrade" && len(args) == 0:
		// The re-exec action (TPM-O1-L3): a new master loads the on-disk
		// certificate and the old one exits.
		s.active = clone(s.files[s.certPath])
		s.reexecs++
		return nil
	default:
		return nil
	}
}

// Send is unsupported: the nginx connector deploys over the filesystem, not the
// network.
func (s *Server) Send(target string, payload []byte) error {
	return fmt.Errorf("nginxtest: the nginx connector does not use the network")
}

// File returns the data written at path.
func (s *Server) File(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[path]
	return clone(v), ok
}

// Active returns the certificate nginx is currently serving (set by the last
// successful reload), or nil if it has never reloaded.
func (s *Server) Active() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.active)
}

// Reexecs returns how many times nginx was re-executed (TPM-O1-L3).
func (s *Server) Reexecs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reexecs
}

// Reloads returns how many times nginx has reloaded.
func (s *Server) Reloads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloads
}

func looksLikeCertificate(b []byte) bool {
	return bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----"))
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
