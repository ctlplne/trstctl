// Package apachetest is a faithful in-process Apache (httpd) double for
// connector tests and conformance. It records the files a connector writes,
// validates the certificate when the connector runs `apachectl configtest`, and
// activates it on `apachectl graceful` — modelling that apache keeps serving the
// running certificate until a configuration that passes the config test is
// gracefully reloaded.
package apachetest

import (
	"bytes"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/connector"
)

// Server is an in-process stand-in for an Apache host. It satisfies connector.Ops.
type Server struct {
	mu       sync.Mutex
	certPath string
	files    map[string][]byte
	active   []byte
	reloads  int
}

var _ connector.Ops = (*Server)(nil)

// New returns a server whose certificate is read from certPath (the
// SSLCertificateFile path in its configuration).
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

// Exec models the apachectl commands the connector runs: `configtest` validates
// the configuration (here, that the certificate file is a PEM certificate) and
// `graceful` activates the on-disk certificate. A failed `configtest` returns an
// error and changes nothing.
func (s *Server) Exec(name string, args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(args) == 1 && args[0] == "configtest":
		if !looksLikeCertificate(s.files[s.certPath]) {
			return fmt.Errorf("apachectl: AH02565: cannot load certificate %q: not PEM-encoded", s.certPath)
		}
		return nil
	case len(args) == 1 && args[0] == "graceful":
		s.active = clone(s.files[s.certPath])
		s.reloads++
		return nil
	default:
		return nil
	}
}

// Send is unsupported: the apache connector deploys over the filesystem, not the
// network.
func (s *Server) Send(target string, payload []byte) error {
	return fmt.Errorf("apachetest: the apache connector does not use the network")
}

// File returns the data written at path.
func (s *Server) File(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[path]
	return clone(v), ok
}

// Active returns the certificate apache is currently serving (set by the last
// graceful reload), or nil if it has never reloaded.
func (s *Server) Active() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.active)
}

// Reloads returns how many times apache has gracefully reloaded.
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
