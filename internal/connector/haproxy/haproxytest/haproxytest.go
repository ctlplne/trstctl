// Package haproxytest is a faithful in-process HAProxy double for connector
// tests and conformance. It records the bundle a connector writes, validates it
// when the connector runs `haproxy -c` (the configuration check), and activates
// it on `systemctl reload haproxy` — modelling that haproxy keeps serving the
// running bundle until a configuration that passes the check is reloaded.
package haproxytest

import (
	"bytes"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/connector"
)

// Server is an in-process stand-in for an HAProxy host. It satisfies
// connector.Ops.
type Server struct {
	mu      sync.Mutex
	crtPath string
	files   map[string][]byte
	active  []byte
	reloads int
}

var _ connector.Ops = (*Server)(nil)

// New returns a server whose bundle is read from crtPath (the `ssl crt` path).
func New(crtPath string) *Server {
	return &Server{crtPath: crtPath, files: map[string][]byte{}}
}

// WriteFile records a file written to the host.
func (s *Server) WriteFile(path string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = clone(data)
	return nil
}

// Exec models the commands the connector runs: `haproxy -c -f <cfg>` validates
// the configuration (here, that the crt file is a combined certificate+key PEM)
// and `systemctl reload haproxy` activates the on-disk bundle. A failed config
// check returns an error and changes nothing.
func (s *Server) Exec(name string, args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(args) >= 1 && args[0] == "-c":
		if !isCombinedPEM(s.files[s.crtPath]) {
			return fmt.Errorf("haproxy: [ALERT] unable to load SSL certificate from PEM file '%s'", s.crtPath)
		}
		return nil
	case name == "systemctl" && containsArg(args, "reload"):
		s.active = clone(s.files[s.crtPath])
		s.reloads++
		return nil
	default:
		return nil
	}
}

// Send is unsupported: the haproxy connector deploys over the filesystem.
func (s *Server) Send(target string, payload []byte) error {
	return fmt.Errorf("haproxytest: the haproxy connector does not use the network")
}

// File returns the data written at path.
func (s *Server) File(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[path]
	return clone(v), ok
}

// Active returns the bundle haproxy is currently serving (set by the last
// reload), or nil if it has never reloaded.
func (s *Server) Active() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.active)
}

// Reloads returns how many times haproxy has reloaded.
func (s *Server) Reloads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloads
}

// isCombinedPEM reports whether b is a single PEM file carrying both the
// certificate and the private key, as HAProxy's `ssl crt` file requires.
func isCombinedPEM(b []byte) bool {
	return bytes.Contains(b, []byte("-----BEGIN CERTIFICATE-----")) &&
		bytes.Contains(b, []byte("-----BEGIN ")) && hasKey(b)
}

func hasKey(b []byte) bool {
	return bytes.Contains(b, []byte("PRIVATE KEY-----"))
}

func containsArg(args []string, v string) bool {
	for _, a := range args {
		if a == v {
			return true
		}
	}
	return false
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
