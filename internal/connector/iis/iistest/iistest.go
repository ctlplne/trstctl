// SPDX-License-Identifier: MPL-2.0

// Package iistest is a faithful in-process IIS (HTTP.SYS / Windows certificate
// store) double for connector tests and conformance. It models the two effects
// the IIS connector produces: importing a certificate into the machine store
// (via a PowerShell command) and binding a certificate thumbprint to an HTTPS
// site (via `netsh http ... sslcert`).
package iistest

import (
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/connector"
)

// Server is an in-process stand-in for an IIS host. It satisfies connector.Ops.
type Server struct {
	mu       sync.Mutex
	imports  int
	bindings map[string]string // ipport -> certhash (thumbprint)
	files    map[string][]byte
	writes   map[string][][]byte
	execs    [][]string
}

var _ connector.Ops = (*Server)(nil)

// New returns a server with no imported certificates and no bindings.
func New() *Server {
	return &Server{bindings: map[string]string{}, files: map[string][]byte{}, writes: map[string][][]byte{}}
}

// Exec models the commands the IIS connector runs: a PowerShell command that
// adds a certificate to the machine store, and `netsh http {add|update|delete}
// sslcert` that manages an HTTPS binding.
func (s *Server) Exec(name string, args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.execs = append(s.execs, append([]string{name}, args...))
	if isStoreImport(args) {
		s.imports++
		return nil
	}
	// netsh http <verb> sslcert ...
	if len(args) >= 3 && args[0] == "http" && args[2] == "sslcert" {
		ipport := argValue(args, "ipport=")
		if ipport == "" {
			return fmt.Errorf("iistest: netsh sslcert without an ipport")
		}
		switch args[1] {
		case "add", "update":
			certhash := argValue(args, "certhash=")
			if certhash == "" {
				return fmt.Errorf("iistest: netsh %s sslcert without a certhash", args[1])
			}
			s.bindings[ipport] = certhash
		case "delete":
			delete(s.bindings, ipport)
		}
		return nil
	}
	return nil
}

// WriteFile records the transient PFX/password files staged for PowerShell.
func (s *Server) WriteFile(path string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := append([]byte(nil), data...)
	s.files[path] = copied
	s.writes[path] = append(s.writes[path], append([]byte(nil), data...))
	return nil
}

// Send is unsupported: the IIS connector does not use the network.
func (s *Server) Send(target string, payload []byte) error {
	return fmt.Errorf("iistest: the iis connector does not use the network")
}

// Imports returns how many certificates have been imported into the store.
func (s *Server) Imports() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imports
}

// Binding returns the certificate thumbprint bound to ipport, if any.
func (s *Server) Binding(ipport string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.bindings[ipport]
	return v, ok
}

// Files returns the staged files observed by the test double.
func (s *Server) Files() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.files))
	for k, v := range s.files {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// Writes returns every file payload written, grouped by path.
func (s *Server) Writes() map[string][][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][][]byte, len(s.writes))
	for k, writes := range s.writes {
		out[k] = make([][]byte, len(writes))
		for i, v := range writes {
			out[k][i] = append([]byte(nil), v...)
		}
	}
	return out
}

// Execs returns the command invocations observed by the test double.
func (s *Server) Execs() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.execs))
	for i, e := range s.execs {
		out[i] = append([]string(nil), e...)
	}
	return out
}

// isStoreImport reports whether the command adds a certificate to the Windows
// store (the connector's PowerShell uses System.Security...X509Store).
func isStoreImport(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "Import-PfxCertificate") {
			return true
		}
	}
	return false
}

// argValue returns the suffix of the first argument starting with prefix.
func argValue(args []string, prefix string) string {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return a[len(prefix):]
		}
	}
	return ""
}
