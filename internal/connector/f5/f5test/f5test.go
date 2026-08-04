// SPDX-License-Identifier: MPL-2.0

// Package f5test is a faithful in-process double of the F5 BIG-IP iControl REST
// API, for testing the f5 connector without a real appliance. It is an
// httptest.Server that accepts the upload, crypto-install, and Client SSL
// profile calls the connector makes, requires authentication, and records the
// resulting state so a test can assert the certificate was installed and bound.
package f5test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Chain is the cert/key pair a Client SSL profile references.
type Chain struct {
	Cert string
	Key  string
}

// Server is a fake BIG-IP iControl REST endpoint.
type Server struct {
	srv  *httptest.Server
	user string
	pass string

	mu       sync.Mutex
	uploads  map[string][]byte // filename -> bytes
	certs    map[string]bool   // installed crypto cert names
	keys     map[string]bool   // installed crypto key names
	profiles map[string]Chain  // client-ssl profile -> bound chain
	calls    int
}

// New starts a fake BIG-IP requiring the given basic-auth credentials.
func New(user, pass string) *Server {
	s := &Server{
		user: user, pass: pass,
		uploads:  map[string][]byte{},
		certs:    map[string]bool{},
		keys:     map[string]bool{},
		profiles: map[string]Chain{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the management base URL of the fake appliance.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client trusting the fake appliance's TLS (it is plain
// HTTP here, so the default client also works; this mirrors real usage).
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Uploaded returns the bytes uploaded under filename.
func (s *Server) Uploaded(filename string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.uploads[filename]
	return v, ok
}

// Profile returns the chain bound to a Client SSL profile.
func (s *Server) Profile(name string) (Chain, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.profiles[name]
	return c, ok
}

// BindProfile sets what a Client SSL profile is bound to, without a deploy.
//
// It exists so a test can construct the state that matters for E2: an object
// installed on the device while the profile the VIP uses still points at the
// predecessor. Reaching that state through the deploy path would require
// simulating the misconfiguration that causes it, which is a property of the
// operator's BIG-IP rather than of this connector.
func (s *Server) BindProfile(profile, cert string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[profile] = Chain{Cert: cert, Key: cert}
}

// RemoveCert deletes an installed crypto cert object, so a test can model the
// case that matters most: the predecessor is gone and a rollback must refuse
// rather than report success.
func (s *Server) RemoveCert(name string) {
	s.mu.Lock()
	delete(s.certs, name)
	s.mu.Unlock()
}

// InstalledCert reports whether a crypto cert object of that name exists.
func (s *Server) InstalledCert(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certs[name]
}

// InstalledKey reports whether a crypto key object of that name exists.
func (s *Server) InstalledKey(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[name]
}

// Calls is the number of authenticated REST calls served.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != s.user || pass != s.pass {
		http.Error(w, `{"message":"authentication required"}`, http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)

	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/"):
		name := strings.TrimPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/")
		s.mu.Lock()
		s.uploads[name] = body
		s.mu.Unlock()
		s.ok(w, map[string]any{"remainingByteCount": 0})

	case r.Method == http.MethodPost && r.URL.Path == "/mgmt/tm/sys/crypto/cert":
		var cmd struct{ Name string }
		_ = json.Unmarshal(body, &cmd)
		s.mu.Lock()
		s.certs[cmd.Name] = true
		s.mu.Unlock()
		s.ok(w, map[string]any{"name": cmd.Name})

	case r.Method == http.MethodPost && r.URL.Path == "/mgmt/tm/sys/crypto/key":
		var cmd struct{ Name string }
		_ = json.Unmarshal(body, &cmd)
		s.mu.Lock()
		s.keys[cmd.Name] = true
		s.mu.Unlock()
		s.ok(w, map[string]any{"name": cmd.Name})

	// D4: reading a crypto object. Rollback checks the predecessor is present
	// before re-binding to it, and a double that answered 200 to everything
	// would let the "predecessor is gone" test pass for the wrong reason.
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/cert/"):
		name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/cert/")
		s.mu.Lock()
		exists := s.certs[name]
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{"name": name})

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/key/"):
		name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/key/")
		s.mu.Lock()
		exists := s.keys[name]
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{"name": name})

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/"):
		// E2: what the profile is ACTUALLY bound to, which is the question a
		// deploy's own return value cannot answer. A BIG-IP will happily hold a
		// freshly installed crypto object while the virtual server keeps
		// presenting the previous one.
		profile := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/")
		s.mu.Lock()
		chain, bound := s.profiles[profile]
		s.mu.Unlock()
		if !bound {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{
			"name": profile,
			"certKeyChain": []map[string]string{
				{"name": chain.Cert, "cert": chain.Cert, "key": chain.Key},
			},
		})

	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/"):
		profile := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/")
		var patch struct {
			CertKeyChain []struct {
				Cert string `json:"cert"`
				Key  string `json:"key"`
			} `json:"certKeyChain"`
		}
		if err := json.Unmarshal(body, &patch); err != nil || len(patch.CertKeyChain) == 0 {
			http.Error(w, `{"message":"malformed certKeyChain"}`, http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.profiles[profile] = Chain{Cert: patch.CertKeyChain[0].Cert, Key: patch.CertKeyChain[0].Key}
		s.mu.Unlock()
		s.ok(w, map[string]any{"name": profile})

	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func (s *Server) ok(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
