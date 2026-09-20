// SPDX-License-Identifier: BUSL-1.1

// Package kemptest is an in-process double of the Kemp LoadMaster management
// endpoints used by the Kemp deployment connector.
package kemptest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Binding is the certificate/key material bound to a virtual service.
type Binding struct {
	Certificate []byte
	PrivateKey  []byte
	CertName    string
}

// Server is a fake Kemp LoadMaster API endpoint.
type Server struct {
	srv   *httptest.Server
	token string

	mu       sync.Mutex
	certs    map[string]Binding
	bindings map[string]Binding
}

// New starts a fake LoadMaster endpoint requiring token.
func New(token string) *Server {
	s := &Server{token: token, certs: map[string]Binding{}, bindings: map[string]Binding{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the fake management base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Binding returns the credential bound to virtualService.
func (s *Server) Binding(virtualService string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[virtualService]
	return b, ok
}

// ObjectCounts reports the number of named certificate and virtual-service
// objects. Replaying a target-derived PUT/PATCH must keep both counts stable.
func (s *Server) ObjectCounts() (certificates, bindings int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certs), len(s.bindings)
}

// RemoveCert deletes an uploaded certificate object so a test can model the
// "predecessor is gone" case a rollback must refuse.
func (s *Server) RemoveCert(name string) {
	s.mu.Lock()
	delete(s.certs, name)
	s.mu.Unlock()
}

// BoundCertName reports which certificate a virtual service is bound to.
func (s *Server) BoundCertName(virtualService string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[virtualService]
	return b.CertName, ok
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/access/certificates/"):
		s.upload(w, body, strings.TrimPrefix(r.URL.Path, "/access/certificates/"))
	// D4: reading a certificate object. Rollback confirms the predecessor is
	// present before re-binding, so the double must be able to say it is not.
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/access/certificates/"):
		name := strings.TrimPrefix(r.URL.Path, "/access/certificates/")
		s.mu.Lock()
		_, exists := s.certs[name]
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/access/virtual-services/") && strings.HasSuffix(r.URL.Path, "/certificate"):
		vs := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/access/virtual-services/"), "/certificate")
		s.bind(w, body, vs)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (s *Server) upload(w http.ResponseWriter, body []byte, certName string) {
	var in struct {
		Certificate []byte `json:"certificate_pem"`
		PrivateKey  []byte `json:"private_key_pem"`
	}
	if err := json.Unmarshal(body, &in); err != nil || len(in.Certificate) == 0 || len(in.PrivateKey) == 0 {
		http.Error(w, `{"error":"bad certificate"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.certs[certName] = Binding{Certificate: append([]byte(nil), in.Certificate...), PrivateKey: append([]byte(nil), in.PrivateKey...), CertName: certName}
	s.mu.Unlock()
	s.ok(w)
}

func (s *Server) bind(w http.ResponseWriter, body []byte, virtualService string) {
	var in struct {
		CertName string `json:"cert_name"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.CertName == "" {
		http.Error(w, `{"error":"bad binding"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cert, ok := s.certs[in.CertName]
	if ok {
		s.bindings[virtualService] = cert
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"missing certificate"}`, http.StatusNotFound)
		return
	}
	s.ok(w)
}

func (s *Server) ok(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
