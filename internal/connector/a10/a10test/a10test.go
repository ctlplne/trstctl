// SPDX-License-Identifier: BUSL-1.1

// Package a10test is an in-process double of the A10 aXAPI endpoints used by
// the A10 deployment connector.
package a10test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
)

// Binding is the certificate/key material bound to a client-SSL template.
type Binding struct {
	Certificate []byte
	PrivateKey  []byte
	CertFile    string
	KeyFile     string
}

// Server is a fake A10 aXAPI management endpoint.
type Server struct {
	srv  *httptest.Server
	user string
	pass string

	mu       sync.Mutex
	nextTok  int
	tokens   map[string]bool
	certs    map[string][]byte
	keys     map[string][]byte
	bindings map[string]Binding
}

// New starts a fake A10 endpoint requiring the given credentials.
func New(user, pass string) *Server {
	s := &Server{
		user: user, pass: pass,
		tokens:   map[string]bool{},
		certs:    map[string][]byte{},
		keys:     map[string][]byte{},
		bindings: map[string]Binding{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the fake management base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Binding returns the credential bound to template.
func (s *Server) Binding(template string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[template]
	return b, ok
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/auth":
		s.login(w, body)
	case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-cert":
		s.requireToken(w, r, func() { s.upload(w, body, "ssl-cert") })
	case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-key":
		s.requireToken(w, r, func() { s.upload(w, body, "ssl-key") })
	// D4: reading an uploaded file, so a rollback can tell "the predecessor is
	// gone" from "the appliance did not answer".
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/axapi/v3/file/"):
		rest := strings.TrimPrefix(r.URL.Path, "/axapi/v3/file/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
			return
		}
		name, _ := url.PathUnescape(parts[1])
		s.mu.Lock()
		_, isCert := s.certs[name]
		_, isKey := s.keys[name]
		exists := isCert || isKey
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{"file": name})
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/axapi/v3/slb/template/client-ssl/"):
		s.requireToken(w, r, func() { s.bind(w, body, strings.TrimPrefix(r.URL.Path, "/axapi/v3/slb/template/client-ssl/")) })
	default:
		http.Error(w, `{"response":{"status":"fail","err":"not found"}}`, http.StatusNotFound)
	}
}

func (s *Server) login(w http.ResponseWriter, body []byte) {
	var in struct {
		Credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Credentials.Username != s.user || in.Credentials.Password != s.pass {
		http.Error(w, `{"response":{"status":"fail","err":"auth"}}`, http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	s.nextTok++
	tok := fmt.Sprintf("A10TOKEN-%d", s.nextTok)
	s.tokens[tok] = true
	s.mu.Unlock()
	s.ok(w, map[string]any{"authresponse": map[string]string{"signature": tok}})
}

func (s *Server) upload(w http.ResponseWriter, body []byte, kind string) {
	var in map[string]struct {
		File        string `json:"file"`
		FileContent string `json:"file-content"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, `{"response":{"status":"fail","err":"bad upload"}}`, http.StatusBadRequest)
		return
	}
	item := in[kind]
	content, err := base64.StdEncoding.DecodeString(item.FileContent)
	if err != nil || item.File == "" {
		http.Error(w, `{"response":{"status":"fail","err":"bad file"}}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if kind == "ssl-cert" {
		s.certs[item.File] = content
	} else {
		s.keys[item.File] = content
	}
	s.mu.Unlock()
	s.ok(w, map[string]any{"response": map[string]string{"status": "OK"}})
}

func (s *Server) bind(w http.ResponseWriter, body []byte, template string) {
	var in struct {
		ClientSSL struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		} `json:"client-ssl"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.ClientSSL.Cert == "" || in.ClientSSL.Key == "" {
		http.Error(w, `{"response":{"status":"fail","err":"bad bind"}}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cert := append([]byte(nil), s.certs[in.ClientSSL.Cert]...)
	key := append([]byte(nil), s.keys[in.ClientSSL.Key]...)
	s.bindings[template] = Binding{Certificate: cert, PrivateKey: key, CertFile: in.ClientSSL.Cert, KeyFile: in.ClientSSL.Key}
	s.mu.Unlock()
	s.ok(w, map[string]any{"response": map[string]string{"status": "OK"}})
}

func (s *Server) requireToken(w http.ResponseWriter, r *http.Request, next func()) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "A10 ")
	s.mu.Lock()
	ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"response":{"status":"fail","err":"token"}}`, http.StatusUnauthorized)
		return
	}
	next()
}

// RemoveCert deletes an uploaded certificate file so a test can model the
// "predecessor is gone" case a rollback must refuse.
func (s *Server) RemoveCert(name string) {
	s.mu.Lock()
	delete(s.certs, name)
	s.mu.Unlock()
}

func (s *Server) ok(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
