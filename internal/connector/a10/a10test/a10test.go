// SPDX-License-Identifier: BUSL-1.1

// Package a10test is an in-process double of the A10 aXAPI endpoints used by
// the A10 deployment connector.
package a10test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	// A122: keys the A10 generated itself (key file -> key), the CSRs it made
	// with them, and how often a client read such a key file.
	deviceKeys     map[string]*crypto.LockedSigner
	csrs           map[string][]byte
	deviceKeyReads int
}

// New starts a fake A10 endpoint requiring the given credentials.
func New(user, pass string) *Server {
	s := &Server{
		user: user, pass: pass,
		tokens:   map[string]bool{},
		certs:    map[string][]byte{},
		keys:     map[string][]byte{},
		bindings: map[string]Binding{},

		deviceKeys: map[string]*crypto.LockedSigner{},
		csrs:       map[string][]byte{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the fake management base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() {
	s.srv.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, key := range s.deviceKeys {
		key.Destroy()
		delete(s.deviceKeys, name)
	}
}

// DeviceKey reports whether the A10 generated the key file name itself.
func (s *Server) DeviceKey(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.deviceKeys[name]
	return ok
}

// DeviceKeyReads counts reads of a key file the A10 generated. A client that
// keeps keys on the appliance never makes one.
func (s *Server) DeviceKeyReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceKeyReads
}

// RemoveCSR deletes a CSR file so a test can model an appliance key whose
// object is gone.
func (s *Server) RemoveCSR(name string) {
	s.mu.Lock()
	delete(s.csrs, name)
	s.mu.Unlock()
}

// HasFile reports whether an uploaded ssl-cert or ssl-key file of that name exists.
func (s *Server) HasFile(kind, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == "ssl-key" {
		_, ok := s.keys[name]
		return ok
	}
	_, ok := s.certs[name]
	return ok
}

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
	// A122: the A10 generates a key file and a CSR file.
	case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/pki/create":
		s.requireToken(w, r, func() { s.createKey(w, body) })
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/axapi/v3/file/csr/"):
		s.requireToken(w, r, func() {
			name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/axapi/v3/file/csr/"))
			s.mu.Lock()
			csr, ok := s.csrs[name]
			s.mu.Unlock()
			if !ok {
				http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
				return
			}
			s.ok(w, map[string]any{"csr": map[string]string{"file": name, "file-content": base64.StdEncoding.EncodeToString(csr)}})
		})
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
		if _, device := s.deviceKeys[name]; device && parts[0] == "ssl-key" {
			s.deviceKeyReads++
		}
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{"file": name})
	// A43: deleting an uploaded file. The aXAPI refuses while a client-ssl
	// template references it.
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/axapi/v3/file/"):
		s.requireToken(w, r, func() {
			rest := strings.TrimPrefix(r.URL.Path, "/axapi/v3/file/")
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) != 2 {
				http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
				return
			}
			name, _ := url.PathUnescape(parts[1])
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, b := range s.bindings {
				if b.CertFile == name || b.KeyFile == name {
					http.Error(w, `{"response":{"status":"fail","err":"file in use"}}`, http.StatusConflict)
					return
				}
			}
			files := s.certs
			if parts[0] == "ssl-key" {
				files = s.keys
			}
			if _, exists := files[name]; !exists {
				http.Error(w, `{"response":{"status":"fail"}}`, http.StatusNotFound)
				return
			}
			delete(files, name)
			s.ok(w, map[string]any{"file": name})
		})
	// E2: the certificate a client-SSL template names, the readback a relay
	// asks after a deploy.
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/axapi/v3/slb/template/client-ssl/"):
		s.requireToken(w, r, func() {
			name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/axapi/v3/slb/template/client-ssl/"))
			s.mu.Lock()
			b, ok := s.bindings[name]
			s.mu.Unlock()
			if !ok {
				http.Error(w, `{"response":{"status":"fail","err":"not found"}}`, http.StatusNotFound)
				return
			}
			s.ok(w, map[string]any{"client-ssl": map[string]string{"name": name, "cert": b.CertFile, "key": b.KeyFile}})
		})
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
	defer s.mu.Unlock()
	cert := append([]byte(nil), s.certs[in.ClientSSL.Cert]...)
	if deviceKey, device := s.deviceKeys[in.ClientSSL.Key]; device {
		// The A10 refuses a template whose certificate is not the key's.
		info, err := certinfo.Inspect(cert)
		if err != nil || info.SPKISHA256 != crypto.SHA256Hex(deviceKey.Public().DER) {
			http.Error(w, `{"response":{"status":"fail","err":"certificate and key do not match"}}`, http.StatusBadRequest)
			return
		}
	}
	key := append([]byte(nil), s.keys[in.ClientSSL.Key]...)
	s.bindings[template] = Binding{Certificate: cert, PrivateKey: key, CertFile: in.ClientSSL.Cert, KeyFile: in.ClientSSL.Key}
	s.ok(w, map[string]any{"response": map[string]string{"status": "OK"}})
}

// createKey generates a key file the A10 holds and a CSR file for it (A122).
// An existing key file is a conflict, as on the device.
func (s *Server) createKey(w http.ResponseWriter, body []byte) {
	var in struct {
		Create struct {
			KeyFile     string `json:"key-file"`
			CSRFile     string `json:"csr-file"`
			CSRGenerate int    `json:"csr-generate"`
			ECCurve     string `json:"ec-curve"`
			CommonName  string `json:"common-name"`
			SANs        []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"subject-alternate-name"`
		} `json:"create"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Create.KeyFile == "" || in.Create.CSRFile == "" ||
		in.Create.CSRGenerate != 1 || in.Create.ECCurve != "prime256v1" {
		http.Error(w, `{"response":{"status":"fail","err":"key-file, csr-file and a prime256v1 curve are required"}}`, http.StatusBadRequest)
		return
	}
	tmpl := crypto.CertificateRequestTemplate{CommonName: in.Create.CommonName}
	for _, san := range in.Create.SANs {
		switch san.Type {
		case "dns":
			tmpl.DNSNames = append(tmpl.DNSNames, san.Value)
		case "ip":
			ip := net.ParseIP(san.Value)
			if ip == nil {
				http.Error(w, `{"response":{"status":"fail","err":"invalid IP"}}`, http.StatusBadRequest)
				return
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		default:
			http.Error(w, `{"response":{"status":"fail","err":"unsupported subject alternate name"}}`, http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[in.Create.KeyFile]; exists {
		http.Error(w, `{"response":{"status":"fail","err":"file exists"}}`, http.StatusConflict)
		return
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		http.Error(w, `{"response":{"status":"fail","err":"key generation failed"}}`, http.StatusInternalServerError)
		return
	}
	csrDER, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		key.Destroy()
		http.Error(w, `{"response":{"status":"fail","err":"CSR could not be created"}}`, http.StatusBadRequest)
		return
	}
	s.keys[in.Create.KeyFile] = []byte("appliance-held ECDSA P-256 key")
	s.deviceKeys[in.Create.KeyFile] = key
	s.csrs[in.Create.CSRFile] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
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
