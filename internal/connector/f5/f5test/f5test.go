// SPDX-License-Identifier: BUSL-1.1

// Package f5test is a faithful in-process double of the F5 BIG-IP iControl REST
// API, for testing the f5 connector without a real appliance. It is an
// httptest.Server that accepts the upload, crypto-install, and Client SSL
// profile calls the connector makes, requires authentication, and records the
// resulting state so a test can assert the certificate was installed and bound.
package f5test

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	// A122: keys the BIG-IP generated itself (key object -> key) and the CSRs
	// it made with them (CSR object -> PEM). Only the CSR is ever readable.
	deviceKeys map[string]*crypto.LockedSigner
	csrs       map[string][]byte
}

// New starts a fake BIG-IP requiring the given basic-auth credentials.
func New(user, pass string) *Server {
	s := &Server{
		user: user, pass: pass,
		uploads:  map[string][]byte{},
		certs:    map[string]bool{},
		keys:     map[string]bool{},
		profiles: map[string]Chain{},

		deviceKeys: map[string]*crypto.LockedSigner{},
		csrs:       map[string][]byte{},
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
func (s *Server) Close() {
	s.srv.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, key := range s.deviceKeys {
		key.Destroy()
		delete(s.deviceKeys, name)
	}
}

// DeviceKey reports whether the BIG-IP generated the key object name itself.
func (s *Server) DeviceKey(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.deviceKeys[name]
	return ok
}

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
		var cmd struct {
			Name                   string              `json:"name"`
			KeyType                string              `json:"keyType"`
			CurveName              string              `json:"curveName"`
			CommonName             string              `json:"commonName"`
			SubjectAlternativeName string              `json:"subjectAlternativeName"`
			Options                []map[string]string `json:"options"`
		}
		_ = json.Unmarshal(body, &cmd)
		csrName := ""
		for _, option := range cmd.Options {
			if v, ok := option["gen-csr"]; ok {
				csrName = v
			}
		}
		if csrName != "" {
			s.generateKey(w, cmd.Name, csrName, cmd.KeyType, cmd.CurveName, cmd.CommonName, cmd.SubjectAlternativeName)
			return
		}
		s.mu.Lock()
		s.keys[cmd.Name] = true
		s.mu.Unlock()
		s.ok(w, map[string]any{"name": cmd.Name})

	// A122: the CSR the BIG-IP generated with a key.
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/csr/"):
		name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/csr/")
		s.mu.Lock()
		csr, exists := s.csrs[name]
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w, map[string]any{"name": name, "csrPem": string(csr)})

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

	// A43: deleting an installed crypto object by name. A BIG-IP refuses to
	// delete an object a profile still references; the double does the same so
	// a takedown that would pull the rug from under a virtual server is refused
	// rather than modeled as success.
	case r.Method == http.MethodDelete && (strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/cert/") || strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/key/")):
		isKey := strings.HasPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/key/")
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/cert/"), "/mgmt/tm/sys/crypto/key/")
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, chain := range s.profiles {
			if (!isKey && chain.Cert == name) || (isKey && chain.Key == name) {
				http.Error(w, `{"message":"object is in use by a profile"}`, http.StatusConflict)
				return
			}
		}
		objects := s.certs
		if isKey {
			objects = s.keys
		}
		if !objects[name] {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		delete(objects, name)
		delete(s.uploads, name)
		s.ok(w, map[string]any{"name": name})

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
		chain := Chain{Cert: patch.CertKeyChain[0].Cert, Key: patch.CertKeyChain[0].Key}
		s.mu.Lock()
		defer s.mu.Unlock()
		if key, device := s.deviceKeys[chain.Key]; device {
			// The BIG-IP refuses a chain whose certificate is not the key's.
			info, err := certinfo.Inspect(s.uploads[chain.Cert])
			if err != nil || info.SPKISHA256 != crypto.SHA256Hex(key.Public().DER) {
				http.Error(w, `{"message":"certificate and key do not match"}`, http.StatusBadRequest)
				return
			}
		}
		s.profiles[profile] = chain
		s.ok(w, map[string]any{"name": profile})

	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

// generateKey creates a key object the BIG-IP holds and a CSR for it (A122).
// An existing key object is a conflict, as on the device.
func (s *Server) generateKey(w http.ResponseWriter, keyName, csrName, keyType, curve, commonName, sans string) {
	if keyName == "" || keyType != "ec-private" || curve != "prime256v1" {
		http.Error(w, `{"message":"an ec-private prime256v1 key name is required"}`, http.StatusBadRequest)
		return
	}
	tmpl := crypto.CertificateRequestTemplate{CommonName: commonName}
	for _, entry := range strings.Split(sans, ",") {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "":
		case strings.HasPrefix(entry, "DNS:"):
			tmpl.DNSNames = append(tmpl.DNSNames, strings.TrimPrefix(entry, "DNS:"))
		case strings.HasPrefix(entry, "IP Address:"):
			ip := net.ParseIP(strings.TrimPrefix(entry, "IP Address:"))
			if ip == nil {
				http.Error(w, `{"message":"invalid IP address"}`, http.StatusBadRequest)
				return
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		default:
			http.Error(w, `{"message":"unsupported subject alternative name"}`, http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys[keyName] {
		http.Error(w, `{"message":"key already exists"}`, http.StatusConflict)
		return
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		http.Error(w, `{"message":"key generation failed"}`, http.StatusInternalServerError)
		return
	}
	csrDER, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		key.Destroy()
		http.Error(w, `{"message":"CSR could not be created"}`, http.StatusBadRequest)
		return
	}
	s.keys[keyName] = true
	s.deviceKeys[keyName] = key
	s.csrs[csrName] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	s.ok(w, map[string]any{"name": keyName})
}

func (s *Server) ok(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
