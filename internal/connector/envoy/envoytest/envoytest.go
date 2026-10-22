// SPDX-License-Identifier: BUSL-1.1

// Package envoytest is a faithful in-process double of the SDS management
// surface the envoy connector speaks: one v3 Secret resource per name under
// /v1/sds/secrets/{name} (GET returns the stored resource, PUT replaces it) and
// one TLS posture document per listener under /v1/tls-posture/{target} (GET
// returns it, PUT replaces it). It is an httptest.Server, so the connector is
// driven through the same HTTP ops a real endpoint would see, and it records
// what the endpoint received rather than echoing the deploy back. Failure
// injection mirrors what a management plane can do: apply an update and then
// report failure, or apply a different posture than the one requested. No
// crypto/* (AN-3): PEM content is opaque bytes.
package envoytest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/connector"
)

// Secret is the material the double holds for one SDS resource name.
type Secret struct {
	Name        string
	Fingerprint string
	CertPEM     []byte
	KeyPEM      []byte
}

// Server is a fake SDS management endpoint.
type Server struct {
	srv *httptest.Server

	mu                  sync.Mutex
	secrets             map[string]sdsResource
	puts                int
	paths               []string
	failPutAfterApply   bool
	postures            map[string]connector.TLSPosture
	posturePuts         int
	mismatchNextPosture bool
}

// New starts a fake SDS management endpoint with no secrets and no postures.
func New() *Server {
	s := &Server{secrets: map[string]sdsResource{}, postures: map[string]connector.TLSPosture{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the management base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake endpoint.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Seed installs dep under name as the endpoint's current secret, encoded the
// way the connector would have pushed it.
func (s *Server) Seed(name string, dep connector.Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[name] = resourceFromDeployment(name, dep)
}

// Secret returns the material the endpoint currently holds under name.
func (s *Server) Secret(name string) (Secret, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.secrets[name]
	if !ok || len(res.Resources) == 0 {
		return Secret{}, false
	}
	r := res.Resources[0]
	return Secret{
		Name: r.Name, Fingerprint: r.Fingerprint,
		CertPEM: append([]byte(nil), r.TLSCertificate.CertificateChain.InlineBytes...),
		KeyPEM:  append([]byte(nil), r.TLSCertificate.PrivateKey.InlineBytes...),
	}, true
}

// Puts is the number of secret updates the endpoint received.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// Paths lists every request path seen, so a test can assert the connector
// spoke SDS and never the SPIFFE Workload API.
func (s *Server) Paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// FailNextPutAfterApply makes the next secret PUT store the resource and then
// report failure, the way an SDS plane that applied but was refused by Envoy
// does.
func (s *Server) FailNextPutAfterApply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPutAfterApply = true
}

// SetPosture installs the TLS posture the listener named target reports.
func (s *Server) SetPosture(target string, posture connector.TLSPosture) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postures[target] = clonePosture(posture)
}

// Posture returns the listener's current TLS posture.
func (s *Server) Posture(target string) connector.TLSPosture {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePosture(s.postures[target])
}

// PosturePuts is the number of posture mutations the endpoint received.
func (s *Server) PosturePuts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posturePuts
}

// MismatchNextPostureApply makes the next posture PUT apply a different cipher
// list than requested, so a connector that reads back must notice.
func (s *Server) MismatchNextPostureApply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mismatchNextPosture = true
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/sds/secrets/"):
		s.handleSecret(w, r, strings.TrimPrefix(r.URL.Path, "/v1/sds/secrets/"))
	case strings.HasPrefix(r.URL.Path, "/v1/tls-posture/"):
		s.handlePosture(w, r, strings.TrimPrefix(r.URL.Path, "/v1/tls-posture/"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "bad secret name", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		res, ok := s.secrets[name]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var res sdsResource
		if err := json.Unmarshal(body, &res); err != nil || len(res.Resources) != 1 || res.Resources[0].Name != name {
			http.Error(w, "body is not one v3 Secret resource for this name", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.secrets[name] = res
		s.puts++
		fail := s.failPutAfterApply
		s.failPutAfterApply = false
		s.mu.Unlock()
		if fail {
			http.Error(w, "applied but envoy rejected SDS ack", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request, target string) {
	if target == "" || strings.Contains(target, "/") {
		http.Error(w, "bad listener name", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		posture, ok := s.postures[target]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(posture)
	case http.MethodPut:
		var desired connector.TLSPosture
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&desired); err != nil {
			http.Error(w, "bad posture", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.posturePuts++
		if s.mismatchNextPosture {
			s.mismatchNextPosture = false
			desired.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"}
		}
		s.postures[target] = desired
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func clonePosture(p connector.TLSPosture) connector.TLSPosture {
	return connector.TLSPosture{
		MinimumVersion:    p.MinimumVersion,
		CipherSuites:      append([]string(nil), p.CipherSuites...),
		KeyExchangeGroups: append([]string(nil), p.KeyExchangeGroups...),
	}
}

// The v3 Secret wire shape the connector pushes. inline_bytes is base64 on the
// wire, which encoding/json gives a []byte for free.
func resourceFromDeployment(name string, dep connector.Deployment) sdsResource {
	return sdsResource{Resources: []sdsSecret{{
		Type:        "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		Name:        name,
		Fingerprint: dep.Fingerprint,
		TLSCertificate: tlsCertificate{
			CertificateChain: dataSource{InlineBytes: append([]byte(nil), dep.CertPEM...)},
			PrivateKey:       dataSource{InlineBytes: append([]byte(nil), dep.KeyPEM...)},
		},
	}}}
}

type sdsResource struct {
	Resources []sdsSecret `json:"resources"`
}

type sdsSecret struct {
	Type           string         `json:"@type"`
	Name           string         `json:"name"`
	Fingerprint    string         `json:"fingerprint"`
	TLSCertificate tlsCertificate `json:"tls_certificate"`
}

type tlsCertificate struct {
	CertificateChain dataSource `json:"certificate_chain"`
	PrivateKey       dataSource `json:"private_key"`
}

type dataSource struct {
	InlineBytes []byte `json:"inline_bytes"`
}
