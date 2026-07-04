// SPDX-License-Identifier: MPL-2.0

// Package gcpcmtest is a faithful in-process double of the GCP Certificate
// Manager certificates.patch API, for testing the gcpcm connector without real
// GCP. It is an httptest.Server that requires a Google OAuth2 bearer token,
// accepts PATCH of a self-managed certificate, and — like the real API — returns
// a long-running operation that is reported done only on a follow-up poll, so
// the connector's operation-polling is exercised. It records the updated
// certificate by id. No crypto/* (AN-3): PEM content is treated as opaque bytes.
package gcpcmtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Imported is the self-managed certificate the fake received.
type Imported struct {
	PEMCertificate []byte
	PEMPrivateKey  []byte
}

// Server is a fake Certificate Manager endpoint.
type Server struct {
	srv   *httptest.Server
	token string

	mu     sync.Mutex
	certs  map[string]Imported // certificate id -> content
	ops    map[string]bool     // operation name -> done
	patch  int
	polls  int
	nextOp int
}

// New starts a fake Certificate Manager that accepts requests bearing
// expectedToken.
func New(expectedToken string) *Server {
	s := &Server{token: expectedToken, certs: map[string]Imported{}, ops: map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the API base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake API.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the certificate content updated under id.
func (s *Server) Imported(id string) (Imported, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.certs[id]
	return v, ok
}

// Polls is the number of operation poll requests served.
func (s *Server) Polls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusUnauthorized, "UNAUTHENTICATED", "bearer token missing or invalid")
		return
	}

	switch {
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/operations/"):
		name := strings.TrimPrefix(r.URL.Path, "/v1/")
		s.mu.Lock()
		s.polls++
		s.ops[name] = true // the operation completes by the time it is polled
		s.mu.Unlock()
		s.writeJSON(w, operation{Name: name, Done: true})

	case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/certificates/"):
		if !strings.Contains(r.URL.Query().Get("updateMask"), "self_managed") {
			s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "updateMask must include self_managed")
			return
		}
		id, project, location, ok := parseCertPath(r.URL.Path)
		if !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate resource path")
			return
		}
		body, _ := io.ReadAll(r.Body)
		var in struct {
			SelfManaged struct {
				PEMCertificateValue string `json:"pemCertificate"`
				PEMPrivateKeyValue  string `json:"pemPrivateKey"`
			} `json:"selfManaged"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.SelfManaged.PEMCertificateValue == "" || in.SelfManaged.PEMPrivateKeyValue == "" {
			s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "selfManaged.pemCertificate and pemPrivateKey are required")
			return
		}

		s.mu.Lock()
		s.patch++
		s.nextOp++
		opName := fmt.Sprintf("projects/%s/locations/%s/operations/op-%d", project, location, s.nextOp)
		s.ops[opName] = false
		s.certs[id] = Imported{
			PEMCertificate: []byte(in.SelfManaged.PEMCertificateValue),
			PEMPrivateKey:  []byte(in.SelfManaged.PEMPrivateKeyValue),
		}
		s.mu.Unlock()
		s.writeJSON(w, operation{Name: opName, Done: false})

	default:
		s.fail(w, http.StatusNotFound, "NOT_FOUND", "no such operation")
	}
}

type operation struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}

// parseCertPath pulls id, project, and location from
// /v1/projects/{project}/locations/{location}/certificates/{id}.
func parseCertPath(path string) (id, project, location string, ok bool) {
	p := strings.Split(strings.Trim(path, "/"), "/")
	// [v1 projects {p} locations {l} certificates {id}]
	if len(p) != 7 || p[0] != "v1" || p[1] != "projects" || p[3] != "locations" || p[5] != "certificates" {
		return "", "", "", false
	}
	return p[6], p[2], p[4], true
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"status": code, "message": msg}})
}
