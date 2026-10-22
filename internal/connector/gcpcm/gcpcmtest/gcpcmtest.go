// SPDX-License-Identifier: BUSL-1.1

// Package gcpcmtest is a faithful in-process double of the GCP Certificate
// Manager REST surface the gcpcm connector uses, for testing without real GCP.
// It is an httptest.Server that requires a Google OAuth2 bearer token and
// models certificates.patch (in-place renewal), certificates.create and
// certificates.get (fingerprint-named deploys), and certificateMapEntries
// get/patch (the binding a deploy points at a certificate and a rollback points
// back). Like the real API, every mutation returns a long-running operation
// that is reported done only on a follow-up poll, so the connector's
// operation-polling is exercised. No crypto/* (AN-3): PEM content is treated
// as opaque bytes.
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

	mu      sync.Mutex
	certs   map[string]Imported // certificate id -> content
	entries map[string][]string // "map/entry" -> certificate resource names
	ops     map[string]bool     // operation name -> done
	patch   int
	create  int
	bind    int
	keys    int
	polls   int
	preview int
	nextOp  int
}

// New starts a fake Certificate Manager that accepts requests bearing
// expectedToken.
func New(expectedToken string) *Server {
	s := &Server{token: expectedToken, certs: map[string]Imported{}, entries: map[string][]string{}, ops: map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the API base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake API.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the certificate content stored under id, whether it arrived
// by an in-place patch or a fingerprint-named create.
func (s *Server) Imported(id string) (Imported, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.certs[id]
	return v, ok
}

// MapEntry returns the certificate resource names a certificate map entry
// ("map/entry") currently points at.
func (s *Server) MapEntry(entry string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.entries[entry]...)
}

// Polls is the number of operation poll requests served.
func (s *Server) Polls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls
}

// PreviewCalls is the number of authenticated read-only certificate lists.
func (s *Server) PreviewCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preview
}

// PatchCalls is the number of in-place certificate patch calls.
func (s *Server) PatchCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.patch
}

// CreateCalls is the number of certificates.create calls, including ones
// refused because the id already existed.
func (s *Server) CreateCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.create
}

// BindCalls is the number of certificate map entry patches.
func (s *Server) BindCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bind
}

// UploadedKeys is the number of requests that carried a private key.
func (s *Server) UploadedKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusUnauthorized, "UNAUTHENTICATED", "bearer token missing or invalid")
		return
	}
	path := strings.Trim(r.URL.Path, "/")

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/certificates"):
		if _, _, ok := parseCollectionPath(path); !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate collection path")
			return
		}
		s.mu.Lock()
		s.preview++
		s.mu.Unlock()
		s.writeJSON(w, map[string]any{"certificates": []any{}})

	case r.Method == http.MethodGet && strings.Contains(path, "/operations/"):
		name := strings.TrimPrefix(path, "v1/")
		s.mu.Lock()
		s.polls++
		s.ops[name] = true // the operation completes by the time it is polled
		s.mu.Unlock()
		s.writeJSON(w, operation{Name: name, Done: true})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/certificates"):
		project, location, ok := parseCollectionPath(path)
		if !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate collection path")
			return
		}
		id := r.URL.Query().Get("certificateId")
		in, ok := s.readSelfManaged(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		s.create++
		if !validID(id) {
			s.mu.Unlock()
			s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "certificateId must match [a-z]([-a-z0-9]*[a-z0-9])? and be at most 63 characters")
			return
		}
		if _, exists := s.certs[id]; exists {
			s.mu.Unlock()
			s.fail(w, http.StatusConflict, "ALREADY_EXISTS", "certificate already exists")
			return
		}
		s.certs[id] = in
		opName := s.newOp(project, location)
		s.mu.Unlock()
		s.writeJSON(w, operation{Name: opName, Done: false})

	case r.Method == http.MethodGet && strings.Contains(path, "/certificates/"):
		id, _, _, ok := parseCertPath(path)
		if !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate resource path")
			return
		}
		s.mu.Lock()
		_, exists := s.certs[id]
		s.mu.Unlock()
		if !exists {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "certificate not found")
			return
		}
		s.writeJSON(w, map[string]any{"name": strings.TrimPrefix(path, "v1/")})

	case r.Method == http.MethodPatch && strings.Contains(path, "/certificates/"):
		if !strings.Contains(r.URL.Query().Get("updateMask"), "self_managed") {
			s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "updateMask must include self_managed")
			return
		}
		id, project, location, ok := parseCertPath(path)
		if !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate resource path")
			return
		}
		in, ok := s.readSelfManaged(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		s.patch++
		s.certs[id] = in
		opName := s.newOp(project, location)
		s.mu.Unlock()
		s.writeJSON(w, operation{Name: opName, Done: false})

	case strings.Contains(path, "/certificateMapEntries/"):
		key, project, location, ok := parseEntryPath(path)
		if !ok {
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "malformed certificate map entry path")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			bound := append([]string(nil), s.entries[key]...)
			s.mu.Unlock()
			s.writeJSON(w, map[string]any{"name": strings.TrimPrefix(path, "v1/"), "certificates": bound})
		case http.MethodPatch:
			if !strings.Contains(r.URL.Query().Get("updateMask"), "certificates") {
				s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "updateMask must include certificates")
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var in struct {
				Certificates []string `json:"certificates"`
			}
			if err := json.Unmarshal(body, &in); err != nil || len(in.Certificates) == 0 {
				s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "certificates is required")
				return
			}
			s.mu.Lock()
			s.bind++
			for _, resource := range in.Certificates {
				id := resource[strings.LastIndex(resource, "/")+1:]
				if _, exists := s.certs[id]; !exists || !strings.HasPrefix(resource, "projects/"+project+"/locations/"+location+"/certificates/") {
					s.mu.Unlock()
					s.fail(w, http.StatusBadRequest, "FAILED_PRECONDITION", "certificate "+resource+" does not exist in this project and location")
					return
				}
			}
			s.entries[key] = append([]string(nil), in.Certificates...)
			opName := s.newOp(project, location)
			s.mu.Unlock()
			s.writeJSON(w, operation{Name: opName, Done: false})
		default:
			s.fail(w, http.StatusNotFound, "NOT_FOUND", "no such operation")
		}

	default:
		s.fail(w, http.StatusNotFound, "NOT_FOUND", "no such operation")
	}
}

// readSelfManaged decodes a Certificate body carrying selfManaged PEM fields.
func (s *Server) readSelfManaged(w http.ResponseWriter, r *http.Request) (Imported, bool) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var in struct {
		SelfManaged struct {
			PEMCertificateValue string `json:"pemCertificate"`
			PEMPrivateKeyValue  string `json:"pemPrivateKey"`
		} `json:"selfManaged"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.SelfManaged.PEMCertificateValue == "" || in.SelfManaged.PEMPrivateKeyValue == "" {
		s.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "selfManaged.pemCertificate and pemPrivateKey are required")
		return Imported{}, false
	}
	s.mu.Lock()
	s.keys++
	s.mu.Unlock()
	return Imported{
		PEMCertificate: []byte(in.SelfManaged.PEMCertificateValue),
		PEMPrivateKey:  []byte(in.SelfManaged.PEMPrivateKeyValue),
	}, true
}

// newOp registers a not-yet-done operation; the caller holds s.mu.
func (s *Server) newOp(project, location string) string {
	s.nextOp++
	opName := fmt.Sprintf("projects/%s/locations/%s/operations/op-%d", project, location, s.nextOp)
	s.ops[opName] = false
	return opName
}

func validID(id string) bool {
	if id == "" || len(id) > 63 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		case r == '-':
			if i == 0 || i == len(id)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func parseCollectionPath(path string) (project, location string, ok bool) {
	p := strings.Split(path, "/")
	if len(p) != 6 || p[0] != "v1" || p[1] != "projects" || p[3] != "locations" || p[5] != "certificates" {
		return "", "", false
	}
	return p[2], p[4], true
}

type operation struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}

// parseCertPath pulls id, project, and location from
// v1/projects/{project}/locations/{location}/certificates/{id}.
func parseCertPath(path string) (id, project, location string, ok bool) {
	p := strings.Split(path, "/")
	// [v1 projects {p} locations {l} certificates {id}]
	if len(p) != 7 || p[0] != "v1" || p[1] != "projects" || p[3] != "locations" || p[5] != "certificates" {
		return "", "", "", false
	}
	return p[6], p[2], p[4], true
}

// parseEntryPath pulls "map/entry", project, and location from
// v1/projects/{p}/locations/{l}/certificateMaps/{map}/certificateMapEntries/{entry}.
func parseEntryPath(path string) (key, project, location string, ok bool) {
	p := strings.Split(path, "/")
	if len(p) != 9 || p[0] != "v1" || p[1] != "projects" || p[3] != "locations" || p[5] != "certificateMaps" || p[7] != "certificateMapEntries" {
		return "", "", "", false
	}
	return p[6] + "/" + p[8], p[2], p[4], true
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
