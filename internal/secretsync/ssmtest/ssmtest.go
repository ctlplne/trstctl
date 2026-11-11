// SPDX-License-Identifier: BUSL-1.1

// Package ssmtest is a stand-in for the AWS Systems Manager Parameter Store
// JSON API, built from its public API reference: PutParameter, GetParameter,
// GetParametersByPath and DeleteParameter over POST / with X-Amz-Target
// AmazonSSM.<Action>, each request signed with SigV4 for the ssm service. It
// keeps parameters in memory, so a test can change one outside the sync (drift)
// and read back what a sync wrote. A SecureString read without decryption
// returns a marker, never the value, as the service returns ciphertext.
package ssmtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// EncryptedMarker is what a SecureString reads as without WithDecryption.
const EncryptedMarker = "AQICAHstand-in-kms-ciphertext"

type parameter struct {
	value   string
	typ     string
	version int
}

// Server is the stand-in. Close it when the test ends.
type Server struct {
	*httptest.Server
	mu       sync.Mutex
	params   map[string]parameter
	calls    []string
	pageSize int
}

// New starts a stand-in on loopback.
func New() *Server {
	s := &Server{params: map[string]parameter{}, pageSize: 10}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Set writes a SecureString parameter outside any sync, as an operator or
// another tool would.
func (s *Server) Set(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.params[name]
	s.params[name] = parameter{value: value, typ: "SecureString", version: p.version + 1}
}

// Value returns a parameter's value and whether it exists.
func (s *Server) Value(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	return p.value, ok
}

// Version returns a parameter's version, 0 when it does not exist.
func (s *Server) Version(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.params[name].version
}

// Calls returns the actions received, in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// SetPageSize sets how many parameters one GetParametersByPath page holds.
func (s *Server) SetPageSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pageSize = n
}

func (s *Server) fail(w http.ResponseWriter, kind string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": kind, "message": kind})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "/ssm/aws4_request") || r.Header.Get("X-Amz-Date") == "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"__type": "UnrecognizedClientException"})
		return
	}
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSSM.")
	var in struct {
		Name           string
		Value          string
		Type           string
		Overwrite      bool
		WithDecryption bool
		Path           string
		Recursive      bool
		MaxResults     int
		NextToken      string
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.fail(w, "ValidationException")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, action)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	view := func(name string, p parameter, decrypt bool) map[string]any {
		value := p.value
		if p.typ == "SecureString" && !decrypt {
			value = EncryptedMarker
		}
		return map[string]any{"Name": name, "Type": p.typ, "Value": value, "Version": p.version}
	}
	switch action {
	case "PutParameter":
		if !strings.HasPrefix(in.Name, "/") || in.Value == "" {
			s.fail(w, "ValidationException")
			return
		}
		p, exists := s.params[in.Name]
		if exists && !in.Overwrite {
			s.fail(w, "ParameterAlreadyExists")
			return
		}
		typ := in.Type
		if typ == "" {
			typ = p.typ
		}
		s.params[in.Name] = parameter{value: in.Value, typ: typ, version: p.version + 1}
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": p.version + 1, "Tier": "Standard"})
	case "GetParameter":
		p, ok := s.params[in.Name]
		if !ok {
			s.fail(w, "ParameterNotFound")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Parameter": view(in.Name, p, in.WithDecryption)})
	case "GetParametersByPath":
		if !strings.HasPrefix(in.Path, "/") || (in.Path != "/" && strings.HasSuffix(in.Path, "/")) {
			s.fail(w, "ValidationException")
			return
		}
		if in.MaxResults > 10 {
			s.fail(w, "ValidationException")
			return
		}
		base := strings.TrimSuffix(in.Path, "/") + "/"
		var names []string
		for name := range s.params {
			rest, under := strings.CutPrefix(name, base)
			if !under || rest == "" || (!in.Recursive && strings.Contains(rest, "/")) {
				continue
			}
			names = append(names, name)
		}
		slices.Sort(names)
		start := 0
		if in.NextToken != "" {
			n, err := strconv.Atoi(strings.TrimPrefix(in.NextToken, "page-"))
			if err != nil || n < 0 || n > len(names) {
				s.fail(w, "InvalidNextToken")
				return
			}
			start = n
		}
		size := s.pageSize
		if in.MaxResults > 0 && in.MaxResults < size {
			size = in.MaxResults
		}
		end := min(start+size, len(names))
		page := make([]map[string]any, 0, end-start)
		for _, name := range names[start:end] {
			page = append(page, view(name, s.params[name], in.WithDecryption))
		}
		out := map[string]any{"Parameters": page}
		if end < len(names) {
			out["NextToken"] = "page-" + strconv.Itoa(end)
		}
		_ = json.NewEncoder(w).Encode(out)
	case "DeleteParameter":
		if _, ok := s.params[in.Name]; !ok {
			s.fail(w, "ParameterNotFound")
			return
		}
		delete(s.params, in.Name)
		_, _ = w.Write([]byte("{}"))
	default:
		s.fail(w, "InvalidAction")
	}
}
