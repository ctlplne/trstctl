// SPDX-License-Identifier: BUSL-1.1

// Package netscalertest is a faithful in-process double of the Citrix ADC
// (NetScaler) NITRO REST API, for testing the netscaler connector without a real
// appliance. It models the session-token auth flow (login mints a token that
// later calls must present, logout invalidates it), the systemfile upload, and
// the sslcertkey rebind — recording the uploaded files and the certkey binding
// so a test can assert the renewed certificate landed and went live. No crypto/*
// (AN-3): file contents are base64 PEM, decoded as plain bytes.
package netscalertest

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

// Binding is the cert/key file pair an SSL certkey points at.
type Binding struct {
	Cert string
	Key  string
}

// Server is a fake NetScaler NITRO endpoint.
type Server struct {
	srv  *httptest.Server
	user string
	pass string

	mu       sync.Mutex
	tokens   map[string]bool   // valid session tokens
	files    map[string][]byte // filename -> decoded content
	bindings map[string]Binding
	logins   int
	logouts  int
	nextTok  int
}

// New starts a fake NetScaler that accepts the given NITRO credentials.
func New(user, pass string) *Server {
	s := &Server{
		user: user, pass: pass,
		tokens:   map[string]bool{},
		files:    map[string][]byte{},
		bindings: map[string]Binding{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the NSIP management base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// File returns the content uploaded under filename.
func (s *Server) File(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[name]
	return v, ok
}

// Binding returns the cert/key files an SSL certkey is bound to.
func (s *Server) Binding(certkey string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[certkey]
	return b, ok
}

// Logins and Logouts report how many sessions were opened and closed.
func (s *Server) Logins() int  { s.mu.Lock(); defer s.mu.Unlock(); return s.logins }
func (s *Server) Logouts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.logouts }

// OpenSessions is the number of still-valid session tokens.
func (s *Server) OpenSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// fileNameFromArgs pulls filename out of NITRO's args=filename:x,filelocation:y
// query form, which is not a normal query string.
func fileNameFromArgs(rawQuery string) string {
	q, err := url.PathUnescape(rawQuery)
	if err != nil {
		q = rawQuery
	}
	q = strings.TrimPrefix(q, "args=")
	for _, part := range strings.Split(q, ",") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(part), "filename:"); ok {
			return name
		}
	}
	return ""
}

// RemoveFile deletes an uploaded system file so a test can model the
// "predecessor is gone" case.
func (s *Server) RemoveFile(name string) {
	s.mu.Lock()
	delete(s.files, name)
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.URL.Path == "/nitro/v1/config/login" && r.Method == http.MethodPost:
		s.login(w, body)
	case r.URL.Path == "/nitro/v1/config/logout" && r.Method == http.MethodPost:
		s.requireSession(w, r, func() { s.logout(w, r) })
	case r.URL.Path == "/nitro/v1/config/systemfile" && r.Method == http.MethodPost:
		s.requireSession(w, r, func() { s.systemfile(w, body) })
	// D4: reading a system file. Rollback confirms the predecessor file is
	// present before re-pointing the certkey at it — a NITRO PUT naming a
	// missing file can be accepted and leave the certkey unusable, which takes
	// the listener down instead of restoring it.
	case r.URL.Path == "/nitro/v1/config/systemfile" && r.Method == http.MethodGet:
		name := fileNameFromArgs(r.URL.RawQuery)
		s.mu.Lock()
		_, exists := s.files[name]
		s.mu.Unlock()
		if !exists {
			http.Error(w, `{"message":"file not found"}`, http.StatusNotFound)
			return
		}
		s.ok(w)
	case r.URL.Path == "/nitro/v1/config/sslcertkey" && r.Method == http.MethodPut:
		s.requireSession(w, r, func() { s.sslcertkey(w, body) })
	default:
		s.fail(w, http.StatusNotFound, 258, "no such resource")
	}
}

func (s *Server) login(w http.ResponseWriter, body []byte) {
	var in struct {
		Login struct{ Username, Password string } `json:"login"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Login.Username != s.user || in.Login.Password != s.pass {
		s.fail(w, http.StatusUnauthorized, 354, "Invalid username or password")
		return
	}
	s.mu.Lock()
	s.nextTok++
	s.logins++
	tok := fmt.Sprintf("NSSESSION-%d", s.nextTok)
	s.tokens[tok] = true
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"errorcode": 0, "message": "Done", "sessionid": tok})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("NITRO_AUTH_TOKEN"); err == nil {
		s.mu.Lock()
		delete(s.tokens, c.Value)
		s.logouts++
		s.mu.Unlock()
	}
	s.ok(w)
}

func (s *Server) systemfile(w http.ResponseWriter, body []byte) {
	var in struct {
		Systemfile struct {
			Filename     string `json:"filename"`
			Filecontent  string `json:"filecontent"`
			Fileencoding string `json:"fileencoding"`
		} `json:"systemfile"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Systemfile.Filename == "" {
		s.fail(w, http.StatusBadRequest, 1096, "filename is required")
		return
	}
	content, err := base64.StdEncoding.DecodeString(in.Systemfile.Filecontent)
	if err != nil {
		s.fail(w, http.StatusBadRequest, 1096, "filecontent must be base64")
		return
	}
	s.mu.Lock()
	s.files[in.Systemfile.Filename] = content
	s.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"errorcode": 0, "message": "Done"})
}

func (s *Server) sslcertkey(w http.ResponseWriter, body []byte) {
	var in struct {
		Sslcertkey struct {
			Certkey string `json:"certkey"`
			Cert    string `json:"cert"`
			Key     string `json:"key"`
		} `json:"sslcertkey"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Sslcertkey.Certkey == "" || in.Sslcertkey.Cert == "" {
		s.fail(w, http.StatusBadRequest, 1096, "certkey and cert are required")
		return
	}
	s.mu.Lock()
	s.bindings[in.Sslcertkey.Certkey] = Binding{Cert: in.Sslcertkey.Cert, Key: in.Sslcertkey.Key}
	s.mu.Unlock()
	s.ok(w)
}

// requireSession runs next only if the request carries a valid session token.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, next func()) {
	c, err := r.Cookie("NITRO_AUTH_TOKEN")
	if err != nil {
		s.fail(w, http.StatusUnauthorized, 444, "session required")
		return
	}
	s.mu.Lock()
	ok := s.tokens[c.Value]
	s.mu.Unlock()
	if !ok {
		s.fail(w, http.StatusUnauthorized, 444, "invalid or expired session")
		return
	}
	next()
}

func (s *Server) ok(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"errorcode": 0, "message": "Done"})
}

func (s *Server) fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errorcode": code, "message": msg, "severity": "ERROR"})
}
