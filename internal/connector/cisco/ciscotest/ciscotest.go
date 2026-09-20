// SPDX-License-Identifier: BUSL-1.1

// Package ciscotest is a faithful in-process double of the Cisco ASA / Identity
// Services Engine (ISE ERS) management API's certificate-import endpoint, for
// testing the cisco connector without a real appliance. It is an httptest.Server
// that requires HTTP Basic authentication, accepts exactly the one call the
// connector is allowed to make, refuses everything else the way the device does,
// and records what was imported under which certificate name so a test can
// assert the renewed credential actually landed.
//
// It is deliberately strict. A double that answered 200 to anything would let
// every test pass while the connector spoke a protocol no device understands,
// and that is precisely the gap this package exists to close: cisco was
// advertised as relay-executable with nothing driving it end to end.
//
// No crypto/* (AN-3): the Basic credential is decoded with encoding/base64,
// which is not a cryptographic primitive. Credential and key material stays in
// []byte and is never materialized as a Go string (AN-8) — the request body is
// decoded through secretjson, the same seam the connector encodes it with.
package ciscotest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/secretjson"
)

// importPath is the endpoint the connector is allowed to call. It duplicates the
// connector's own constant on purpose rather than importing it: if the connector
// changes the path, that must fail a test instead of being silently mirrored
// here, because the whole value of this double is that it disagrees when the
// connector stops speaking the device's protocol.
const importPath = "/api/certificate/import"

// Credential is the material imported under a certificate name.
type Credential struct {
	Certificate []byte
	PrivateKey  []byte
}

// Refusal records a request the device rejected. Tests assert on it so a failed
// deploy is shown to have failed for the reason the device actually gave, rather
// than for some unrelated transport error that happens to also produce an error.
type Refusal struct {
	Method string
	Path   string
	Status int
	Reason string
}

// Server is a fake Cisco ASA / ISE certificate-import endpoint.
type Server struct {
	srv  *httptest.Server
	user string
	pass []byte // AN-8: the management password stays byte-backed here too

	mu         sync.Mutex
	imported   map[string]Credential
	order      []string
	calls      int
	refusals   []Refusal
	failStatus int
	failBody   []byte
}

// New starts a fake appliance that accepts the given Basic credentials.
//
// password is []byte rather than string so the double holds the credential the
// same way the connector does (AN-8); a test that had to hand over a string
// would be modelling custody the product does not use.
func New(user string, password []byte) *Server {
	s := &Server{
		user:     user,
		pass:     append([]byte(nil), password...),
		imported: map[string]Credential{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the management base URL of the fake appliance.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the credential imported under a certificate name.
func (s *Server) Imported(name string) (Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.imported[name]
	return c, ok
}

// ImportedNames lists the certificate names present on the device, in the order
// they were first imported.
//
// Order and count matter for idempotency: re-importing the same credential must
// converge on one object, not accumulate a second one under a slightly different
// name, and a test can only see the difference if the double reports both.
func (s *Server) ImportedNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}

// Calls is the total number of HTTP requests the device received, refused ones
// included. A connector that probed extra endpoints would show up here.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Refusals lists the requests the device rejected, oldest first.
func (s *Server) Refusals() []Refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Refusal(nil), s.refusals...)
}

// FailNext makes the next otherwise-valid import fail with status and body, and
// import nothing.
//
// Real devices refuse imports for reasons a connector cannot anticipate: the
// trustpoint name is in use, the key is refused by the device's FIPS mode, the
// ERS node is mid-sync. That failure path is where a credential leaks if it
// leaks at all, because the response body is the one part of the exchange the
// device controls and a naive handler formats it straight into the error. body
// is []byte so a test can make the device echo the private key back (AN-8) and
// prove the connector still does not put it in an error.
func (s *Server) FailNext(status int, body []byte) {
	s.mu.Lock()
	s.failStatus = status
	s.failBody = append([]byte(nil), body...)
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	// The device authenticates before it parses, so a caller with no credential
	// learns nothing about the request schema.
	if !s.authOK(r) {
		s.refuse(w, r, http.StatusUnauthorized, "authentication failed")
		return
	}
	if r.URL.Path != importPath {
		s.refuse(w, r, http.StatusNotFound, "no such resource")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.refuse(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !jsonContentType(r.Header.Get("Content-Type")) {
		s.refuse(w, r, http.StatusUnsupportedMediaType, "body must be application/json")
		return
	}

	if status, body, failing := s.takeFailure(); failing {
		s.record(Refusal{Method: r.Method, Path: r.URL.Path, Status: status, Reason: "injected device failure"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "unreadable body")
		return
	}
	var in importBody
	// Unknown fields are an error: a connector that added a second key-bearing
	// attribute, or renamed one and kept the old spelling alongside it, would
	// otherwise ship a body the device silently drops half of.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.refuse(w, r, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if in.Name == "" {
		s.refuse(w, r, http.StatusBadRequest, "name is required")
		return
	}
	// The device parses what it is given. Accepting arbitrary bytes as a
	// certificate would hide the failure that matters most here: a connector
	// that double-encoded the PEM, base64ed it, or truncated it would still be
	// recorded as a successful import and every assertion downstream would pass.
	if !looksPEM(in.Certificate) {
		s.refuse(w, r, http.StatusBadRequest, "certificate must be PEM")
		return
	}
	if !looksPEM(in.PrivateKey) {
		s.refuse(w, r, http.StatusBadRequest, "privateKey must be PEM")
		return
	}

	s.mu.Lock()
	if _, exists := s.imported[in.Name]; !exists {
		s.order = append(s.order, in.Name)
	}
	s.imported[in.Name] = Credential{
		Certificate: append([]byte(nil), in.Certificate...),
		PrivateKey:  append([]byte(nil), in.PrivateKey...),
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"name": in.Name, "status": "imported"})
}

// importBody mirrors the connector's importRequest on the wire. The PEM fields
// decode through secretjson.StringBytes so the double never materializes key
// material as a Go string (AN-8), which is the same reason the connector encodes
// them that way.
type importBody struct {
	Name        string                 `json:"name"`
	Certificate secretjson.StringBytes `json:"certificate"`
	PrivateKey  secretjson.StringBytes `json:"privateKey"`
}

// refuse answers with the device's error shape and records the refusal. The body
// never echoes the request or the credential — a double that leaked the password
// back would make the connector's redaction test pass for the wrong reason.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	s.record(Refusal{Method: r.Method, Path: r.URL.Path, Status: status, Reason: reason})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

func (s *Server) record(ref Refusal) {
	s.mu.Lock()
	s.refusals = append(s.refusals, ref)
	s.mu.Unlock()
}

func (s *Server) takeFailure() (status int, body []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failStatus == 0 {
		return 0, nil, false
	}
	status, body = s.failStatus, s.failBody
	s.failStatus, s.failBody = 0, nil
	return status, body, true
}

// authOK validates the Authorization header the connector emits, parsing it by
// hand rather than through http.Request.BasicAuth so the password is compared as
// bytes and never lands in a GC-managed string (AN-8).
func (s *Server) authOK(r *http.Request) bool {
	const prefix = "Basic "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return false
	}
	user, pass, found := bytes.Cut(raw, []byte(":"))
	return found && string(user) == s.user && bytes.Equal(pass, s.pass)
}

// jsonContentType accepts a charset parameter, which real clients and devices
// both attach; rejecting it would fail a connector that is behaving correctly.
func jsonContentType(header string) bool {
	media, _, _ := strings.Cut(header, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/json")
}

func looksPEM(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN"))
}
