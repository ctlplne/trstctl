// SPDX-License-Identifier: MPL-2.0

// Package paloaltotest is a faithful in-process double of the PAN-OS XML API
// certificate-import surface, for testing the paloalto connector without a real
// firewall or Panorama. It is an httptest.Server that authenticates the API key,
// serves the two imports the connector makes (category=certificate, then
// category=private-key, under one certificate-name), and records the resulting
// certificate objects so a test can assert what landed and under what name.
//
// It is deliberately strict. A double that answered success to anything would
// let the connector pass while sending parameters no firewall accepts, which is
// the exact failure this emulator exists to rule out: paloalto was advertised as
// relay-executable with nothing driving it. So every parameter the real API
// validates is validated here, and the two PAN-OS failure shapes are both
// modelled — a transport-level rejection (403/400/404/405) and PAN-OS's
// signature failure-inside-a-200, where the HTTP layer accepts the request and
// the XML envelope carries status="error". The second shape is why the connector
// cannot trust a 2xx alone, so a double that never produced one would leave that
// logic unproven.
//
// No crypto/* (AN-3): PEM is matched as opaque bytes by its armour, never
// parsed. Imported material is held as []byte (AN-8), never as a string.
//
// Two known fidelity gaps bound what a passing test here proves. Both are
// recorded rather than guessed at, because a double that invents a requirement
// fails a working connector just as surely as a permissive one passes a broken
// one.
//
// Body encoding. PAN-OS's published import recipe posts the PEM as a
// multipart/form-data "file" part; the shipped connector posts the PEM as the
// raw request body. This double accepts the raw body, so it does NOT prove the
// connector's body encoding is one a firewall accepts. What it does prove is
// everything around the body: the endpoint, the method, the query parameters,
// the two-call ordering, authentication, and that a failure in either shape is
// surfaced rather than swallowed. Settling the encoding needs hardware; until
// then, treat the encoding as unverified and the rest as covered. Content-Type
// is likewise not checked, for the same reason — the raw-body shape has no
// documented Content-Type to check against.
//
// Passphrase. Real PAN-OS takes a passphrase parameter on a
// category=private-key import, used to encrypt the key at rest. The shipped
// connector sends none, so requiring one here would fail every deploy on an
// assumption this package cannot verify against a real device. The parameter is
// therefore recorded when present (see Import.Passphrase) and not required.
package paloaltotest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

// PAN-OS import categories. The certificate and the private key are two objects
// sharing one certificate-name, so category is what distinguishes the two calls
// the connector makes.
const (
	categoryCertificate = "certificate"
	categoryPrivateKey  = "private-key"
)

// maxImportBody bounds a single import read, so a runaway test cannot exhaust
// memory inside the double.
const maxImportBody = 1 << 20

// Object is a PAN-OS certificate object: a name, the certificate imported under
// it, and the private key attached to it.
type Object struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
}

// Import is one accepted import call, in the order it was served. The order
// matters on PAN-OS — a key attaches to a certificate object, so the
// certificate import must come first — and a test asserts on it.
type Import struct {
	Name     string
	Category string
	// Passphrase is the passphrase parameter if the caller sent one. Recorded,
	// not required; see the package comment.
	Passphrase string
}

// Server is a fake PAN-OS XML API endpoint.
type Server struct {
	srv    *httptest.Server
	apiKey []byte

	mu      sync.Mutex
	objects map[string]Object
	imports []Import
	queries [][]byte
	calls   int

	failStatus int
	failBody   []byte

	partFailCategory string
	partFailStatus   int
	partFailBody     []byte
}

// New starts a fake PAN-OS requiring apiKey in the X-PAN-KEY header. The key is
// []byte because that is how the connector holds it (AN-8); nothing here turns
// it into a string.
func New(apiKey []byte) *Server {
	s := &Server{
		apiKey:  append([]byte(nil), apiKey...),
		objects: map[string]Object{},
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

// Object returns the certificate object stored under name.
func (s *Server) Object(name string) (Object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[name]
	return o, ok
}

// Imports returns the accepted imports in the order they were served, so a test
// can assert the certificate was imported before the key it anchors.
func (s *Server) Imports() []Import {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Import(nil), s.imports...)
}

// Queries returns the raw query string of every request the server saw, in
// order, including ones it rejected.
//
// It exists for one assertion the device cannot make on the caller's behalf:
// PAN-OS accepts its API key as a key= query parameter, so a connector that put
// the key in the URL would work against real hardware while writing the key in
// clear into the firewall's own log, into every proxy between, and into request
// tracing. That is a leak this double must not paper over, but it is a policy
// the device does not enforce, so recording the query and letting a test assert
// on it is honest where answering 400 would not be.
func (s *Server) Queries() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.queries))
	for _, q := range s.queries {
		out = append(out, append([]byte(nil), q...))
	}
	return out
}

// ObjectCount is the number of distinct certificate objects. A redeploy of the
// same credential must leave it unchanged: PAN-OS import overwrites in place
// rather than accumulating.
func (s *Server) ObjectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

// Calls is the number of authenticated import requests accepted.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// InjectFailure makes every subsequent authenticated request answer with status
// and body until ClearFailure.
//
// It exists because the connector's redaction guarantee is only testable if the
// device can be made to return a hostile body: a test injects a failure whose
// body carries the API key and the private key, then asserts neither survives
// into the error. It never loosens the success path — an injected failure only
// ever turns an accepted request into a rejected one.
func (s *Server) InjectFailure(status int, body []byte) {
	s.mu.Lock()
	s.failStatus = status
	s.failBody = append([]byte(nil), body...)
	s.mu.Unlock()
}

// ClearFailure removes every injected failure, scoped or not. It clears both
// kinds because a caller that cleared one and silently kept the other would get
// a test passing or failing for a reason it never set up.
func (s *Server) ClearFailure() {
	s.mu.Lock()
	s.failStatus = 0
	s.failBody = nil
	s.partFailCategory = ""
	s.partFailStatus = 0
	s.partFailBody = nil
	s.mu.Unlock()
}

// InjectFailureFor fails only imports of the named category, letting the others
// through.
//
// Without it, every failure a test can provoke lands on the FIRST import — the
// certificate — so the connector returns before the private-key import is ever
// attempted, and the error wrap on that second call is dead code under test.
// That wrap is the one holding the private key in scope, so its redaction
// guarantee was the one thing the suite could not see. A mutant that formatted
// dep.KeyPEM into it survived the entire suite. Scoping the failure to
// category=private-key is what makes that path reachable.
//
// The certificate import still really happens first, so a test can also assert
// the honest partial state a half-finished deploy leaves on the firewall.
func (s *Server) InjectFailureFor(category string, status int, body []byte) {
	s.mu.Lock()
	s.partFailCategory = category
	s.partFailStatus = status
	s.partFailBody = append([]byte(nil), body...)
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// Recorded before the auth check, so a request that leaked the key in its URL
	// is caught even when the device went on to reject it.
	s.mu.Lock()
	s.queries = append(s.queries, []byte(r.URL.RawQuery))
	s.mu.Unlock()

	// PAN-OS answers an unauthenticated call at the transport level, before it
	// looks at anything else, and it does not echo the key back. Checked first so
	// a bad-credential test cannot pass for some other reason.
	if !s.authorized(r) {
		writeEnvelope(w, http.StatusForbidden,
			`<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`)
		return
	}
	if status, body, ok := s.injected(); ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	// The XML API is served at exactly one path, by POST for an import. Anything
	// else is a call the connector should never make, and answering it would hide
	// a connector that drifted onto a wrong endpoint.
	if r.URL.Path != "/api/" {
		writeEnvelope(w, http.StatusNotFound,
			`<response status="error" code="404"><result><msg>Not Found</msg></result></response>`)
		return
	}
	if r.Method != http.MethodPost {
		writeEnvelope(w, http.StatusMethodNotAllowed,
			`<response status="error" code="405"><result><msg>Method Not Allowed</msg></result></response>`)
		return
	}

	q := r.URL.Query()
	category := q.Get("category")
	name := q.Get("certificate-name")
	switch {
	case q.Get("type") != "import":
		writeEnvelope(w, http.StatusBadRequest,
			`<response status="error" code="400"><result><msg>Missing or invalid type</msg></result></response>`)
		return
	case q.Get("format") != "pem":
		// format is what tells PAN-OS how to read the body. Getting it wrong means
		// the body is interpreted as something else entirely, so it is not a
		// detail the double may wave through.
		writeEnvelope(w, http.StatusBadRequest,
			`<response status="error" code="400"><result><msg>Unsupported format</msg></result></response>`)
		return
	case category != categoryCertificate && category != categoryPrivateKey:
		writeEnvelope(w, http.StatusBadRequest,
			`<response status="error" code="400"><result><msg>Invalid category</msg></result></response>`)
		return
	case name == "":
		writeEnvelope(w, http.StatusBadRequest,
			`<response status="error" code="400"><result><msg>certificate-name is required</msg></result></response>`)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxImportBody))
	if err != nil || len(body) == 0 {
		writeEnvelope(w, http.StatusBadRequest,
			`<response status="error" code="400"><result><msg>Empty import body</msg></result></response>`)
		return
	}

	// From here the request was well-formed enough for PAN-OS to accept it and
	// then fail in the config engine — the 200-with-status="error" shape. These
	// must not become 4xx: a connector that only checked the status code would
	// pass, and that is precisely the bug this models.
	if !bytes.HasPrefix(body, []byte("-----BEGIN ")) {
		writeEnvelope(w, http.StatusOK,
			`<response status="error" code="400"><result><msg>Failed to parse PEM</msg></result></response>`)
		return
	}
	if !materialMatchesCategory(body, category) {
		writeEnvelope(w, http.StatusOK,
			`<response status="error" code="400"><result><msg>PEM does not match category</msg></result></response>`)
		return
	}

	// Checked here, on a request the device would otherwise have accepted, so the
	// failure models a config-engine rejection of that one part rather than a
	// malformed call.
	if status, body, ok := s.injectedFor(category); ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	s.mu.Lock()
	obj, exists := s.objects[name]
	// A private key attaches to a certificate object, so there has to be one to
	// attach it to. Modelled because it pins the connector's call ORDER: import
	// the certificate, then the key. A double indifferent to order would let a
	// connector that reversed them ship, and it would fail on first contact with
	// real hardware.
	if category == categoryPrivateKey && !exists {
		s.mu.Unlock()
		writeEnvelope(w, http.StatusOK,
			`<response status="error" code="400"><result><msg>certificate-name does not exist</msg></result></response>`)
		return
	}
	obj.Name = name
	if category == categoryCertificate {
		obj.CertPEM = append([]byte(nil), body...)
	} else {
		obj.KeyPEM = append([]byte(nil), body...)
	}
	s.objects[name] = obj
	s.imports = append(s.imports, Import{Name: name, Category: category, Passphrase: q.Get("passphrase")})
	s.calls++
	s.mu.Unlock()

	writeEnvelope(w, http.StatusOK,
		`<response status="success"><result>Successfully imported</result></response>`)
}

// authorized compares the presented key without turning it into a string.
func (s *Server) authorized(r *http.Request) bool {
	presented := []byte(r.Header.Get("X-PAN-KEY"))
	return len(presented) > 0 && bytes.Equal(presented, s.apiKey)
}

func (s *Server) injected() (int, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failStatus == 0 {
		return 0, nil, false
	}
	return s.failStatus, append([]byte(nil), s.failBody...), true
}

func (s *Server) injectedFor(category string) (int, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.partFailStatus == 0 || s.partFailCategory != category {
		return 0, nil, false
	}
	return s.partFailStatus, append([]byte(nil), s.partFailBody...), true
}

// materialMatchesCategory rejects a key imported as a certificate and vice
// versa, which PAN-OS also rejects. Matching the armour keeps this free of any
// certificate parse (AN-3).
func materialMatchesCategory(body []byte, category string) bool {
	if category == categoryCertificate {
		return bytes.Contains(body, []byte("CERTIFICATE"))
	}
	return bytes.Contains(body, []byte("PRIVATE KEY"))
}

func writeEnvelope(w http.ResponseWriter, status int, doc string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, doc)
}
