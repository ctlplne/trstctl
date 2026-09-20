// SPDX-License-Identifier: BUSL-1.1

// Package fortigatetest is a faithful in-process double of the FortiOS REST API
// local-certificate surface (`/api/v2/cmdb/vpn.certificate/local/{name}`), for
// testing the fortigate connector without a real FortiGate or FortiWeb.
//
// Faithful, not permissive: the double authenticates every request as the
// appliance does, serves exactly one method on exactly one path, and validates
// the submitted material before storing it. A double that answered 200 to
// anything would let a connector that sent the key to the wrong path, under the
// wrong name, or with an unusable body pass as proof the connector works.
//
// No crypto/* (AN-3): the PEM check is a structural encoding/pem decode, not a
// parse of the key. Material is held as []byte (AN-8), never as a string, and
// the request body is unmarshalled through secretjson so the private-key PEM
// never becomes an immutable Go string inside the double either.
package fortigatetest

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/secretjson"
)

// certPath is the only FortiOS endpoint this connector is allowed to touch.
const certPath = "/api/v2/cmdb/vpn.certificate/local/"

// LocalCert is the material held by a vpn.certificate/local object.
type LocalCert struct {
	Certificate []byte
	PrivateKey  []byte
}

// Call is a request the double refused as one the connector should never make.
// It carries no body: the point of recording it is to name the endpoint that was
// reached, and a refused request's body may hold key material.
type Call struct {
	Method string
	Path   string
}

// Server is a fake FortiOS REST endpoint.
type Server struct {
	srv   *httptest.Server
	token []byte

	mu       sync.Mutex
	certs    map[string]LocalCert
	puts     int
	bodies   [][]byte // every request body received, for leak assertions
	authSeen []string // every Authorization header received, for leak assertions
	targets  []string // every request-target received, for leak assertions
	refused  []Call

	failStatus int
	failBody   []byte
}

// New starts a fake FortiGate/FortiWeb that accepts the given FortiOS REST API
// token. The token is taken as []byte because that is how the connector custodies
// it (AN-8); the double compares against the same form rather than pinning a
// string copy of a credential into the test binary's read-only data.
func New(token []byte) *Server {
	s := &Server{
		token: append([]byte(nil), token...),
		certs: map[string]LocalCert{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the FortiOS management base URL of the fake appliance.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake appliance.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Stored returns the local-certificate object imported under name.
func (s *Server) Stored(name string) (LocalCert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[name]
	if !ok {
		return LocalCert{}, false
	}
	return LocalCert{
		Certificate: append([]byte(nil), c.Certificate...),
		PrivateKey:  append([]byte(nil), c.PrivateKey...),
	}, true
}

// Count is the number of distinct local-certificate objects on the appliance.
// A redeploy of the same credential must leave this at one: FortiOS addresses the
// object by name, so an accumulating count means deploys are not converging.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certs)
}

// Puts is the number of accepted imports.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// Bodies returns a copy of every request body the appliance received, so a test
// can prove the API token travelled only in the Authorization header.
func (s *Server) Bodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.bodies))
	for _, b := range s.bodies {
		out = append(out, append([]byte(nil), b...))
	}
	return out
}

// AuthHeaders returns every Authorization header value received.
func (s *Server) AuthHeaders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.authSeen...)
}

// RequestTargets returns every request-target (path and query) received.
//
// FortiOS accepts the API token as an `access_token` query parameter as well as a
// bearer header, and the query form is the one that lands in every proxy access
// log and appliance audit trail between here and the device. Recording the target
// lets a test assert directly that the connector never used it, rather than
// inferring it from a transport error that happens to embed the URL.
func (s *Server) RequestTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

// Refused returns the requests the appliance rejected as off-contract — a wrong
// path or a wrong method. A deploy that leaves this non-empty is reaching for
// FortiOS surface the connector's capability story does not cover, and the test
// should fail even though the deploy itself succeeded.
func (s *Server) Refused() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.refused...)
}

// SetFailure makes the next and all subsequent authenticated imports answer with
// status and body until it is cleared with a zero status.
//
// It exists to model the one appliance behaviour that matters for secret
// handling: FortiOS error bodies are assembled from the request that failed and
// can echo submitted fields back. A connector must not forward those bytes into
// an error an operator will paste into a ticket, and that property cannot be
// tested against a double that only ever succeeds.
func (s *Server) SetFailure(status int, body []byte) {
	s.mu.Lock()
	s.failStatus = status
	s.failBody = append([]byte(nil), body...)
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	s.mu.Lock()
	s.bodies = append(s.bodies, body)
	s.authSeen = append(s.authSeen, r.Header.Get("Authorization"))
	s.targets = append(s.targets, r.URL.RequestURI())
	s.mu.Unlock()

	// Authentication first, exactly as the appliance orders it: FortiOS does not
	// look at the body of a request it has not authenticated, so a double that
	// validated the payload first could report 400 for a call the real device
	// answers 401 and send a test chasing the wrong bug.
	//
	// Only the bearer header is accepted. FortiOS also takes the token as an
	// `access_token` query parameter, and this double deliberately does not:
	// a token in a URL lands in every proxy and appliance log between here and
	// there, so a connector that ever sent it that way must fail a test, not pass
	// one.
	if !s.authorized(r.Header.Get("Authorization")) {
		writeJSON(w, http.StatusUnauthorized, response{Status: "error", HTTPStatus: 401})
		return
	}

	if !strings.HasPrefix(r.URL.Path, certPath) {
		s.refuse(w, r, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPut {
		s.refuse(w, r, http.StatusMethodNotAllowed)
		return
	}
	// The CMDB addresses one object per request; a PUT at the collection URL has
	// no mkey to update. Accepting it would let a connector that forgot to append
	// the object name still look like it deployed something.
	name := strings.TrimPrefix(r.URL.Path, certPath)
	if name == "" || strings.Contains(name, "/") {
		s.refuse(w, r, http.StatusMethodNotAllowed)
		return
	}

	if status, failBody, failing := s.failure(); failing {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(failBody) // #nosec G705 -- test-support package compiled only into test binaries (CWE-79)
		return
	}

	var in struct {
		Name        string                 `json:"name"`
		Certificate secretjson.StringBytes `json:"certificate"`
		PrivateKey  secretjson.StringBytes `json:"private-key"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Status: "error", HTTPStatus: 400, Error: -8})
		return
	}
	// The mkey in the URL and the name in the body must agree. On a real FortiGate
	// a body naming a different object is a RENAME, not the in-place replace this
	// connector contracts on — so a disagreement here means the certificate would
	// land under a name nobody is watching, and the double refuses rather than
	// storing it somewhere the test would not think to look.
	if in.Name != name {
		writeJSON(w, http.StatusBadRequest, response{Status: "error", HTTPStatus: 400, Error: -8})
		return
	}
	// FortiOS refuses material it cannot load (error -651). Storing whatever
	// arrived would make the double agree that an empty or truncated payload was a
	// successful deploy, which is the exact failure an operator would discover
	// only when the listener stopped serving.
	if !isPEM(in.Certificate, "CERTIFICATE") || !isPEM(in.PrivateKey, "PRIVATE KEY") {
		writeJSON(w, http.StatusBadRequest, response{Status: "error", HTTPStatus: 400, Error: -651})
		return
	}

	s.mu.Lock()
	s.puts++
	s.certs[name] = LocalCert{
		Certificate: append([]byte(nil), in.Certificate...),
		PrivateKey:  append([]byte(nil), in.PrivateKey...),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, response{Status: "success", HTTPStatus: 200})
}

// response is the FortiOS REST envelope. Error carries the FortiOS numeric error
// code (-8 malformed request, -651 unusable certificate material).
type response struct {
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Error      int    `json:"error,omitempty"`
}

// authorized compares the presented Authorization header against the bearer form
// of the configured token.
func (s *Server) authorized(header string) bool {
	want := append([]byte("Bearer "), s.token...)
	return bytes.Equal([]byte(header), want)
}

// failure reports the injected failure response, if one is armed.
func (s *Server) failure() (status int, body []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failStatus == 0 {
		return 0, nil, false
	}
	return s.failStatus, append([]byte(nil), s.failBody...), true
}

// refuse records an off-contract request and answers it the way the appliance
// would. Recording is what turns "the deploy passed" into "the deploy passed and
// touched nothing else".
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int) {
	s.mu.Lock()
	s.refused = append(s.refused, Call{Method: r.Method, Path: r.URL.Path})
	s.mu.Unlock()
	writeJSON(w, status, response{Status: "error", HTTPStatus: status})
}

// isPEM reports whether material is a PEM block whose type ends in kind. The
// suffix match accepts the several private-key spellings (PRIVATE KEY, RSA
// PRIVATE KEY, EC PRIVATE KEY) a FortiGate also accepts.
func isPEM(material []byte, kind string) bool {
	block, _ := pem.Decode(material)
	return block != nil && strings.HasSuffix(block.Type, kind)
}

func writeJSON(w http.ResponseWriter, status int, body response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
