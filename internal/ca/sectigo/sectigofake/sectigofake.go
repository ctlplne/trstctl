// Package sectigofake is a faithful in-process test double of the Sectigo
// Certificate Manager (SCM) SSL REST API, enough to exercise the Sectigo CA
// plugin end-to-end without the real service. It mirrors the documented
// contract: the login/password/customerUri auth headers, POST /api/ssl/v1/enroll
// returning {sslId, renewId}, and GET /api/ssl/v1/collect/{sslId}/{format}
// returning the raw PEM chain once issued — or, while the order is still being
// processed, an error envelope {code:-183,...}. It signs submitted CSRs with a
// local software authority via the crypto boundary, so it holds no crypto/*.
package sectigofake

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// Credentials this double accepts in the login/password/customerUri headers.
const (
	login       = "scm-user"
	password    = "scm-pass"
	customerURI = "trstctl"

	// codeBeingProcessed is SCM's application code for "order still processing".
	codeBeingProcessed = -183
)

// Server is a running fake SCM SSL API.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority

	mu           sync.Mutex
	certs        map[int][]byte // sslId -> chain PEM
	collectCount map[int]int    // sslId -> times collect has been called
	pendingPolls int            // initial collects per cert that report "being processed"
	seq          int
}

// NewServer starts a fake SCM SSL API backed by a fresh software CA. By default
// certificates are issued immediately (collect returns the chain on first call).
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("Sectigo SCM Test CA")
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority, certs: map[int][]byte{}, collectCount: map[int]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ssl/v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /api/ssl/v1/collect/{sslID}/{format}", s.handleCollect)
	s.ts = httptest.NewServer(s.auth(mux))
	return s, nil
}

// URL is the base URL; the plugin appends /api/ssl/v1/... paths.
func (s *Server) URL() string { return s.ts.URL }

// Login, Password, and CustomerURI are the credentials the double accepts.
func (s *Server) Login() string       { return login }
func (s *Server) Password() string    { return password }
func (s *Server) CustomerURI() string { return customerURI }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// SetPendingPolls makes the first n collect calls for each certificate report
// "being processed" (code -183) before the chain is returned, modelling SCM's
// asynchronous issuance.
func (s *Server) SetPendingPolls(n int) {
	s.mu.Lock()
	s.pendingPolls = n
	s.mu.Unlock()
}

// auth enforces the SCM credential headers on every request.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("login") != login || r.Header.Get("password") != password || r.Header.Get("customerUri") != customerURI {
			writeErr(w, http.StatusUnauthorized, -16, "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrgID    int    `json:"orgId"`
		CSR      string `json:"csr"`
		CertType int    `json:"certType"`
		Term     int    `json:"term"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, -1, "invalid request body")
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, -1, "could not parse CSR PEM")
		return
	}
	ttl := time.Duration(body.Term) * 24 * time.Hour
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	issued, err := s.authority.IssueFromCSR(block.Bytes, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, -1, err.Error())
		return
	}
	s.mu.Lock()
	s.seq++
	sslID := s.seq
	s.certs[sslID] = issued.CertificatePEM
	s.collectCount[sslID] = 0
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"sslId": sslID, "renewId": "renew-" + strconv.Itoa(sslID)})
}

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("sslID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeBeingProcessed, "Being processed by Sectigo CA")
		return
	}
	switch r.PathValue("format") {
	case "pem", "pemia", "x509":
	default:
		writeErr(w, http.StatusBadRequest, -1, "unsupported certificate format")
		return
	}
	s.mu.Lock()
	chain, ok := s.certs[id]
	s.collectCount[id]++
	pending := s.collectCount[id] <= s.pendingPolls
	s.mu.Unlock()
	if !ok || pending {
		writeErr(w, http.StatusBadRequest, codeBeingProcessed, "Being processed by Sectigo CA")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(chain)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status, code int, description string) {
	writeJSON(w, status, map[string]any{"code": code, "description": description})
}
