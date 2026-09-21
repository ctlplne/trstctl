// SPDX-License-Identifier: BUSL-1.1

// Package venafifake is an in-process test double of the Venafi TPP Web SDK
// certificate request/retrieve flow. It is enough to exercise the Venafi CA
// plugin end-to-end without a real TPP/TLS Protect deployment: bearer-token auth,
// POST /vedsdk/Certificates/Request returning a CertificateDN/Guid, and
// POST /vedsdk/Certificates/Retrieve returning a PEM chain. It signs submitted
// CSRs with a local software authority through the crypto boundary.
package venafifake

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

const (
	token    = "venafi-test-token" // #nosec G101 -- test-support package compiled only into test binaries (CWE-798)
	policyDN = `\VED\Policy\Certificates\trstctl`
)

// Server is a running fake Venafi TPP Web SDK API.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority

	mu           sync.Mutex
	certs        map[string][]byte // CertificateDN -> PEM chain
	guids        map[string]string // Guid -> CertificateDN
	retrieveSeen map[string]int
	pendingPolls int
	seq          int
}

// NewServer starts a fake Venafi API backed by a fresh software CA.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("Venafi TPP Test CA")
	if err != nil {
		return nil, err
	}
	s := &Server{
		authority:    authority,
		certs:        map[string][]byte{},
		guids:        map[string]string{},
		retrieveSeen: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /vedsdk/Certificates/Request", s.handleRequest)
	mux.HandleFunc("POST /vedsdk/Certificates/Retrieve", s.handleRetrieve)
	s.ts = httptest.NewServer(s.auth(mux))
	return s, nil
}

// URL is the base URL; the plugin appends /vedsdk/... paths.
func (s *Server) URL() string { return s.ts.URL }

// Token is the bearer token the double accepts.
func (s *Server) Token() string { return token }

// PolicyDN is the policy DN the double accepts.
func (s *Server) PolicyDN() string { return policyDN }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// SetPendingPolls makes the first n Retrieve calls for each certificate return a
// pending status without CertificateData, modeling asynchronous issuance.
func (s *Server) SetPendingPolls(n int) {
	s.mu.Lock()
	s.pendingPolls = n
	s.mu.Unlock()
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			writeErr(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PolicyDN   string `json:"PolicyDN"`
		PKCS10     string `json:"PKCS10"`
		ObjectName string `json:"ObjectName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.PolicyDN != policyDN {
		writeErr(w, http.StatusBadRequest, "unknown PolicyDN")
		return
	}
	block, _ := pem.Decode([]byte(body.PKCS10))
	if block == nil {
		writeErr(w, http.StatusBadRequest, "could not parse PKCS10 CSR")
		return
	}
	issued, err := s.authority.IssueFromCSR(block.Bytes, 90*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	s.seq++
	name := body.ObjectName
	if name == "" {
		name = "certificate-" + strconv.Itoa(s.seq)
	}
	certDN := policyDN + `\` + name + "-" + strconv.Itoa(s.seq)
	guid := fmt.Sprintf("venafi-guid-%d", s.seq)
	s.certs[certDN] = issued.CertificatePEM
	s.guids[guid] = certDN
	s.retrieveSeen[certDN] = 0
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"CertificateDN": certDN, "Guid": guid})
}

func (s *Server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertificateDN string `json:"CertificateDN"`
		GUID          string `json:"Guid"`
		Format        string `json:"Format"`
		IncludeChain  bool   `json:"IncludeChain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid retrieve body")
		return
	}
	if body.Format != "" && body.Format != "PEM" {
		writeErr(w, http.StatusBadRequest, "unsupported certificate format")
		return
	}
	certDN := body.CertificateDN
	s.mu.Lock()
	if certDN == "" {
		certDN = s.guids[body.GUID]
	}
	chain, ok := s.certs[certDN]
	s.retrieveSeen[certDN]++
	pending := s.retrieveSeen[certDN] <= s.pendingPolls
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	if pending {
		writeJSON(w, http.StatusOK, map[string]string{"Status": "Pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"Status": "Issued", "CertificateData": string(chain)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"Message": message})
}
