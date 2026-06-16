// Package ejbcafake is a faithful in-process test double of the EJBCA REST API
// certificate-enrollment endpoint, enough to exercise the EJBCA CA plugin
// end-to-end without a real EJBCA. It mirrors the documented contract: OAuth2
// bearer auth, POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll accepting
// the CSR (PEM or bare base64 DER) and returning {certificate, serial_number,
// response_format:"DER", certificate_chain} with the leaf and chain as
// base64-encoded DER, and the {error_code,error_message} error envelope. It signs
// submitted CSRs with a local software authority via the crypto boundary, so it
// holds no crypto/* itself.
package ejbcafake

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

const (
	bearerToken  = "ejbca-test-token"
	certValidity = 365 * 24 * time.Hour
)

// Server is a running fake EJBCA REST API.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority
}

// NewServer starts a fake EJBCA REST API backed by a fresh software CA.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("EJBCA ManagementCA Test")
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll", s.handleEnroll)
	mux.HandleFunc("GET /ejbca/ejbca-rest-api/v1/certificate/status", s.handleStatus)
	s.ts = httptest.NewServer(s.auth(mux))
	return s, nil
}

// URL is the base URL; the plugin appends the REST paths.
func (s *Server) URL() string { return s.ts.URL }

// Token is the OAuth2 bearer token the double accepts.
func (s *Server) Token() string { return bearerToken }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// auth enforces the OAuth2 bearer token (one of EJBCA's two REST auth methods).
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearerToken {
			writeErr(w, http.StatusForbidden, "Not authorized to resource /administrator.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "OK", "version": "1.0", "revision": "ALPHA"})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertificateRequest string `json:"certificate_request"`
		IncludeChain       bool   `json:"include_chain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	csrDER, err := decodeCSR(body.CertificateRequest)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "could not parse certificate_request")
		return
	}
	issued, err := s.authority.IssueFromCSR(csrDER, certValidity)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ders := derBlocks(issued.CertificatePEM)
	if len(ders) == 0 {
		writeErr(w, http.StatusInternalServerError, "no certificate produced")
		return
	}
	resp := map[string]any{
		"certificate":     base64.StdEncoding.EncodeToString(ders[0]),
		"serial_number":   issued.Serial,
		"response_format": "DER",
	}
	if body.IncludeChain && len(ders) > 1 {
		chain := make([]string, 0, len(ders)-1)
		for _, d := range ders[1:] {
			chain = append(chain, base64.StdEncoding.EncodeToString(d))
		}
		resp["certificate_chain"] = chain
	}
	writeJSON(w, http.StatusCreated, resp)
}

// decodeCSR accepts a PEM CSR or a bare base64 DER blob, as EJBCA does.
func decodeCSR(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, fmt.Errorf("bad CSR PEM")
		}
		return block.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s))
}

// derBlocks extracts the DER bytes of each CERTIFICATE block in a PEM chain.
func derBlocks(pemBytes []byte) [][]byte {
	var ders [][]byte
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
		rest = r
	}
	return ders
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error_code": status, "error_message": message})
}
