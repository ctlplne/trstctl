// Package smallstepfake is a faithful in-process test double of the Smallstep
// step-ca HTTP API, enough to exercise the Smallstep CA plugin end-to-end without
// a real step-ca. It mirrors the documented contract: GET /health and
// POST /1.0/sign accepting {csr, ott} and returning {crt, ca, certChain}. It
// verifies the one-time token (a JWS minted by the JWK provisioner) through the
// jose crypto boundary and signs the CSR with a local software authority via the
// crypto boundary, so it holds no crypto/* itself.
package smallstepfake

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/jose"
)

const (
	provisionerName = "trstctl@smallstep.test"
	certValidity    = 24 * time.Hour
)

// Server is a running fake step-ca.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority
	key       []byte // the JWK (symmetric) provisioner secret
}

// NewServer starts a fake step-ca backed by a fresh software CA and a random
// symmetric provisioner key.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("Smallstep Test Intermediate CA")
	if err != nil {
		return nil, err
	}
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /1.0/sign", s.handleSign)
	s.ts = httptest.NewServer(mux)
	return s, nil
}

// URL is the step-ca base URL.
func (s *Server) URL() string { return s.ts.URL }

// ProvisionerName is the JWK provisioner's name (the OTT "iss").
func (s *Server) ProvisionerName() string { return provisionerName }

// ProvisionerKey is the symmetric provisioner secret used to sign/verify OTTs.
func (s *Server) ProvisionerKey() []byte { return s.key }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR string `json:"csr"`
		OTT string `json:"ott"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse sign request")
		return
	}
	payload, err := jose.VerifyHS256(s.key, body.OTT)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "the provisioner token signature is invalid")
		return
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
		Nbf int64  `json:"nbf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token claims")
		return
	}
	now := time.Now().Unix()
	switch {
	case claims.Iss != provisionerName:
		writeErr(w, http.StatusUnauthorized, "token issued by an unknown provisioner")
		return
	case claims.Sub == "":
		writeErr(w, http.StatusUnauthorized, "token has no subject")
		return
	case claims.Exp != 0 && now > claims.Exp:
		writeErr(w, http.StatusUnauthorized, "token has expired")
		return
	case claims.Nbf != 0 && now < claims.Nbf:
		writeErr(w, http.StatusUnauthorized, "token is not yet valid")
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, "could not parse CSR")
		return
	}
	issued, err := s.authority.IssueFromCSR(block.Bytes, certValidity)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	leaf, caChain := splitChain(issued.CertificatePEM)
	chain := make([]string, 0, 2)
	if leaf != "" {
		chain = append(chain, leaf)
	}
	if caChain != "" {
		chain = append(chain, caChain)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"crt": leaf, "ca": caChain, "certChain": chain})
}

// splitChain returns the first CERTIFICATE block (the leaf) and the remaining
// blocks (the issuing chain), each as PEM text.
func splitChain(pemBytes []byte) (leaf, chain string) {
	rest := pemBytes
	first := true
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		enc := string(pem.EncodeToMemory(block))
		if first {
			leaf = enc
			first = false
		} else {
			chain += enc
		}
		rest = r
	}
	return leaf, chain
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"status": status, "message": message})
}
