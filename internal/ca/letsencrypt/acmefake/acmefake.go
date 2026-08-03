// SPDX-License-Identifier: MPL-2.0

// Package acmefake is a minimal in-process ACME (RFC 8555) certificate authority
// for exercising ACME clients in tests and local development. It is the test
// counterpart to a real Let's Encrypt: it speaks enough of the protocol for
// golang.org/x/crypto/acme to drive an order to completion, pre-authorizing the
// order (no real challenge validation) and signing the submitted CSR with an
// internal/crypto/ca authority. It performs no signature checks and must never be
// used as a real CA.
package acmefake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// Server is a running fake ACME CA.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority

	mu     sync.Mutex
	nonce  int
	orders int
	certs  map[string][]byte // path -> PEM chain
	// revocations records revoke-cert requests that actually arrived (epic R2).
	revocations []string
}

// NewServer starts a fake ACME CA backed by a fresh internal CA.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("acmefake Test CA")
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority, certs: map[string][]byte{}}
	s.ts = httptest.NewServer(http.HandlerFunc(s.route))
	return s, nil
}

// DirectoryURL is the ACME directory endpoint to configure a client with.
func (s *Server) DirectoryURL() string { return s.ts.URL + "/directory" }

// CACertificatePEM is the fake CA's certificate (the trust anchor for issued
// chains).
func (s *Server) CACertificatePEM() []byte { return s.authority.CertificatePEM() }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

func (s *Server) u(path string) string { return s.ts.URL + path }

// Revocations returns the raw revoke-cert requests this authority received.
// A test asserts on the COUNT: the point is whether the authority was actually
// contacted, not what the JWS decoded to.
func (s *Server) Revocations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revocations...)
}

func (s *Server) nextNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonce++
	return fmt.Sprintf("nonce-%d", s.nonce)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.URL.Path == "/directory" {
		// revokeCert is advertised because the client only attempts revocation
		// when the directory offers it (RFC 8555 §7.1.1). A double that omitted
		// it would make the revoke test pass for the wrong reason — by never
		// reaching the endpoint at all.
		_, _ = fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"meta":{"termsOfService":%q}}`,
			s.u("/new-nonce"), s.u("/new-account"), s.u("/new-order"), s.u("/revoke-cert"), s.u("/terms"))
		return
	}

	// Every non-directory response carries a fresh nonce (RFC 8555).
	w.Header().Set("Replay-Nonce", s.nextNonce())

	switch {
	case r.URL.Path == "/new-nonce":
		return
	case r.URL.Path == "/new-account":
		w.Header().Set("Location", s.u("/account/1"))
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"status":"valid","orders":%q}`, s.u("/account/1/orders"))
	case r.URL.Path == "/new-order":
		s.mu.Lock()
		s.orders++
		n := s.orders
		s.mu.Unlock()
		w.Header().Set("Location", s.u(fmt.Sprintf("/order/%d", n)))
		w.WriteHeader(http.StatusCreated)
		// Pre-authorized: the order is immediately ready to finalize.
		_, _ = fmt.Fprintf(w, `{"status":"ready","authorizations":[%q],"finalize":%q}`,
			s.u(fmt.Sprintf("/authz/%d", n)), s.u(fmt.Sprintf("/order/%d/finalize", n)))
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		_, _ = fmt.Fprint(w, `{"status":"valid","identifier":{"type":"dns","value":"example.test"}}`)
	case strings.HasSuffix(r.URL.Path, "/finalize"):
		s.finalize(w, r)
	case r.URL.Path == "/revoke-cert":
		// RFC 8555 §7.6. The body is a JWS whose payload carries the
		// base64url DER of the certificate and an optional reason. The double
		// records that the request ARRIVED, which is the property the test
		// needs: a Revoke that returns nil without reaching here is exactly
		// what the epic exists to prevent.
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.revocations = append(s.revocations, string(body))
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(r.URL.Path, "/cert/"):
		s.mu.Lock()
		pem := s.certs[r.URL.Path]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pem)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"type":"urn:ietf:params:acme:error:malformed","detail":"unhandled %s"}`, r.URL.Path) // #nosec G705 -- test-support package compiled only into test binaries (CWE-79)
	}
}

func (s *Server) finalize(w http.ResponseWriter, r *http.Request) {
	csr, err := csrFromJWS(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"type":"urn:ietf:params:acme:error:malformed","detail":%q}`, err.Error())
		return
	}
	issued, err := s.authority.IssueFromCSR(csr, 90*24*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"type":"urn:ietf:params:acme:error:badCSR","detail":%q}`, err.Error())
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/order/"), "/finalize")
	certPath := "/cert/" + id
	s.mu.Lock()
	s.certs[certPath] = issued.CertificatePEM
	s.mu.Unlock()
	w.Header().Set("Location", s.u("/order/"+id))
	_, _ = fmt.Fprintf(w, `{"status":"valid","finalize":%q,"certificate":%q}`, s.u(r.URL.Path), s.u(certPath)) // #nosec G705 -- test-support package compiled only into test binaries (CWE-79)
}

// csrFromJWS extracts the finalize request's CSR from the flattened-JSON JWS body
// (the fake CA does not verify the signature).
func csrFromJWS(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, fmt.Errorf("acmefake: decode jws: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("acmefake: decode payload: %w", err)
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("acmefake: decode finalize: %w", err)
	}
	return base64.RawURLEncoding.DecodeString(req.CSR)
}
