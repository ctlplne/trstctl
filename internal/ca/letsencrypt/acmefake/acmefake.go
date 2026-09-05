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
// dnsChallengeToken is the fixed token this authority issues. Fixed so a test
// can compute the expected TXT value without scraping it back out.
const dnsChallengeToken = "b7-dns01-token" // #nosec G101 -- fabricated fixture challenge token in a test double; no value is real (CWE-798)

type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority

	mu                sync.Mutex
	nonce             int
	orders            int
	accountRegistered bool
	certs             map[string][]byte // path -> PEM chain
	// revocations records revoke-cert requests that actually arrived (epic R2).
	revocations []string
	// B7: domain-validation mode. Off by default so existing tests keep
	// exercising what they were written for.
	requireDV        bool
	identifier       string
	wildcard         bool
	accepted         map[string]bool
	challengeAccepts int
	asyncFinalize    bool
}

// NewServer starts a fake ACME CA backed by a fresh internal CA.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("acmefake Test CA")
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority, certs: map[string][]byte{}, accepted: map[string]bool{}}
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

// RequireDomainValidation makes this authority issue PENDING orders with a
// dns-01 challenge, so a client must actually solve one.
//
// Opt-in rather than the default: the six existing call sites test issuance
// mechanics, not validation, and forcing DV on them would test the fixture.
func (s *Server) RequireDomainValidation(identifier string, wildcard bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requireDV = true
	s.identifier = identifier
	s.wildcard = wildcard
}

// EmulateAsyncFinalizeWithoutLocation models authorities such as Pebble that
// may answer finalize with a processing order but no Location header. The
// original order URL remains the only safe reconciliation handle in that case.
func (s *Server) EmulateAsyncFinalizeWithoutLocation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asyncFinalize = true
}

// ChallengeAccepts counts challenges the client accepted. A DV test asserts
// this moved: an order that finalized without it did not validate anything.
func (s *Server) ChallengeAccepts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.challengeAccepts
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
		s.mu.Lock()
		alreadyRegistered := s.accountRegistered
		s.accountRegistered = true
		s.mu.Unlock()
		w.Header().Set("Location", s.u("/account/1"))
		if alreadyRegistered {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = fmt.Fprintf(w, `{"status":"valid","orders":%q}`, s.u("/account/1/orders"))
	case r.URL.Path == "/new-order":
		s.mu.Lock()
		s.orders++
		n := s.orders
		requireDV := s.requireDV
		s.mu.Unlock()
		w.Header().Set("Location", s.u(fmt.Sprintf("/order/%d", n)))
		w.WriteHeader(http.StatusCreated)
		if requireDV {
			// PENDING. The order cannot be finalized until the authorization
			// validates, which happens only after the client publishes the
			// record and accepts the challenge.
			_, _ = fmt.Fprintf(w, `{"status":"pending","authorizations":[%q],"finalize":%q}`,
				s.u(fmt.Sprintf("/authz/%d", n)), s.u(fmt.Sprintf("/order/%d/finalize", n)))
			return
		}
		// Pre-authorized: the order is immediately ready to finalize.
		_, _ = fmt.Fprintf(w, `{"status":"ready","authorizations":[%q],"finalize":%q}`,
			s.u(fmt.Sprintf("/authz/%d", n)), s.u(fmt.Sprintf("/order/%d/finalize", n)))
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		s.mu.Lock()
		requireDV := s.requireDV
		accepted := s.accepted[r.URL.Path]
		s.mu.Unlock()
		if !requireDV {
			_, _ = fmt.Fprint(w, `{"status":"valid","identifier":{"type":"dns","value":"example.test"}}`)
			return
		}
		// A REAL pending authorization offering dns-01. It becomes valid only
		// once the challenge has been accepted, so a client that presents
		// nothing and accepts nothing never gets an order it can finalize.
		//
		// This is the whole point of the option: with a pre-authorized order,
		// a solver that does nothing passes every test — which is how the
		// upstream path shipped for this long unable to validate at all.
		status := "pending"
		if accepted {
			status = "valid"
		}
		writeJSON(w, map[string]any{
			"status":     status,
			"wildcard":   s.wildcard,
			"identifier": map[string]string{"type": "dns", "value": s.identifier},
			"challenges": []map[string]any{{
				"type":   "dns-01",
				"url":    s.u(strings.Replace(r.URL.Path, "/authz/", "/chal/", 1)),
				"token":  dnsChallengeToken,
				"status": status,
			}},
		})
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		// Accepting the challenge is what flips the authorization to valid.
		authzPath := strings.Replace(r.URL.Path, "/chal/", "/authz/", 1)
		s.mu.Lock()
		s.accepted[authzPath] = true
		s.challengeAccepts++
		s.mu.Unlock()
		writeJSON(w, map[string]any{
			"type": "dns-01", "url": s.u(r.URL.Path),
			"token": dnsChallengeToken, "status": "valid",
		})
	case strings.HasPrefix(r.URL.Path, "/order/") && !strings.HasSuffix(r.URL.Path, "/finalize"):
		// Polling the order. After the authorization validates, the order
		// becomes ready — this is the transition a real client waits on, and
		// without it a DV order can never be finalized.
		n := strings.TrimPrefix(r.URL.Path, "/order/")
		authzPath := "/authz/" + n
		s.mu.Lock()
		accepted := s.accepted[authzPath]
		_, finalized := s.certs["/cert/"+n]
		s.mu.Unlock()
		if finalized {
			writeJSON(w, map[string]any{
				"status": "valid", "authorizations": []string{s.u(authzPath)},
				"finalize": s.u(r.URL.Path + "/finalize"), "certificate": s.u("/cert/" + n),
			})
			return
		}
		status := "pending"
		if accepted || !s.requireDV {
			status = "ready"
		}
		writeJSON(w, map[string]any{
			"status":         status,
			"authorizations": []string{s.u(authzPath)},
			"finalize":       s.u(r.URL.Path + "/finalize"),
		})
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
	asyncFinalize := s.asyncFinalize
	s.mu.Unlock()
	if asyncFinalize {
		_, _ = fmt.Fprintf(w, `{"status":"processing","finalize":%q}`, s.u(r.URL.Path)) // #nosec G705 -- test-support package compiled only into test binaries (CWE-79)
		return
	}
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

// writeJSON encodes a response value.
//
// The DV handlers used to interpolate identifiers and URLs into a JSON string
// template with %q, which is correct for well-formed input and a taint finding
// for anything else — the identifier arrives from the client's own order. A
// double that models a hostile authority should not itself be the thing that
// mis-encodes.
func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
