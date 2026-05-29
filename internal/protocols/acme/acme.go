// Package acme is the built-in ACME (RFC 8555) server (F5). It serves the ACME
// directory, account, order, authorization, challenge, finalize, and certificate
// endpoints, verifying each client request's JWS (via the internal/crypto/jose
// boundary) and enforcing single-use nonces. On finalize it brokers the CSR to a
// configured upstream certificate authority (the ca.CA interface — the built-in
// CA or a CA plugin such as Let's Encrypt). Challenge validation is pluggable
// (a real HTTP-01 validator ships in validate.go).
//
// State is held in memory for a single server instance; durable, event-sourced
// order state is a later integration. This package handles no crypto/* directly.
package acme

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/crypto/jose"
	"certctl.io/certctl/internal/protocols/ari"
)

const (
	statusPending = "pending"
	statusReady   = "ready"
	statusValid   = "valid"

	// ariRetryAfterSeconds is how long an ARI client should wait before polling
	// renewalInfo again (RFC 9773 Retry-After), here 6 hours.
	ariRetryAfterSeconds = 6 * 60 * 60
)

type account struct {
	id  string // thumbprint
	url string
	key *jose.ACMEKey
}

type challenge struct {
	id      string
	typ     string
	token   string
	status  string
	authzID string
}

type authorization struct {
	id         string
	orderID    string
	domain     string
	status     string
	challenges []*challenge
}

type order struct {
	id         string
	accountURL string
	domains    []string
	authzIDs   []string
	status     string
	certID     string
	replaces   string // ARI: the certificate identifier this order renews (RFC 9773)
}

// ariWindow is the validity span the server derives a renewal window from.
type ariWindow struct {
	notBefore time.Time
	notAfter  time.Time
}

// Server is the built-in ACME server. Construct it with New and mount it as an
// http.Handler.
type Server struct {
	ca        ca.CA
	validator Validator

	mu         sync.Mutex
	nonces     map[string]bool
	accounts   map[string]*account // by URL
	byKey      map[string]*account // by thumbprint (registration idempotency)
	orders     map[string]*order
	authzs     map[string]*authorization
	challenges map[string]*challenge
	certs      map[string][]byte
	ariWindows map[string]ariWindow // ARI: certID -> validity span (RFC 9773)
	earlyRenew map[string]bool      // ARI: certIDs flagged for proactive renewal
	seq        int

	mux *http.ServeMux
}

// New returns an ACME server brokering issuance to ca, validating challenges with
// validator.
func New(ca ca.CA, validator Validator) *Server {
	s := &Server{
		ca: ca, validator: validator,
		nonces: map[string]bool{}, accounts: map[string]*account{}, byKey: map[string]*account{},
		orders: map[string]*order{}, authzs: map[string]*authorization{},
		challenges: map[string]*challenge{}, certs: map[string][]byte{},
		ariWindows: map[string]ariWindow{}, earlyRenew: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", s.directory)
	mux.HandleFunc("GET /acme/renewal-info/{certid}", s.renewalInfo)
	mux.HandleFunc("GET /acme/new-nonce", s.newNonce)
	mux.HandleFunc("HEAD /acme/new-nonce", s.newNonce)
	mux.HandleFunc("POST /acme/new-account", s.jws(s.newAccount))
	mux.HandleFunc("POST /acme/new-order", s.jws(s.newOrder))
	mux.HandleFunc("POST /acme/authz/{id}", s.jws(s.getAuthz))
	mux.HandleFunc("POST /acme/chal/{id}", s.jws(s.acceptChallenge))
	mux.HandleFunc("POST /acme/order/{id}", s.jws(s.getOrder))
	mux.HandleFunc("POST /acme/order/{id}/finalize", s.jws(s.finalize))
	mux.HandleFunc("POST /acme/cert/{id}", s.jws(s.getCert))
	s.mux = mux
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) nextID() string {
	s.seq++
	return fmt.Sprintf("%d", s.seq)
}

func (s *Server) mintNonce() string {
	b, _ := crypto.RandomBytes(16)
	n := base64.RawURLEncoding.EncodeToString(b)
	s.nonces[n] = true
	return n
}

func randomToken() string {
	b, _ := crypto.RandomBytes(24)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) directory(w http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":    base + "/acme/new-nonce",
		"newAccount":  base + "/acme/new-account",
		"newOrder":    base + "/acme/new-order",
		"renewalInfo": base + "/acme/renewal-info",
		"meta":        map[string]any{"termsOfService": base + "/terms"},
	})
}

func (s *Server) newNonce(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// jwsHandler is a POST handler that has already had its JWS verified; account is
// non-nil for kid-authenticated requests.
type jwsHandler func(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account)

// jws wraps a handler with JWS verification and single-use nonce enforcement,
// always returning a fresh Replay-Nonce.
func (s *Server) jws(h jwsHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "malformed", "cannot read request body")
			return
		}
		msg, err := jose.ParseACMEJWS(body)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
			return
		}

		s.mu.Lock()
		if !s.nonces[msg.Protected.Nonce] {
			s.mu.Unlock()
			s.problem(w, r, http.StatusBadRequest, "badNonce", "unknown or used nonce")
			return
		}
		delete(s.nonces, msg.Protected.Nonce)

		var acct *account
		var key *jose.ACMEKey
		if msg.Protected.Kid != "" {
			acct = s.accounts[msg.Protected.Kid]
			if acct == nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusBadRequest, "accountDoesNotExist", "unknown account")
				return
			}
			key = acct.key
		} else if len(msg.Protected.JWK) > 0 {
			key, err = jose.ACMEKeyFromJWK(msg.Protected.JWK)
			if err != nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
				return
			}
		} else {
			s.mu.Unlock()
			s.problem(w, r, http.StatusBadRequest, "malformed", "JWS has neither kid nor jwk")
			return
		}
		s.mu.Unlock()

		if err := msg.Verify(key); err != nil {
			s.problem(w, r, http.StatusUnauthorized, "unauthorized", "JWS verification failed")
			return
		}

		// Every ACME response carries a fresh nonce.
		s.mu.Lock()
		w.Header().Set("Replay-Nonce", s.mintNonce())
		s.mu.Unlock()
		h(w, r, msg, acct)
	}
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, _ *account) {
	key, err := jose.ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
		return
	}
	thumb := key.Thumbprint()
	s.mu.Lock()
	acct := s.byKey[thumb]
	if acct == nil {
		acct = &account{id: thumb, url: baseURL(r) + "/acme/acct/" + s.nextID(), key: key}
		s.byKey[thumb] = acct
		s.accounts[acct.url] = acct
	}
	url := acct.url
	s.mu.Unlock()

	w.Header().Set("Location", url)
	writeJSON(w, http.StatusCreated, map[string]any{"status": statusValid, "orders": url + "/orders"})
}

func (s *Server) newOrder(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	var req struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
		Replaces    string                         `json:"replaces"` // ARI (RFC 9773)
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	if req.Replaces != "" && !ari.ValidCertID(req.Replaces) {
		s.problem(w, r, http.StatusBadRequest, "malformed", "replaces is not a valid certificate identifier")
		return
	}
	base := baseURL(r)
	s.mu.Lock()
	o := &order{id: s.nextID(), accountURL: acct.url, status: statusPending, replaces: req.Replaces}
	var authzURLs []string
	for _, id := range req.Identifiers {
		o.domains = append(o.domains, id.Value)
		az := &authorization{id: s.nextID(), orderID: o.id, domain: id.Value, status: statusPending}
		for _, ct := range []string{ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01} {
			ch := &challenge{id: s.nextID(), typ: ct, token: randomToken(), status: statusPending, authzID: az.id}
			az.challenges = append(az.challenges, ch)
			s.challenges[ch.id] = ch
		}
		s.authzs[az.id] = az
		o.authzIDs = append(o.authzIDs, az.id)
		authzURLs = append(authzURLs, base+"/acme/authz/"+az.id)
	}
	s.orders[o.id] = o
	orderURL := base + "/acme/order/" + o.id
	s.mu.Unlock()

	w.Header().Set("Location", orderURL)
	writeJSON(w, http.StatusCreated, s.orderJSON(base, o, authzURLs))
}

func (s *Server) getAuthz(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, _ *account) {
	base := baseURL(r)
	s.mu.Lock()
	az := s.authzs[r.PathValue("id")]
	s.mu.Unlock()
	if az == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	writeJSON(w, http.StatusOK, s.authzJSON(base, az))
}

func (s *Server) acceptChallenge(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, acct *account) {
	base := baseURL(r)
	s.mu.Lock()
	ch := s.challenges[r.PathValue("id")]
	if ch == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	az := s.authzs[ch.authzID]
	s.mu.Unlock()

	keyAuth := ch.token + "." + acct.key.Thumbprint()
	if err := s.validator.Validate(r.Context(), ch.typ, az.domain, ch.token, keyAuth); err != nil {
		s.problem(w, r, http.StatusBadRequest, "unauthorized", "challenge validation failed: "+err.Error())
		return
	}

	s.mu.Lock()
	ch.status = statusValid
	az.status = statusValid
	if o := s.orders[az.orderID]; o != nil && s.allAuthzValid(o) {
		o.status = statusReady
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"type": ch.typ, "url": base + "/acme/chal/" + ch.id, "token": ch.token, "status": ch.status,
	})
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, _ *account) {
	base := baseURL(r)
	s.mu.Lock()
	o := s.orders[r.PathValue("id")]
	var authzURLs []string
	if o != nil {
		for _, id := range o.authzIDs {
			authzURLs = append(authzURLs, base+"/acme/authz/"+id)
		}
	}
	s.mu.Unlock()
	if o == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such order")
		return
	}
	writeJSON(w, http.StatusOK, s.orderJSON(base, o, authzURLs))
}

func (s *Server) finalize(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, _ *account) {
	base := baseURL(r)
	s.mu.Lock()
	o := s.orders[r.PathValue("id")]
	s.mu.Unlock()
	if o == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such order")
		return
	}
	if o.status != statusReady {
		s.problem(w, r, http.StatusForbidden, "orderNotReady", "order is not ready to finalize")
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	csr, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "badCSR", err.Error())
		return
	}

	cert, err := s.ca.Issue(r.Context(), ca.IssueRequest{CSR: csr, DNSNames: o.domains, TTL: 90 * 24 * time.Hour})
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", "issuance failed: "+err.Error())
		return
	}

	s.mu.Lock()
	o.certID = s.nextID()
	s.certs[o.certID] = cert.CertificatePEM
	// ARI (RFC 9773): index the issued certificate's validity by its ARI
	// certificate identifier so the renewalInfo endpoint can serve its window.
	if block, _ := pem.Decode(cert.CertificatePEM); block != nil {
		if certid, err := certinfo.ARICertID(block.Bytes); err == nil {
			if info, ierr := certinfo.Inspect(cert.CertificatePEM); ierr == nil {
				s.ariWindows[certid] = ariWindow{notBefore: info.NotBefore, notAfter: info.NotAfter}
			}
		}
	}
	o.status = statusValid
	authzURLs := make([]string, 0, len(o.authzIDs))
	for _, id := range o.authzIDs {
		authzURLs = append(authzURLs, base+"/acme/authz/"+id)
	}
	s.mu.Unlock()

	w.Header().Set("Location", base+"/acme/order/"+o.id)
	writeJSON(w, http.StatusOK, s.orderJSON(base, o, authzURLs))
}

func (s *Server) getCert(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, _ *account) {
	s.mu.Lock()
	pem := s.certs[r.PathValue("id")]
	s.mu.Unlock()
	if pem == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such certificate")
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(pem)
}

// renewalInfo serves ACME Renewal Information (RFC 9773) for a certificate: a
// suggested renewal window and a Retry-After poll hint. It is an unauthenticated
// GET. An early-renewal flag (set by MarkEarlyRenewal for a mass-revocation
// scenario) moves the window into the past so clients renew proactively.
func (s *Server) renewalInfo(w http.ResponseWriter, r *http.Request) {
	certid := r.PathValue("certid")
	if !ari.ValidCertID(certid) {
		s.problem(w, r, http.StatusBadRequest, "malformed", "invalid certificate identifier")
		return
	}
	s.mu.Lock()
	win, ok := s.ariWindows[certid]
	early := s.earlyRenew[certid]
	s.mu.Unlock()
	if !ok {
		s.problem(w, r, http.StatusNotFound, "malformed", "no renewal information for this certificate")
		return
	}
	info := ari.RenewalInfo{SuggestedWindow: ari.SuggestWindow(win.notBefore, win.notAfter, time.Now(), early)}
	w.Header().Set("Retry-After", strconv.Itoa(ariRetryAfterSeconds))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, info)
}

// MarkEarlyRenewal flags a certificate (by its ARI certificate identifier) for
// proactive renewal — the renewalInfo window for it then starts immediately. This
// is how a mass-revocation event signals clients to renew ahead of schedule.
func (s *Server) MarkEarlyRenewal(certID string) {
	s.mu.Lock()
	s.earlyRenew[certID] = true
	s.mu.Unlock()
}

func (s *Server) allAuthzValid(o *order) bool {
	for _, id := range o.authzIDs {
		if az := s.authzs[id]; az == nil || az.status != statusValid {
			return false
		}
	}
	return true
}

func (s *Server) orderJSON(base string, o *order, authzURLs []string) map[string]any {
	ids := make([]map[string]string, 0, len(o.domains))
	for _, d := range o.domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	out := map[string]any{
		"status":         o.status,
		"identifiers":    ids,
		"authorizations": authzURLs,
		"finalize":       base + "/acme/order/" + o.id + "/finalize",
	}
	if o.certID != "" {
		out["certificate"] = base + "/acme/cert/" + o.certID
	}
	return out
}

func (s *Server) authzJSON(base string, az *authorization) map[string]any {
	chals := make([]map[string]any, 0, len(az.challenges))
	for _, ch := range az.challenges {
		chals = append(chals, map[string]any{
			"type": ch.typ, "url": base + "/acme/chal/" + ch.id, "token": ch.token, "status": ch.status,
		})
	}
	return map[string]any{
		"status":     az.status,
		"identifier": map[string]string{"type": "dns", "value": az.domain},
		"challenges": chals,
	}
}

func (s *Server) problem(w http.ResponseWriter, _ *http.Request, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
