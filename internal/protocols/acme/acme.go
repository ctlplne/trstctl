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
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
)

const (
	maxJWSBody = 1 << 20

	statusPending = "pending"
	statusReady   = "ready"
	statusValid   = "valid"

	// ariRetryAfterSeconds is how long an ARI client should wait before polling
	// renewalInfo again (RFC 9773 Retry-After), here 6 hours.
	ariRetryAfterSeconds = 6 * 60 * 60
)

type account struct {
	id      string // thumbprint
	url     string
	key     *jose.ACMEKey
	contact []string // RFC 8555 §7.1.2 account contact URLs (e.g. mailto:)
	status  string   // "valid" (the only state this server tracks)
}

// DirectoryMeta is the optional metadata block the ACME directory advertises
// (RFC 8555 §7.1.1 "meta"). All fields are optional; a zero DirectoryMeta yields the
// minimal directory. ExternalAccountRequired, when true, also makes the server
// reject a newAccount that carries no externalAccountBinding (§7.3.4).
type DirectoryMeta struct {
	TermsOfService          string   // URL of the current terms of service
	Website                 string   // URL of a human-readable CA website
	CAAIdentities           []string // hostnames the CA recognises in CAA records
	ExternalAccountRequired bool     // require an externalAccountBinding on newAccount
}

// RevocationRequest is the authorized ACME revokeCert effect the served control
// plane receives after RFC 8555 account-key or certificate-key authorization has
// already succeeded. The ACME package remains storage-agnostic; served deployments
// use a hook to make the platform revocation state, OCSP, CRL, and audit trail
// converge before ACME returns success.
type RevocationRequest struct {
	Fingerprint string
	Serial      string
	Reason      int
	CertDER     []byte
}

// RevocationHook persists an authorized revocation effect. It must be idempotent
// for a repeated certificate fingerprint because ACME clients do not send a
// trustctl HTTP Idempotency-Key on revokeCert.
type RevocationHook func(context.Context, RevocationRequest) error

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

// issuedCert records what the server needs to authorize a later revokeCert
// (RFC 8555 §7.6): which account ordered the certificate (the account-key path),
// the leaf's public-key thumbprint (the certificate-key path), and its serial.
type issuedCert struct {
	accountURL string
	keyThumb   string // RFC 7638 thumbprint of the certificate's public key
	serial     string
	certID     string
}

// revocation is the recorded fact that a certificate has been revoked.
type revocation struct {
	serial string
	reason int
	at     time.Time
}

// Server is the built-in ACME server. Construct it with New and mount it as an
// http.Handler.
type Server struct {
	ca        ca.CA
	validator Validator

	meta DirectoryMeta

	mu         sync.Mutex
	nonces     map[string]bool
	accounts   map[string]*account // by URL
	byKey      map[string]*account // by thumbprint (registration idempotency)
	orders     map[string]*order
	authzs     map[string]*authorization
	challenges map[string]*challenge
	certs      map[string][]byte
	issued     map[string]*issuedCert // by SHA-256 fingerprint (hex) of the leaf DER
	revoked    map[string]revocation  // by SHA-256 fingerprint (hex); presence == revoked
	ariWindows map[string]ariWindow   // ARI: certID -> validity span (RFC 9773)
	earlyRenew map[string]bool        // ARI: certIDs flagged for proactive renewal
	seq        int

	revokeHook RevocationHook

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
		issued: map[string]*issuedCert{}, revoked: map[string]revocation{},
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
	// RFC 8555 §7.3.5 (account key rollover) and §7.6 (certificate revocation).
	mux.HandleFunc("POST /acme/key-change", s.jws(s.keyChange))
	mux.HandleFunc("POST /acme/revoke-cert", s.jws(s.revokeCert))
	s.mux = mux
	return s
}

// WithDirectoryMeta sets the directory meta block (RFC 8555 §7.1.1) the server
// advertises and, if ExternalAccountRequired is set, enables the §7.3.4
// external-account-binding requirement on newAccount. It returns s for chaining and
// is safe to call once immediately after New, before serving.
func (s *Server) WithDirectoryMeta(m DirectoryMeta) *Server {
	s.meta = m
	return s
}

// WithRevocationHook installs the served-platform revocation effect. The hook is
// invoked only after ACME revokeCert authorization succeeds; if it fails, revokeCert
// fails and the in-memory ACME state is not marked revoked.
func (s *Server) WithRevocationHook(h RevocationHook) *Server {
	s.revokeHook = h
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
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
		// RFC 8555 §7.1.1: the directory MUST advertise keyChange, and a revokeCert
		// resource MUST exist — without them a client cannot roll its account key
		// (§7.3.5) or revoke a certificate (§7.6).
		"keyChange":   base + "/acme/key-change",
		"revokeCert":  base + "/acme/revoke-cert",
		"renewalInfo": base + "/acme/renewal-info",
		"meta":        s.directoryMeta(base),
	})
}

// directoryMeta renders the RFC 8555 §7.1.1 "meta" object from the configured
// DirectoryMeta. termsOfService defaults to <base>/terms when unset so existing
// clients still see a ToS URL; the richer fields (website, caaIdentities,
// externalAccountRequired) appear only when configured.
func (s *Server) directoryMeta(base string) map[string]any {
	meta := map[string]any{}
	if s.meta.TermsOfService != "" {
		meta["termsOfService"] = s.meta.TermsOfService
	} else {
		meta["termsOfService"] = base + "/terms"
	}
	if s.meta.Website != "" {
		meta["website"] = s.meta.Website
	}
	if len(s.meta.CAAIdentities) > 0 {
		meta["caaIdentities"] = s.meta.CAAIdentities
	}
	if s.meta.ExternalAccountRequired {
		meta["externalAccountRequired"] = true
	}
	return meta
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
		body, err := bodylimit.ReadAll(r.Body, maxJWSBody)
		if errors.Is(err, bodylimit.ErrTooLarge) {
			s.problem(w, r, http.StatusRequestEntityTooLarge, "malformed", "request body too large")
			return
		}
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

// newAccountRequest is the RFC 8555 §7.3 new-account request payload.
type newAccountRequest struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, _ *account) {
	key, err := jose.ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
		return
	}

	// The payload is optional (an empty body is a bare registration), but when
	// present it must be well-formed JSON.
	var req newAccountRequest
	if len(msg.Payload) > 0 {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			s.problem(w, r, http.StatusBadRequest, "malformed", "cannot parse new-account request")
			return
		}
	}

	thumb := key.Thumbprint()
	s.mu.Lock()
	acct := s.byKey[thumb]
	existed := acct != nil

	// RFC 8555 §7.3.1: onlyReturnExisting asks the server to look up an existing
	// account WITHOUT creating one; if none exists it MUST return 400
	// accountDoesNotExist.
	if !existed && req.OnlyReturnExisting {
		s.mu.Unlock()
		s.problem(w, r, http.StatusBadRequest, "accountDoesNotExist", "no account exists for this key")
		return
	}

	if !existed {
		// RFC 8555 §7.3.4: when the CA requires external account binding, a
		// newAccount that creates an account MUST carry an externalAccountBinding.
		if s.meta.ExternalAccountRequired && len(req.ExternalAccountBinding) == 0 {
			s.mu.Unlock()
			s.problem(w, r, http.StatusBadRequest, "externalAccountRequired", "this CA requires an external account binding")
			return
		}
		acct = &account{
			id: thumb, url: baseURL(r) + "/acme/acct/" + s.nextID(), key: key,
			contact: req.Contact, status: statusValid,
		}
		s.byKey[thumb] = acct
		s.accounts[acct.url] = acct
	} else if len(req.Contact) > 0 {
		// Update contact on a returning registration (§7.3.2 allows contact update).
		acct.contact = req.Contact
	}
	url := acct.url
	contact := append([]string(nil), acct.contact...)
	s.mu.Unlock()

	// A returning account is 200 OK; a freshly created one is 201 Created (§7.3.1).
	code := http.StatusCreated
	if existed {
		code = http.StatusOK
	}
	w.Header().Set("Location", url)
	body := map[string]any{"status": statusValid, "orders": url + "/orders"}
	if len(contact) > 0 {
		body["contact"] = contact
	}
	writeJSON(w, code, body)
}

func (s *Server) newOrder(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	req, err := ParseOrderRequest(msg.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
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

func (s *Server) finalize(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
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
	csr, err := ParseFinalizeRequest(msg.Payload)
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
		// Index the leaf for revokeCert (RFC 8555 §7.6): a later revocation is
		// authorized either by this account's key or by the certificate's own key,
		// and matched against this DER's SHA-256 fingerprint.
		if fp := certFingerprint(block.Bytes); fp != "" {
			ic := &issuedCert{accountURL: acct.url, serial: cert.Serial, certID: o.certID}
			if thumb, terr := certinfo.PublicKeyJWKThumbprint(block.Bytes); terr == nil {
				ic.keyThumb = thumb
			}
			if info, ierr := certinfo.Inspect(block.Bytes); ierr == nil && ic.serial == "" {
				ic.serial = info.SerialNumber
			}
			s.issued[fp] = ic
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

// keyChange implements account key rollover (RFC 8555 §7.3.5). The OUTER JWS is
// kid-authenticated with the OLD account key (verified by the jws wrapper). Its
// payload is an INNER JWS, signed by the NEW key, whose protected header carries the
// new key as `jwk` and whose payload is {"account": <acctURL>, "oldKey": <oldKey>}.
// The server checks possession of the new key (inner signature), that the inner
// `account`/`oldKey` match the requesting account, and that the new key is not
// already bound to another account, then rotates the account key.
func (s *Server) keyChange(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	if acct == nil {
		// §7.3.5: keyChange MUST be kid-authenticated by the existing account.
		s.problem(w, r, http.StatusUnauthorized, "unauthorized", "keyChange requires an existing account (kid)")
		return
	}
	inner, err := jose.ParseACMEJWS(msg.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", "keyChange inner JWS: "+err.Error())
		return
	}
	newKey, err := jose.ACMEKeyFromJWK(inner.Protected.JWK)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "badPublicKey", "keyChange new key: "+err.Error())
		return
	}
	// The inner JWS must be signed by the new key (proof of possession).
	if err := inner.Verify(newKey); err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", "keyChange inner JWS not signed by the new key")
		return
	}
	body, err := ParseKeyChangeInner(inner.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	oldKey, err := jose.ACMEKeyFromJWK(body.OldKey)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", "keyChange oldKey: "+err.Error())
		return
	}
	// The inner payload must name THIS account and its CURRENT key.
	if body.Account != acct.url {
		s.problem(w, r, http.StatusForbidden, "unauthorized", "keyChange account URL does not match the authenticated account")
		return
	}
	newThumb := newKey.Thumbprint()
	s.mu.Lock()
	if oldKey.Thumbprint() != acct.key.Thumbprint() {
		s.mu.Unlock()
		s.problem(w, r, http.StatusForbidden, "unauthorized", "keyChange oldKey does not match the account's current key")
		return
	}
	// The new key must not already be in use by a different account (§7.3.5: 409).
	if other := s.byKey[newThumb]; other != nil && other.url != acct.url {
		s.mu.Unlock()
		w.Header().Set("Location", other.url)
		s.problem(w, r, http.StatusConflict, "accountDoesNotExist", "the new key is already in use by another account")
		return
	}
	// Rotate: re-key the thumbprint index and swap the account's verifying key.
	delete(s.byKey, acct.key.Thumbprint())
	acct.key = newKey
	acct.id = newThumb
	s.byKey[newThumb] = acct
	url := acct.url
	s.mu.Unlock()

	w.Header().Set("Location", url)
	writeJSON(w, http.StatusOK, map[string]any{"status": statusValid, "orders": url + "/orders"})
}

// revokeCert implements certificate revocation (RFC 8555 §7.6). The request is
// authorized EITHER by the account that issued the certificate (kid JWS) OR by the
// certificate's own key pair (jwk JWS whose embedded key matches the certificate).
// On success the certificate's serial is recorded revoked; a served deployment
// routes this to the revocation service / OCSP-CRL store (tracked as the served
// wire-in, EXC-WIRE-02). A double revocation returns 400 alreadyRevoked.
func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	req, err := ParseRevokeRequest(msg.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	fp := certFingerprint(req.CertDER)
	if fp == "" {
		s.problem(w, r, http.StatusBadRequest, "malformed", "revoke certificate does not parse")
		return
	}

	s.mu.Lock()
	ic := s.issued[fp]
	if ic == nil {
		s.mu.Unlock()
		// §7.6: the server does not have a record of this certificate.
		s.problem(w, r, http.StatusNotFound, "malformed", "no such certificate")
		return
	}
	if _, done := s.revoked[fp]; done {
		s.mu.Unlock()
		s.problem(w, r, http.StatusBadRequest, "alreadyRevoked", "certificate is already revoked")
		return
	}
	authorized := false
	switch {
	case acct != nil:
		// Account-key path: the account that ordered the certificate may revoke it.
		authorized = ic.accountURL == acct.url
	case len(msg.Protected.JWK) > 0:
		// Certificate-key path: the embedded JWK must be the certificate's key.
		if reqKey, kerr := jose.ACMEKeyFromJWK(msg.Protected.JWK); kerr == nil {
			authorized = ic.keyThumb != "" && reqKey.Thumbprint() == ic.keyThumb
		}
	}
	if !authorized {
		s.mu.Unlock()
		s.problem(w, r, http.StatusForbidden, "unauthorized", "not authorized to revoke this certificate")
		return
	}
	revReq := RevocationRequest{Fingerprint: fp, Serial: ic.serial, Reason: req.Reason, CertDER: req.CertDER}
	hook := s.revokeHook
	revokedAt := time.Now()
	s.mu.Unlock()

	if hook != nil {
		if err := hook(r.Context(), revReq); err != nil {
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", "revocation failed: "+err.Error())
			return
		}
	}

	s.mu.Lock()
	if _, done := s.revoked[fp]; !done {
		s.revoked[fp] = revocation{serial: ic.serial, reason: req.Reason, at: revokedAt}
	}
	s.mu.Unlock()

	// §7.6: a successful revocation responds 200 with an empty body.
	w.WriteHeader(http.StatusOK)
}

// IsRevoked reports whether the certificate with the given SHA-256 DER fingerprint
// (lowercase hex, as certinfo.Inspect reports it) has been revoked through this
// server, along with its recorded serial. It lets a served deployment / test
// confirm the revocation took effect without reaching into server internals.
func (s *Server) IsRevoked(fingerprintHex string) (serial string, revoked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.revoked[fingerprintHex]
	return rec.serial, ok
}

// certFingerprint returns the SHA-256 fingerprint (lowercase hex) of a certificate
// DER, computed inside the crypto boundary (AN-3 — the acme package must not import
// crypto/*). Returns "" if the DER does not parse as a certificate.
func certFingerprint(der []byte) string {
	info, err := certinfo.Inspect(der)
	if err != nil {
		return ""
	}
	return info.SHA256Fingerprint
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
