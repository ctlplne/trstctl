// SPDX-License-Identifier: MPL-2.0

// Package acme is the built-in ACME (RFC 8555) server (F5). It serves the ACME
// directory, account, order, authorization, challenge, finalize, and certificate
// endpoints, verifying each client request's JWS (via the internal/crypto/jose
// boundary) and enforcing single-use nonces. On finalize it brokers the CSR to a
// configured upstream certificate authority (the ca.CA interface — the built-in
// CA or a CA plugin such as Let's Encrypt). Challenge validation is pluggable
// (a real HTTP-01 validator ships in validate.go).
//
// Served deployments attach the source-of-truth event log with WithStateLog; the
// in-process maps are then a replayed serving view, not the durable truth. This
// package handles no crypto/* directly.
package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
)

const (
	maxJWSBody = 1 << 20

	statusPending = "pending"
	statusReady   = "ready"
	statusValid   = "valid"
	// statusProcessing is RFC 8555's state for an order whose finalize is in
	// flight. It exists here to CLAIM an order atomically, so two concurrent
	// finalize requests cannot both observe "ready" and both mint.
	statusProcessing = "processing"

	// ariRetryAfterSeconds is how long an ARI client should wait before polling
	// renewalInfo again (RFC 9773 Retry-After), here 6 hours.
	ariRetryAfterSeconds = 6 * 60 * 60
)

// QuotaConfig bounds public ACME state. A served deployment gets one ACME server
// per tenant mount, so these limits are tenant-local; source limits are keyed by
// the request peer address and account limits are keyed by the ACME account URL.
type QuotaConfig struct {
	MaxNonces                  int
	MaxAccounts                int
	MaxPendingOrders           int
	MaxPendingAuthorizations   int
	MaxPendingChallenges       int
	MaxPendingOrdersPerAccount int
	MaxNewOrdersPerAccount     int
	MaxNewNoncesPerSource      int
	MaxNewAccountsPerSource    int
	MaxNewOrdersPerSource      int
	SourceWindow               time.Duration
	NonceTTL                   time.Duration
	StateTTL                   time.Duration
}

// DefaultQuotaConfig returns conservative in-process caps for the public ACME
// surface. The durable ACME state finding is separate; these caps prevent the
// memory-only view from growing without an abuse budget.
func DefaultQuotaConfig() QuotaConfig {
	return QuotaConfig{
		MaxNonces:                  4096,
		MaxAccounts:                2048,
		MaxPendingOrders:           4096,
		MaxPendingAuthorizations:   8192,
		MaxPendingChallenges:       24576,
		MaxPendingOrdersPerAccount: 128,
		MaxNewOrdersPerAccount:     100,
		MaxNewNoncesPerSource:      120,
		MaxNewAccountsPerSource:    20,
		MaxNewOrdersPerSource:      60,
		SourceWindow:               10 * time.Minute,
		NonceTTL:                   10 * time.Minute,
		StateTTL:                   24 * time.Hour,
	}
}

func normalizeQuota(q QuotaConfig) QuotaConfig {
	d := DefaultQuotaConfig()
	if q.MaxNonces <= 0 {
		q.MaxNonces = d.MaxNonces
	}
	if q.MaxAccounts <= 0 {
		q.MaxAccounts = d.MaxAccounts
	}
	if q.MaxPendingOrders <= 0 {
		q.MaxPendingOrders = d.MaxPendingOrders
	}
	if q.MaxPendingAuthorizations <= 0 {
		q.MaxPendingAuthorizations = d.MaxPendingAuthorizations
	}
	if q.MaxPendingChallenges <= 0 {
		q.MaxPendingChallenges = d.MaxPendingChallenges
	}
	if q.MaxPendingOrdersPerAccount <= 0 {
		q.MaxPendingOrdersPerAccount = d.MaxPendingOrdersPerAccount
	}
	if q.MaxNewOrdersPerAccount <= 0 {
		q.MaxNewOrdersPerAccount = d.MaxNewOrdersPerAccount
	}
	if q.MaxNewNoncesPerSource <= 0 {
		q.MaxNewNoncesPerSource = d.MaxNewNoncesPerSource
	}
	if q.MaxNewAccountsPerSource <= 0 {
		q.MaxNewAccountsPerSource = d.MaxNewAccountsPerSource
	}
	if q.MaxNewOrdersPerSource <= 0 {
		q.MaxNewOrdersPerSource = d.MaxNewOrdersPerSource
	}
	if q.SourceWindow <= 0 {
		q.SourceWindow = d.SourceWindow
	}
	if q.NonceTTL <= 0 {
		q.NonceTTL = d.NonceTTL
	}
	if q.StateTTL <= 0 {
		q.StateTTL = d.StateTTL
	}
	return q
}

type account struct {
	id      string // thumbprint
	url     string
	key     *jose.ACMEKey
	jwk     json.RawMessage // public JWK needed to rebuild account verification after restart
	contact []string        // RFC 8555 §7.1.2 account contact URLs (e.g. mailto:)
	status  string          // "valid" (the only state this server tracks)
	// eabKeyID is the external account credential that authorized this account
	// (RFC 8555 §7.3.4, epic B4). Empty when the deployment does not use EAB.
	// It is what every order under this account is then scoped against, so it
	// travels in the account's state event and survives a replay.
	eabKeyID string
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

// DNS01Automation publishes the DNS-01 TXT record needed for a challenge and
// returns a cleanup function that retracts it. Served deployments implement this
// with tenant provider configs plus the outbox; library embeds can leave it nil
// and publish records out of band.
type DNS01Automation interface {
	Present(ctx context.Context, tenantID, domain, token, keyAuth string) (cleanup func(context.Context) error, err error)
}

// DomainValidationPolicy constrains the ACME challenge methods for a managed
// domain. constrained=false means no tenant policy applies and the RFC 8555
// default challenge set remains available.
type DomainValidationPolicy interface {
	AllowedMethods(ctx context.Context, tenantID, domain string) (methods []string, constrained bool, err error)
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
	createdAt  time.Time
}

type order struct {
	id                string
	accountURL        string
	domains           []string
	authzIDs          []string
	status            string
	authMode          profile.ACMEAuthMode
	certID            string
	replaces          string // ARI: the certificate identifier this order renews (RFC 9773)
	attestedKeySHA256 string
	createdAt         time.Time
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

type sourceBudget struct {
	resetAt    time.Time
	newNonce   int
	newAccount int
	newOrder   int
}

// Server is the built-in ACME server. Construct it with New and mount it as an
// http.Handler.
type Server struct {
	ca        ca.CA
	validator Validator

	meta     DirectoryMeta
	authMode profile.ACMEAuthMode

	// onFailure receives a diagnosis for every refusal this server issues
	// (epic I4). Nil disables it.
	//
	// Hooked at problem() rather than at each refusal site because problem() is
	// the single place every ACME failure passes through — the diagnosis
	// therefore cannot miss a path, and a new refusal added later is diagnosed
	// without anybody remembering to wire it.
	onFailure func(context.Context, enrollmentdiag.Diagnosis)

	mu         sync.Mutex
	quota      QuotaConfig
	nonces     map[string]time.Time
	accounts   map[string]*account // by URL
	byKey      map[string]*account // by thumbprint (registration idempotency)
	orders     map[string]*order
	authzs     map[string]*authorization
	challenges map[string]*challenge
	certs      map[string][]byte
	issued     map[string]*issuedCert // by SHA-256 fingerprint (hex) of the leaf DER
	// certOwner indexes certID -> owning account URL, written at the
	// event-apply site so it is rebuilt naturally on replay/restore. getCert
	// ownership is O(1) instead of a full scan of every certificate ever
	// issued under the global lock (AUD-201 follow-up G2/V31). Never pruned,
	// mirroring issued.
	certOwner  map[string]string
	revoked    map[string]revocation // by SHA-256 fingerprint (hex); presence == revoked
	ariWindows map[string]ariWindow  // ARI: certID -> validity span (RFC 9773)
	earlyRenew map[string]bool       // ARI: certIDs flagged for proactive renewal
	sources    map[string]*sourceBudget
	seq        int

	revokeHook              RevocationHook
	accountLimiter          AccountOrderLimiter
	dns01Automation         DNS01Automation
	dvPolicy                DomainValidationPolicy
	deviceAttestationPolicy DeviceAttestationPolicySource
	deviceAttestNow         func() time.Time
	stateLog                eventLog
	stateTenantID           string
	eabCredentials          map[string]*eabCredential

	mux *http.ServeMux
}

// New returns an ACME server brokering issuance to ca, validating challenges with
// validator.
func New(ca ca.CA, validator Validator) *Server {
	s := &Server{
		ca: ca, validator: validator,
		authMode: profile.ACMEAuthModePublicTrust,
		quota:    DefaultQuotaConfig(),
		nonces:   map[string]time.Time{}, accounts: map[string]*account{}, byKey: map[string]*account{},
		orders: map[string]*order{}, authzs: map[string]*authorization{},
		challenges: map[string]*challenge{}, certs: map[string][]byte{},
		issued: map[string]*issuedCert{}, revoked: map[string]revocation{},
		certOwner:  map[string]string{},
		ariWindows: map[string]ariWindow{}, earlyRenew: map[string]bool{},
		sources:         map[string]*sourceBudget{},
		accountLimiter:  newMemoryAccountOrderLimiter(),
		deviceAttestNow: time.Now,
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

// WithQuota installs public ACME abuse budgets and lifecycle caps. It returns s
// for chaining and is safe to call once immediately after New, before serving.
func (s *Server) WithQuota(q QuotaConfig) *Server {
	s.quota = normalizeQuota(q)
	return s
}

// WithAccountOrderLimiter installs the account-keyed order/hour limiter. Served
// deployments pass a PostgreSQL-backed limiter; tests and embedded uses default to
// a process-local token bucket.
func (s *Server) WithAccountOrderLimiter(l AccountOrderLimiter) *Server {
	s.accountLimiter = l
	return s
}

// WithDNS01Automation wires managed DNS-01 publish/cleanup for served
// deployments. Nil leaves the ACME server's RFC 8555 behavior unchanged:
// clients/operators must publish DNS-01 TXT records out of band before accepting
// the challenge.
func (s *Server) WithDNS01Automation(a DNS01Automation) *Server {
	s.dns01Automation = a
	return s
}

// WithDomainValidationPolicy wires tenant-managed DV method policy into new-order
// challenge selection and challenge acceptance. Nil preserves the library default:
// every public-trust order offers HTTP-01, DNS-01, and TLS-ALPN-01.
func (s *Server) WithDomainValidationPolicy(p DomainValidationPolicy) *Server {
	s.dvPolicy = p
	return s
}

// WithDeviceAttestationPolicy opts this ACME mount into profile-scoped
// device-attest-01. Nil/default construction offers only the existing DV
// challenges.
func (s *Server) WithDeviceAttestationPolicy(p DeviceAttestationPolicySource) *Server {
	s.deviceAttestationPolicy = p
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

// WithExternalAccountBindings installs the ACME External Account Binding key set
// (RFC 8555 §7.3.4). When required is true, newAccount must carry a valid EAB JWS.
// Keys are copied into locked memory; call Destroy when the server is shut down.
func (s *Server) WithExternalAccountBindings(required bool, keys []ExternalAccountBindingKey) (*Server, error) {
	next := make(map[string]*eabCredential, len(keys))
	for _, key := range keys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			destroyEABCredentials(next)
			return nil, errors.New("acme: external account binding key id is required")
		}
		if _, dup := next[keyID]; dup {
			destroyEABCredentials(next)
			return nil, fmt.Errorf("acme: duplicate external account binding key id %q", keyID)
		}
		if len(key.HMACKey) < 16 {
			destroyEABCredentials(next)
			return nil, fmt.Errorf("acme: external account binding key %q must be at least 16 bytes", keyID)
		}
		buf, err := secret.NewFrom(key.HMACKey)
		if err != nil {
			destroyEABCredentials(next)
			return nil, fmt.Errorf("acme: external account binding key %q: %w", keyID, err)
		}
		next[keyID] = &eabCredential{keyID: keyID, key: buf, policy: key.Policy}
	}
	if required && len(next) == 0 {
		return nil, errors.New("acme: external account binding required with no keys")
	}

	s.mu.Lock()
	old := s.eabCredentials
	s.eabCredentials = next
	s.meta.ExternalAccountRequired = required
	s.mu.Unlock()
	destroyEABCredentials(old)
	return s, nil
}

// Destroy wipes ACME server secret material. It is safe to call more than once.
func (s *Server) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	creds := s.eabCredentials
	s.eabCredentials = nil
	s.mu.Unlock()
	destroyEABCredentials(creds)
}

func destroyEABCredentials(creds map[string]*eabCredential) {
	for _, cred := range creds {
		if cred != nil && cred.key != nil {
			cred.key.Destroy()
		}
	}
}

// WithCertificateProfile sets the profile policy this ACME mount serves. trstctl
// defaults to public_trust (full DV); trust_authenticated is an explicit internal
// PKI profile choice and never falls out of an empty profile field.
func (s *Server) WithCertificateProfile(p profile.CertificateProfile) (*Server, error) {
	mode, err := profile.NormalizeACMEAuthMode(p.ACMEAuthMode)
	if err != nil {
		return nil, err
	}
	s.authMode = mode
	return s, nil
}

// WithRevocationHook installs the served-platform revocation effect. The hook is
// invoked only after ACME revokeCert authorization succeeds; if it fails, revokeCert
// fails and the in-memory ACME state is not marked revoked.
func (s *Server) WithRevocationHook(h RevocationHook) *Server {
	s.revokeHook = h
	return s
}

var errDVMethodNotAllowed = errors.New("acme: domain-validation method is not allowed")

func defaultChallengeTypes() []string {
	return []string{ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01}
}

func (s *Server) challengeTypesForDomain(ctx context.Context, domain string) ([]string, error) {
	var challengeTypes []string
	if s.dvPolicy == nil {
		challengeTypes = defaultChallengeTypes()
	} else {
		methods, constrained, err := s.dvPolicy.AllowedMethods(ctx, s.stateTenantID, domain)
		if err != nil {
			return nil, fmt.Errorf("acme: domain-validation policy lookup for %q: %w", domain, err)
		}
		if !constrained {
			challengeTypes = defaultChallengeTypes()
		} else {
			allowed := make(map[string]bool, len(methods))
			for _, method := range methods {
				method = strings.TrimSpace(method)
				if method == "" {
					continue
				}
				if !knownMethod(method) {
					return nil, fmt.Errorf("acme: domain-validation policy for %q returned unknown method %q", domain, method)
				}
				allowed[method] = true
			}
			for _, method := range defaultChallengeTypes() {
				if allowed[method] {
					challengeTypes = append(challengeTypes, method)
				}
			}
			if len(challengeTypes) == 0 {
				return nil, fmt.Errorf("%w for %q", errDVMethodNotAllowed, domain)
			}
		}
	}
	if _, enabled, err := s.lookupDeviceAttestationPolicy(ctx, domain); err != nil {
		return nil, err
	} else if enabled {
		challengeTypes = append(challengeTypes, ChallengeDeviceAttest01)
	}
	return challengeTypes, nil
}

func (s *Server) challengeAllowed(ctx context.Context, domain, challengeType string) error {
	challengeTypes, err := s.challengeTypesForDomain(ctx, domain)
	if err != nil {
		return err
	}
	for _, allowed := range challengeTypes {
		if allowed == challengeType {
			return nil
		}
	}
	return fmt.Errorf("%w: %s for %q", errDVMethodNotAllowed, challengeType, domain)
}

func (s *Server) writeDVPolicyProblem(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errDVMethodNotAllowed) {
		s.problem(w, r, http.StatusBadRequest, "unauthorized", err.Error())
		return
	}
	s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
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

func requestURL(r *http.Request) string {
	// The enrollment relay preserves the stable public authority in Host while
	// dialing the control-plane upstream. RequestURI keeps the client's exact
	// escaped path/query spelling, so this is the same string the stock client
	// received from the directory/resource response and signed.
	requestTarget := r.RequestURI
	if requestTarget == "" {
		requestTarget = r.URL.RequestURI()
	}
	return baseURL(r) + requestTarget
}

func addLink(w http.ResponseWriter, target, rel string) {
	w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"%s\"", target, rel))
}

func addIndexLink(w http.ResponseWriter, r *http.Request) {
	addLink(w, baseURL(r)+"/directory", "index")
}

func (s *Server) nextID() string {
	s.seq++
	return fmt.Sprintf("%d", s.seq)
}

func (s *Server) mintNonce(now time.Time) (string, bool) {
	if len(s.nonces) >= s.quota.MaxNonces {
		return "", false
	}
	b, _ := crypto.RandomBytes(16)
	n := base64.RawURLEncoding.EncodeToString(b)
	s.nonces[n] = now
	return n, true
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

func (s *Server) newNonce(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	now := time.Now()
	s.pruneExpiredLocked(now)
	if !s.consumeSourceLocked(sourceKey(r), "nonce", now) {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many ACME newNonce requests from this source")
		return
	}
	nonce, ok := s.mintNonce(now)
	if !ok {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many outstanding ACME nonces")
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	addIndexLink(w, r)
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
		// RFC 8555 §6.4/6.4.1 binds the signed protected "url" string to
		// the exact HTTP request URL. Check it before touching the nonce: a
		// routing intermediary that changes path, authority, or scheme must not
		// redirect an otherwise valid account signature to another ACME action,
		// and its rejected attempt must not burn the client's one-use nonce.
		if msg.Protected.URL != requestURL(r) {
			s.problem(w, r, http.StatusUnauthorized, "unauthorized", "JWS protected url does not match request URL")
			return
		}

		s.mu.Lock()
		now := time.Now()
		s.pruneExpiredLocked(now)
		if _, ok := s.nonces[msg.Protected.Nonce]; !ok {
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
		now = time.Now()
		s.pruneExpiredLocked(now)
		nonce, ok := s.mintNonce(now)
		if !ok {
			s.mu.Unlock()
			s.rateLimited(w, r, "too many outstanding ACME nonces")
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		s.mu.Unlock()
		addIndexLink(w, r)
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
	now := time.Now()
	s.pruneExpiredLocked(now)
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
		if !s.consumeSourceLocked(sourceKey(r), "account", now) {
			s.mu.Unlock()
			s.rateLimited(w, r, "too many ACME account creations from this source")
			return
		}
		if len(s.accounts) >= s.quota.MaxAccounts {
			s.mu.Unlock()
			s.rateLimited(w, r, "too many ACME accounts on this tenant mount")
			return
		}
		// RFC 8555 §7.3.4: when configured, external account binding proves
		// this ACME account key was pre-authorized by an external account.
		if s.meta.ExternalAccountRequired && len(req.ExternalAccountBinding) == 0 {
			s.mu.Unlock()
			s.problem(w, r, http.StatusBadRequest, "externalAccountRequired", "this CA requires an external account binding")
			return
		}
		boundEABKeyID := ""
		var boundEABCredential *eabCredential
		if len(req.ExternalAccountBinding) > 0 {
			eab, err := jose.ParseACMEJWS(req.ExternalAccountBinding)
			if err != nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusBadRequest, "malformed", "cannot parse external account binding")
				return
			}
			keyID := strings.TrimSpace(eab.Protected.Kid)
			cred := s.eabCredentials[keyID]
			if cred == nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusUnauthorized, "unauthorized", "unknown external account binding key id")
				return
			}
			// The credential's own state gates the door before the MAC is even
			// checked: a disabled, expired, or exhausted credential admits nothing
			// (B4). Refusing here rather than at the first order means the client
			// learns immediately, and the certificates already issued under this
			// credential are untouched.
			if ok, reason := cred.active(time.Now()); !ok {
				s.mu.Unlock()
				s.problem(w, r, http.StatusUnauthorized, "unauthorized", reason)
				return
			}
			macKey := cred.key.Bytes()
			if macKey == nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusInternalServerError, "serverInternal", "external account binding key is unavailable")
				return
			}
			if err := eab.VerifyExternalAccountBinding(macKey, keyID, baseURL(r)+"/acme/new-account", thumb); err != nil {
				s.mu.Unlock()
				s.problem(w, r, http.StatusUnauthorized, "unauthorized", "external account binding verification failed")
				return
			}
			// Keep the kid. Discarding it here is what made every admitted account
			// identical and left nothing to scope, count, or switch off.
			boundEABKeyID, boundEABCredential = keyID, cred
		}
		acct = &account{
			id: thumb, url: baseURL(r) + "/acme/acct/" + s.nextID(), key: key,
			jwk: copyRawMessage(msg.Protected.JWK), contact: req.Contact, status: statusValid,
			eabKeyID: boundEABKeyID,
		}
		if err := s.appendStateEventLocked(r.Context(), acmeEventAccountUpserted, accountEventFrom(acct, s.seq)); err != nil {
			s.mu.Unlock()
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
		s.byKey[thumb] = acct
		s.accounts[acct.url] = acct
		if boundEABCredential != nil {
			boundEABCredential.recordAccountBound(time.Now())
		}
	} else if len(req.Contact) > 0 {
		// Update contact on a returning registration (§7.3.2 allows contact update).
		updated := *acct
		updated.contact = append([]string(nil), req.Contact...)
		if len(updated.jwk) == 0 {
			updated.jwk = copyRawMessage(msg.Protected.JWK)
		}
		if err := s.appendStateEventLocked(r.Context(), acmeEventAccountUpserted, accountEventFrom(&updated, 0)); err != nil {
			s.mu.Unlock()
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
		acct.contact = updated.contact
		acct.jwk = updated.jwk
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
	if acct == nil {
		s.problem(w, r, http.StatusUnauthorized, "unauthorized", "newOrder requires an existing account (kid)")
		return
	}
	req, err := ParseOrderRequest(msg.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	// The credential that admitted this account decides what it may ask for
	// (B4). This runs before any work is done and before any rate limiter, so a
	// denial costs nothing and is recorded against the credential rather than
	// disappearing into a generic rejection.
	eabCred, eabDenial := s.authorizeOrderAgainstEAB(acct, req)
	if eabDenial != "" {
		if eabCred != nil {
			eabCred.recordDenial(time.Now())
		}
		s.recordEABOrderDenial(r.Context(), acct, req, eabDenial)
		s.problem(w, r, http.StatusForbidden, "unauthorized", eabDenial)
		return
	}
	if s.quota.MaxNewOrdersPerAccount > 0 && s.accountLimiter != nil {
		allowed, retryAfter, err := s.accountLimiter.AllowNewOrder(r.Context(), s.stateTenantID, acct.url, s.quota.MaxNewOrdersPerAccount)
		if err != nil {
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
		if !allowed {
			s.rateLimitedAfter(w, r, retryAfter, "too many ACME newOrder requests for this account")
			return
		}
	}
	authMode := s.authMode
	if authMode == "" {
		authMode = profile.ACMEAuthModePublicTrust
	}
	challengeTypesByDomain := make(map[string][]string, len(req.Identifiers))
	pendingChallengeDelta := 0
	if authMode == profile.ACMEAuthModeTrustAuthenticated {
		pendingChallengeDelta = 0
	} else {
		for _, id := range req.Identifiers {
			challengeTypes, err := s.challengeTypesForDomain(r.Context(), id.Value)
			if err != nil {
				s.writeDVPolicyProblem(w, r, err)
				return
			}
			challengeTypesByDomain[id.Value] = challengeTypes
			pendingChallengeDelta += len(challengeTypes)
		}
	}
	base := baseURL(r)
	s.mu.Lock()
	now := time.Now()
	s.pruneExpiredLocked(now)
	if !s.consumeSourceLocked(sourceKey(r), "order", now) {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many ACME newOrder requests from this source")
		return
	}
	if s.pendingOrdersLocked("") >= s.quota.MaxPendingOrders {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many pending ACME orders")
		return
	}
	if s.pendingOrdersLocked(acct.url) >= s.quota.MaxPendingOrdersPerAccount {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many pending ACME orders for this account")
		return
	}
	pendingAuthzDelta := len(req.Identifiers)
	if authMode == profile.ACMEAuthModeTrustAuthenticated {
		pendingAuthzDelta = 0
	}
	if s.pendingAuthzsLocked()+pendingAuthzDelta > s.quota.MaxPendingAuthorizations {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many pending ACME authorizations")
		return
	}
	if s.pendingChallengesLocked()+pendingChallengeDelta > s.quota.MaxPendingChallenges {
		s.mu.Unlock()
		s.rateLimited(w, r, "too many pending ACME challenges")
		return
	}
	orderStatus := statusPending
	authzStatus := statusPending
	challengeStatus := statusPending
	if authMode == profile.ACMEAuthModeTrustAuthenticated {
		orderStatus = statusReady
		authzStatus = statusValid
		challengeStatus = statusValid
	}
	o := &order{id: s.nextID(), accountURL: acct.url, status: orderStatus, authMode: authMode, replaces: req.Replaces, createdAt: now}
	var authzURLs []string
	var authzs []*authorization
	for _, id := range req.Identifiers {
		o.domains = append(o.domains, id.Value)
		az := &authorization{id: s.nextID(), orderID: o.id, domain: id.Value, status: authzStatus, createdAt: now}
		challengeTypes := challengeTypesByDomain[id.Value]
		if authMode == profile.ACMEAuthModeTrustAuthenticated {
			challengeTypes = []string{ChallengeHTTP01}
		}
		for _, ct := range challengeTypes {
			ch := &challenge{id: s.nextID(), typ: ct, token: randomToken(), status: challengeStatus, authzID: az.id}
			az.challenges = append(az.challenges, ch)
		}
		authzs = append(authzs, az)
		o.authzIDs = append(o.authzIDs, az.id)
		authzURLs = append(authzURLs, base+"/acme/authz/"+az.id)
	}
	if err := s.appendStateEventLocked(r.Context(), acmeEventOrderCreated, orderCreatedEventFrom(o, authzs, s.seq)); err != nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	for _, az := range authzs {
		s.authzs[az.id] = az
		for _, ch := range az.challenges {
			s.challenges[ch.id] = ch
		}
	}
	s.orders[o.id] = o
	orderURL := base + "/acme/order/" + o.id
	s.mu.Unlock()

	// Count the order against the credential only once it exists, so a rejected
	// or failed order does not consume quota an operator granted (B4).
	if eabCred != nil {
		eabCred.recordOrder(time.Now())
	}

	w.Header().Set("Location", orderURL)
	writeJSON(w, http.StatusCreated, s.orderJSON(base, o, authzURLs))
}

func (s *Server) getAuthz(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, acct *account) {
	base := baseURL(r)
	s.mu.Lock()
	az := s.authzs[r.PathValue("id")]
	var owner string
	if az != nil {
		if o := s.orders[az.orderID]; o != nil {
			owner = o.accountURL
		}
	}
	s.mu.Unlock()
	if az == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	if !s.accountOwns(owner, acct) {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	writeJSON(w, http.StatusOK, s.authzJSON(base, az))
}

func (s *Server) acceptChallenge(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	base := baseURL(r)
	s.mu.Lock()
	ch := s.challenges[r.PathValue("id")]
	if ch == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	az := s.authzs[ch.authzID]
	if az == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	o := s.orders[az.orderID]
	if o == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such order")
		return
	}
	// Responding to a challenge is scoped to the account that owns it (RFC 8555
	// §7.5.1), same as fetching the order, authorization or certificate. Those
	// three check ownership and this one did not, so any registered account could
	// drive validation state on another account's authorization by challenge ID —
	// and for device-attest-01, bind its own key attestation to that
	// authorization. Checked under the lock, before anything is acted on. 404
	// rather than 403: a non-owner should not learn the challenge exists.
	if !s.accountOwns(o.accountURL, acct) {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	s.mu.Unlock()
	r = withACMEDiagnosticIdentity(r, "dns:"+strings.ToLower(strings.TrimSpace(az.domain)))

	if err := s.challengeAllowed(r.Context(), az.domain, ch.typ); err != nil {
		s.writeDVPolicyProblem(w, r, err)
		return
	}

	var attestedKeyDigest []byte
	var cleanup func(context.Context) error
	if ch.typ == ChallengeDeviceAttest01 {
		var err error
		attestedKeyDigest, err = s.validateDeviceAttestation(r.Context(), msg, acct, ch, az, o)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "unauthorized", "challenge validation failed: "+err.Error())
			return
		}
	} else {
		keyAuth := ch.token + "." + acct.key.Thumbprint()
		if ch.typ == ChallengeDNS01 && s.dns01Automation != nil {
			var err error
			cleanup, err = s.dns01Automation.Present(r.Context(), s.stateTenantID, az.domain, ch.token, keyAuth)
			if err != nil {
				s.problem(w, r, http.StatusBadRequest, "unauthorized", "challenge validation failed: "+err.Error())
				return
			}
		}
		validateErr := s.validator.Validate(r.Context(), ch.typ, az.domain, ch.token, keyAuth)
		if cleanup != nil && validateErr != nil {
			_ = cleanup(context.WithoutCancel(r.Context()))
		}
		if validateErr != nil {
			s.problem(w, r, http.StatusBadRequest, "unauthorized", "challenge validation failed: "+validateErr.Error())
			return
		}
	}

	s.mu.Lock()
	ch = s.challenges[r.PathValue("id")]
	if ch == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	if ch.status != statusPending {
		s.mu.Unlock()
		s.problem(w, r, http.StatusBadRequest, "unauthorized", "challenge is not pending")
		return
	}
	az = s.authzs[ch.authzID]
	if az == nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	o = s.orders[az.orderID]
	orderStatus := ""
	if o != nil {
		orderStatus = o.status
		ready := true
		for _, id := range o.authzIDs {
			if id == az.id {
				continue
			}
			if other := s.authzs[id]; other == nil || other.status != statusValid {
				ready = false
				break
			}
		}
		if ready {
			orderStatus = statusReady
		}
	}
	event := challengeValidatedEventFrom(ch, az, o, orderStatus)
	if len(attestedKeyDigest) > 0 {
		event.AttestedKeySHA256 = base64.RawURLEncoding.EncodeToString(attestedKeyDigest)
	}
	if err := s.appendStateEventLocked(r.Context(), acmeEventChallengeValidated, event); err != nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	ch.status = statusValid
	az.status = statusValid
	if o := s.orders[az.orderID]; o != nil {
		if event.AttestedKeySHA256 != "" {
			o.attestedKeySHA256 = event.AttestedKeySHA256
		}
		if s.allAuthzValid(o) {
			o.status = statusReady
		}
	}
	s.mu.Unlock()

	if cleanup != nil {
		_ = cleanup(context.WithoutCancel(r.Context()))
	}
	addLink(w, base+"/acme/authz/"+az.id, "up")
	writeJSON(w, http.StatusOK, map[string]any{
		"type": ch.typ, "url": base + "/acme/chal/" + ch.id, "token": ch.token, "status": ch.status,
	})
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, acct *account) {
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
	if !s.accountOwns(o.accountURL, acct) {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such order")
		return
	}
	writeJSON(w, http.StatusOK, s.orderJSON(base, o, authzURLs))
}

func (s *Server) finalize(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	base := baseURL(r)
	s.mu.Lock()
	o := s.orders[r.PathValue("id")]
	// RFC 8555 objects belong to the account that created them, and the check
	// runs INSIDE the locked block BEFORE any state changes (AUD-201 follow-up
	// G1/V15): the claim used to flip statusReady -> statusProcessing first and
	// verify ownership only after unlocking, so a non-owner — order IDs are
	// sequential and guessable, and acct can even be nil for jwk-signed posts —
	// could repeatedly flip a victim's ready order into processing and starve
	// the owner's own finalize with 403 orderNotReady. The denial is
	// deliberately indistinguishable from "no such order" so the endpoint is
	// not an existence oracle.
	if o == nil || !s.accountOwns(o.accountURL, acct) {
		s.mu.Unlock()
		s.problem(w, r, http.StatusNotFound, "malformed", "no such order")
		return
	}
	replayValid := o.status == statusValid && o.certID != ""
	var replayAuthzURLs []string
	if replayValid {
		replayAuthzURLs = s.orderAuthzURLs(base, o)
	}
	// Claim the order while still holding the lock. The readiness check used to
	// happen AFTER this unlock, so two concurrent finalize requests both saw
	// "ready" and both went on to mint — one order, two certificates. Flipping
	// the status here makes the claim atomic: the loser sees "processing".
	claimed := false
	if !replayValid && o.status == statusReady {
		o.status = statusProcessing
		claimed = true
	}
	// Capture the status for the not-ready branch while the lock is held — the
	// old code re-read o.status after unlocking, a data race.
	statusAtClaim := o.status
	s.mu.Unlock()
	// Release the claim if this request does not go on to issue, so a transient
	// failure does not wedge the order in "processing" forever.
	issued := false
	defer func() {
		if claimed && !issued {
			s.mu.Lock()
			if o.status == statusProcessing {
				o.status = statusReady
			}
			s.mu.Unlock()
		}
	}()
	if replayValid {
		writeJSON(w, http.StatusOK, s.orderJSON(base, o, replayAuthzURLs))
		return
	}
	if !claimed {
		if statusAtClaim == statusProcessing {
			s.problem(w, r, http.StatusForbidden, "orderNotReady", "order finalization is already in progress")
			return
		}
		s.problem(w, r, http.StatusForbidden, "orderNotReady", "order is not ready to finalize")
		return
	}
	csr, err := ParseFinalizeRequest(msg.Payload)
	if err != nil {
		s.problem(w, r, http.StatusBadRequest, "badCSR", err.Error())
		return
	}
	if o.attestedKeySHA256 != "" {
		digest, err := deviceattest.CSRPublicKeySHA256(csr)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "badCSR", err.Error())
			return
		}
		if base64.RawURLEncoding.EncodeToString(digest) != o.attestedKeySHA256 {
			s.problem(w, r, http.StatusBadRequest, "badCSR", "finalize CSR does not contain the attested key")
			return
		}
	}

	// RFC 8555 §7.4: the finalize CSR MUST indicate the exact same set of
	// identifiers as the order. Without this the order's validated identifiers
	// are advisory — DNSNames below is passed to the CA but every in-process CA
	// takes its names from the CSR (internal/ca/ca.go documents exactly that),
	// so an account that validated one domain it controls could finalize with a
	// CSR for any other name and receive a certificate for it.
	//
	// This reads the CSR's names but does NOT verify its signature, so the
	// opaque-bytes seam is intact: proof-of-possession remains the licensed
	// issuer's job, and a CSR whose subject algorithm the core parser cannot
	// verify still reaches the CA unchanged.
	if err := csrIdentifiersMatchOrder(csr, o.domains); err != nil {
		s.problem(w, r, http.StatusBadRequest, "badCSR", err.Error())
		return
	}

	cert, err := s.ca.Issue(r.Context(), ca.IssueRequest{CSR: csr, DNSNames: o.domains, TTL: 90 * 24 * time.Hour})
	if err != nil {
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", "issuance failed: "+err.Error())
		return
	}

	s.mu.Lock()
	certID := s.nextID()
	payload := certificateIssuedEventFrom(o.id, certID, acct.url, cert.CertificatePEM, cert.Serial, s.seq)
	if err := s.appendStateEventLocked(r.Context(), acmeEventCertificateIssued, payload); err != nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	if err := s.applyCertificateIssuedEventLocked(payload); err != nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	authzURLs := s.orderAuthzURLs(base, o)
	// The claim taken at entry is now consumed: applyCertificateIssuedEventLocked
	// has moved the order to its issued state, so the deferred release must not
	// put it back to "ready".
	issued = true
	s.mu.Unlock()

	w.Header().Set("Location", base+"/acme/order/"+o.id)
	writeJSON(w, http.StatusOK, s.orderJSON(base, o, authzURLs))
}

func (s *Server) orderAuthzURLs(base string, o *order) []string {
	authzURLs := make([]string, 0, len(o.authzIDs))
	for _, id := range o.authzIDs {
		authzURLs = append(authzURLs, base+"/acme/authz/"+id)
	}
	return authzURLs
}

func (s *Server) getCert(w http.ResponseWriter, r *http.Request, _ *jose.ACMEMessage, acct *account) {
	certID := r.PathValue("id")
	s.mu.Lock()
	pem := s.certs[certID]
	owner, known := s.certOwner[certID]
	s.mu.Unlock()
	if pem == nil {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such certificate")
		return
	}
	// A certificate with no recorded issuing account cannot be shown to be the
	// caller's, so it is not served rather than served to everyone.
	if !known || !s.accountOwns(owner, acct) {
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
	updated := *acct
	updated.id = newThumb
	updated.key = newKey
	updated.jwk = copyRawMessage(inner.Protected.JWK)
	if err := s.appendStateEventLocked(r.Context(), acmeEventAccountUpserted, accountEventFrom(&updated, 0)); err != nil {
		s.mu.Unlock()
		s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	delete(s.byKey, acct.key.Thumbprint())
	acct.key = newKey
	acct.id = newThumb
	acct.jwk = updated.jwk
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
		payload := acmeCertificateRevokedEvent{Fingerprint: fp, Serial: ic.serial, Reason: req.Reason, At: revokedAt}
		if err := s.appendStateEventLocked(r.Context(), acmeEventCertificateRevoked, payload); err != nil {
			s.mu.Unlock()
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
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
	info, ok := s.LookupRenewalInfo(certid, time.Now())
	if !ok {
		s.problem(w, r, http.StatusNotFound, "malformed", "no renewal information for this certificate")
		return
	}
	w.Header().Set("Retry-After", strconv.Itoa(ariRetryAfterSeconds))
	w.Header().Set("Cache-Control", "no-store")
	addIndexLink(w, r)
	writeJSON(w, http.StatusOK, info)
}

// LookupRenewalInfo returns exactly the renewal information the public
// renewalInfo handler would publish for certID at the supplied time. It is a
// read-only operator-observability seam: callers can distinguish an actually
// published window from one they could merely compute from certificate dates.
func (s *Server) LookupRenewalInfo(certID string, at time.Time) (ari.RenewalInfo, bool) {
	if !ari.ValidCertID(certID) {
		return ari.RenewalInfo{}, false
	}
	s.mu.Lock()
	win, ok := s.ariWindows[certID]
	early := s.earlyRenew[certID]
	s.mu.Unlock()
	if !ok {
		return ari.RenewalInfo{}, false
	}
	return ari.RenewalInfo{SuggestedWindow: ari.SuggestWindow(win.notBefore, win.notAfter, at, early)}, true
}

// MarkEarlyRenewal flags a certificate (by its ARI certificate identifier) for
// proactive renewal — the renewalInfo window for it then starts immediately. This
// is how a mass-revocation event signals clients to renew ahead of schedule.
func (s *Server) MarkEarlyRenewal(certID string) {
	_ = s.MarkEarlyRenewalContext(context.Background(), certID)
}

// MarkEarlyRenewalContext is MarkEarlyRenewal with explicit append context for
// served deployments that persist ACME ARI state through the event log.
func (s *Server) MarkEarlyRenewalContext(ctx context.Context, certID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.earlyRenew[certID] {
		return nil
	}
	if err := s.appendStateEventLocked(ctx, acmeEventEarlyRenewalMarked, acmeEarlyRenewalEvent{CertID: certID}); err != nil {
		return err
	}
	s.earlyRenew[certID] = true
	return nil
}

func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func (s *Server) consumeSourceLocked(source, kind string, now time.Time) bool {
	b := s.sources[source]
	if b == nil || !now.Before(b.resetAt) {
		b = &sourceBudget{resetAt: now.Add(s.quota.SourceWindow)}
		s.sources[source] = b
	}
	switch kind {
	case "nonce":
		if b.newNonce >= s.quota.MaxNewNoncesPerSource {
			return false
		}
		b.newNonce++
	case "account":
		if b.newAccount >= s.quota.MaxNewAccountsPerSource {
			return false
		}
		b.newAccount++
	case "order":
		if b.newOrder >= s.quota.MaxNewOrdersPerSource {
			return false
		}
		b.newOrder++
	}
	return true
}

func (s *Server) pruneExpiredLocked(now time.Time) {
	for nonce, created := range s.nonces {
		if !created.IsZero() && now.Sub(created) > s.quota.NonceTTL {
			delete(s.nonces, nonce)
		}
	}
	for source, budget := range s.sources {
		if budget == nil || !now.Before(budget.resetAt) {
			delete(s.sources, source)
		}
	}
	for id, o := range s.orders {
		if o == nil || o.status == statusValid || now.Sub(o.createdAt) <= s.quota.StateTTL {
			continue
		}
		s.deleteOrderStateLocked(id)
	}
}

func (s *Server) deleteOrderStateLocked(orderID string) {
	o := s.orders[orderID]
	if o == nil {
		return
	}
	for _, authzID := range o.authzIDs {
		if az := s.authzs[authzID]; az != nil {
			for _, ch := range az.challenges {
				delete(s.challenges, ch.id)
			}
		}
		delete(s.authzs, authzID)
	}
	delete(s.orders, orderID)
}

func (s *Server) pendingOrdersLocked(accountURL string) int {
	n := 0
	for _, o := range s.orders {
		if o == nil || o.status == statusValid {
			continue
		}
		if accountURL == "" || o.accountURL == accountURL {
			n++
		}
	}
	return n
}

func (s *Server) pendingAuthzsLocked() int {
	n := 0
	for _, az := range s.authzs {
		if az != nil && az.status != statusValid {
			n++
		}
	}
	return n
}

func (s *Server) pendingChallengesLocked() int {
	n := 0
	for _, ch := range s.challenges {
		if ch == nil || ch.status == statusValid {
			continue
		}
		if az := s.authzs[ch.authzID]; az != nil && az.status == statusValid {
			continue
		}
		n++
	}
	return n
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

func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, detail string) {
	s.rateLimitedAfter(w, r, s.quota.SourceWindow, detail)
}

func (s *Server) rateLimitedAfter(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, detail string) {
	retry := int(math.Ceil(retryAfter.Seconds()))
	if retry <= 0 {
		retry = 60
	}
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	s.problem(w, r, http.StatusTooManyRequests, "rateLimited", detail)
}

func (s *Server) problem(w http.ResponseWriter, r *http.Request, status int, typ, detail string) {
	s.mu.Lock()
	notify := s.onFailure
	s.mu.Unlock()
	if notify != nil {
		// The step comes from the path the client was on, which is the only
		// evidence available here about where in the flow this happened.
		diagnosis := enrollmentdiag.ClassifyACME(acmeStepForPath(r), typ, nil).WithEvidence(enrollmentdiag.Evidence{
			OperationRef: r.Method + " " + r.URL.Path,
			IdentityRef:  acmeIdentityRef(r), EndpointRef: strings.TrimSpace(r.Host),
		})
		notify(r.Context(), diagnosis)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status,
	})
}

type acmeDiagnosticIdentityContextKey struct{}

func withACMEDiagnosticIdentity(r *http.Request, identityRef string) *http.Request {
	if r == nil || strings.TrimSpace(identityRef) == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), acmeDiagnosticIdentityContextKey{}, identityRef))
}

func acmeIdentityRef(r *http.Request) string {
	if r == nil {
		return ""
	}
	if identityRef, _ := r.Context().Value(acmeDiagnosticIdentityContextKey{}).(string); identityRef != "" {
		return identityRef
	}
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	id := parts[len(parts)-1]
	if id == "" {
		return ""
	}
	switch {
	case strings.Contains(r.URL.Path, "/challenge/"):
		return "challenge:" + id
	case strings.Contains(r.URL.Path, "/authz/"):
		return "authorization:" + id
	case strings.Contains(r.URL.Path, "/order/"), strings.Contains(r.URL.Path, "/finalize/"):
		return "order:" + id
	case strings.Contains(r.URL.Path, "/certificate/"):
		return "certificate:" + id
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SetFailureDiagnosis records a diagnosis for every refusal this server issues
// (epic I4).
//
// A setter rather than a constructor option, because New has a fixed two-argument
// signature that a dozen call sites use and widening it would touch all of them
// to express something only one caller wants.
func (s *Server) SetFailureDiagnosis(fn func(context.Context, enrollmentdiag.Diagnosis)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onFailure = fn
}

// acmeStepForPath infers which step of the flow a request was on.
//
// From the PATH, which is the one piece of evidence available at the refusal
// site that says where the client had got to. It is deliberately coarse: an
// unrecognised path yields an empty step and the classifier substitutes its own
// default, rather than this function guessing at a stage nobody observed.
func acmeStepForPath(r *http.Request) enrollmentdiag.Step {
	if r == nil {
		return ""
	}
	switch path := r.URL.Path; {
	case strings.Contains(path, "/new-account"), strings.Contains(path, "/key-change"):
		return enrollmentdiag.StepAccount
	case strings.Contains(path, "/new-order"), strings.Contains(path, "/order"):
		return enrollmentdiag.StepOrder
	case strings.Contains(path, "/challenge"):
		return enrollmentdiag.StepValidation
	case strings.Contains(path, "/authz"):
		return enrollmentdiag.StepAuthorize
	case strings.Contains(path, "/finalize"), strings.Contains(path, "/cert"):
		return enrollmentdiag.StepIssue
	case strings.Contains(path, "/revoke"):
		return enrollmentdiag.StepRevocation
	default:
		return ""
	}
}

// csrIdentifiersMatchOrder enforces RFC 8555 §7.4: the finalize CSR must request
// exactly the identifier set the order validated — no more (which would be
// unauthorized issuance) and no fewer (which would certify less than the client
// asked for while the order reports fulfilled).
//
// Comparison is over the CSR's dNSName SANs plus its subject CN when the CN is
// not already a SAN, because a CA that copies the subject would otherwise certify
// a name the order never covered. DNS names are compared case-insensitively and
// with a single trailing dot ignored, both of which denote the same name.
func csrIdentifiersMatchOrder(csrDER []byte, authorized []string) error {
	ids, err := crypto.CSRRequestedIdentifiers(csrDER)
	if err != nil {
		return fmt.Errorf("acme: finalize CSR is unreadable: %w", err)
	}
	requested := map[string]bool{}
	for _, name := range ids.DNSNames {
		requested[normalizeACMEIdentifier(name)] = true
	}
	if cn := strings.TrimSpace(ids.CommonName); cn != "" {
		requested[normalizeACMEIdentifier(cn)] = true
	}
	// Any non-DNS SAN is outside what an ACME dns identifier can authorize.
	if len(ids.IPAddresses) > 0 || len(ids.EmailAddresses) > 0 || len(ids.URIs) > 0 {
		return errors.New("acme: finalize CSR requests identifiers the order did not authorize")
	}
	allowed := map[string]bool{}
	for _, name := range authorized {
		allowed[normalizeACMEIdentifier(name)] = true
	}
	for name := range requested {
		if !allowed[name] {
			return errors.New("acme: finalize CSR requests an identifier the order did not authorize")
		}
	}
	for name := range allowed {
		if !requested[name] {
			return errors.New("acme: finalize CSR omits an identifier the order authorized")
		}
	}
	if len(requested) == 0 {
		return errors.New("acme: finalize CSR requests no identifiers")
	}
	return nil
}

// normalizeACMEIdentifier folds a DNS name to its comparable form: DNS labels are
// case-insensitive, and a single trailing dot denotes the same (fully qualified)
// name.
func normalizeACMEIdentifier(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// accountOwns reports whether the authenticated account owns an object recorded
// with ownerURL. It fails closed: an unauthenticated request, or an object with
// no recorded owner, is never treated as owned.
func (s *Server) accountOwns(ownerURL string, acct *account) bool {
	if acct == nil || ownerURL == "" {
		return false
	}
	return ownerURL == acct.url
}
