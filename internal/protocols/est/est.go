// Package est implements the RFC 7030 EST enrollment server, so network devices
// and IoT fleets enroll and re-enroll for certificates automatically, under
// certificate-profile control (S8.1). It is the server side only; the embedded
// device client is S8.6.
//
// The wire formats (base64 PKCS#10 in, certs-only PKCS#7 out) route through the
// crypto boundary (AN-3). Enrollment is an audited event (AN-2), issuance is
// idempotent and outbox-mediated through the injected Enroller (AN-5/AN-6), and
// every enrollment runs on a bounded pool so a burst cannot starve other
// subsystems (AN-7).
package est

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
)

// Enroller brokers an EST enrollment to the platform issuance path: it validates
// the CSR against profileName (S8.1) and mints a certificate idempotently
// (AN-5/AN-6), returning the issued leaf in DER. A real implementation wraps
// ca.IssuanceService; tests inject a double.
type Enroller interface {
	Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (leafDER []byte, err error)
}

// ServerKeygenResult is the signer-service result for RFC 7030 §4.4
// /serverkeygen: the newly issued leaf certificate and the generated private key
// already wrapped as CMS EnvelopedData. It deliberately contains no plaintext key
// field so the API process never receives generated private material (AN-4/AN-8).
type ServerKeygenResult struct {
	CertificateDER  []byte
	EnvelopedKeyDER []byte
}

// ServerKeyGenerator brokers EST server-side key generation to the sacred
// signing process. The handler authenticates and bounds the HTTP request, then
// passes the CSR and idempotency key through this interface; key generation,
// signing, and CMS wrapping stay outside the API address space (AN-4).
type ServerKeyGenerator interface {
	ServerKeygen(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (ServerKeygenResult, error)
}

// Authenticator authorizes an enrolling client (RFC 7030 §3.2.3 HTTP auth, on top
// of TLS). A real deployment checks an enrollment credential; tests inject a double.
type Authenticator interface {
	Authenticate(r *http.Request) bool
}

// Server is the EST endpoint set. Mount Handler() under the control plane's TLS
// listener (the S15.0 assembly mounts it live).
type Server struct {
	enroller                     Enroller
	serverKeygen                 ServerKeyGenerator
	serverKeygenEnabled          bool
	channelBindingRequired       bool
	channelBindingCertificateDER []byte
	mtlsClientCAsDER             [][]byte
	principalLimit               int
	principalWindow              time.Duration
	principalLimiter             *windowCounter
	auth                         Authenticator
	caChain                      [][]byte // CA certificate chain, DER, for /cacerts
	profile                      string   // the certificate profile this endpoint binds (S8.1)
	pool                         *bulkhead.Pool
	log                          *events.Log
	mux                          *http.ServeMux
}

// Config wires a Server.
type Config struct {
	Enroller                     Enroller
	ServerKeygen                 ServerKeyGenerator
	ServerKeygenEnabled          bool
	ChannelBindingRequired       bool
	ChannelBindingCertificateDER []byte
	MTLSClientCAsDER             [][]byte
	MaxEnrollmentsPerPrincipal   int
	PrincipalRateLimitWindow     time.Duration
	Auth                         Authenticator
	CAChainDER                   [][]byte
	ProfileName                  string
	Pool                         *bulkhead.Pool // AN-7; nil runs inline
	Log                          *events.Log    // AN-2; nil disables audit emit
}

// New builds the EST server.
func New(cfg Config) *Server {
	s := &Server{
		enroller: cfg.Enroller, serverKeygen: cfg.ServerKeygen, serverKeygenEnabled: cfg.ServerKeygenEnabled,
		channelBindingRequired: cfg.ChannelBindingRequired, channelBindingCertificateDER: cfg.ChannelBindingCertificateDER, mtlsClientCAsDER: cfg.MTLSClientCAsDER,
		principalLimit: cfg.MaxEnrollmentsPerPrincipal, principalWindow: cfg.PrincipalRateLimitWindow,
		auth: cfg.Auth, caChain: cfg.CAChainDER, profile: cfg.ProfileName, pool: cfg.Pool, log: cfg.Log,
	}
	if cfg.MaxEnrollmentsPerPrincipal > 0 {
		s.principalLimiter = newWindowCounter(time.Now)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/est/cacerts", s.cacerts)
	mux.HandleFunc("POST /.well-known/est/simpleenroll", s.enroll("est-enroll"))
	mux.HandleFunc("POST /.well-known/est/simplereenroll", s.enroll("est-reenroll"))
	mux.HandleFunc("POST /.well-known/est/serverkeygen", s.serverKeygenHandler)
	mux.HandleFunc("GET /.well-known/est/csrattrs", s.csrattrs)
	s.mux = mux
	return s
}

// Handler returns the EST http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// SetMTLSClientCAs sets the DER trust anchors used by the mTLS sibling route.
func (s *Server) SetMTLSClientCAs(casDER [][]byte) {
	s.mtlsClientCAsDER = append([][]byte(nil), casDER...)
}

const maxEnrollBody = 1 << 16 // 64 KiB: a CSR is small; bound untrusted input.

func writePKCS7(w http.ResponseWriter, p7 []byte) {
	body := mimeBase64(p7)
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeServerKeygenMultipart(w http.ResponseWriter, certsOnlyPKCS7, envelopedKeyDER []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := writeServerKeygenPart(mw, "certs-only", certsOnlyPKCS7); err != nil {
		return err
	}
	if err := writeServerKeygenPart(mw, "enveloped-data", envelopedKeyDER); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	w.Header().Set("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": mw.Boundary()}))
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(body.Bytes())
	return err
}

func writeServerKeygenPart(mw *multipart.Writer, smimeType string, der []byte) error {
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", "application/pkcs7-mime; smime-type="+smimeType)
	header.Set("Content-Transfer-Encoding", "base64")
	part, err := mw.CreatePart(header)
	if err != nil {
		return err
	}
	_, err = part.Write(mimeBase64(der))
	return err
}

func mimeBase64(src []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(encoded, src)
	if len(encoded) == 0 {
		return encoded
	}
	const line = 64
	lines := (len(encoded) + line - 1) / line
	out := make([]byte, 0, len(encoded)+lines)
	for len(encoded) > line {
		out = append(out, encoded[:line]...)
		out = append(out, '\n')
		encoded = encoded[line:]
	}
	out = append(out, encoded...)
	out = append(out, '\n')
	return out
}

// cacerts returns the CA chain as a certs-only PKCS#7 (RFC 7030 §4.1). No auth
// required — a client needs the CA to establish explicit TLS trust.
func (s *Server) cacerts(w http.ResponseWriter, _ *http.Request) {
	p7, err := crypto.DegeneratePKCS7(s.caChain)
	if err != nil {
		http.Error(w, "ca unavailable", http.StatusServiceUnavailable)
		return
	}
	writePKCS7(w, p7)
}

// csrattrs advertises required CSR attributes (RFC 7030 §4.5). This server imposes
// none beyond the bound profile, so it returns 204 No Content (a valid response).
func (s *Server) csrattrs(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// parseEnrollBody decodes the base64 PKCS#10 request body to CSR DER and verifies
// its self-signature. It fails closed on oversize, bad base64, or an unparseable
// CSR — the fuzz target.
func parseEnrollBody(r io.Reader) ([]byte, error) {
	raw, err := bodylimit.ReadAll(r, maxEnrollBody)
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(string(trimSpace(raw)))
	if err != nil {
		return nil, errors.New("est: body is not valid base64 PKCS#10")
	}
	if err := crypto.VerifyCertificateRequest(der); err != nil {
		return nil, errors.New("est: invalid CSR")
	}
	return der, nil
}

func trimSpace(b []byte) []byte {
	out := b[:0]
	for _, c := range b {
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return out
}

// enroll handles /simpleenroll and /simplereenroll. The opType distinguishes them
// in the audit trail.
func (s *Server) enroll(opType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(w, r, opType) {
			return
		}
		csrDER, err := parseEnrollBody(r.Body)
		if err != nil {
			if errors.Is(err, bodylimit.ErrTooLarge) {
				s.audit(r.Context(), opType, "deny", "request body too large")
				http.Error(w, "est: request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			s.audit(r.Context(), opType, "deny", err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.verifyChannelBinding(csrDER); err != nil {
			s.audit(r.Context(), opType, "deny", err.Error())
			writeChannelBindingError(w, err)
			return
		}
		allowed, err := s.allowPrincipalEnrollment(r, csrDER)
		if err != nil {
			s.audit(r.Context(), opType, "deny", err.Error())
			http.Error(w, "est: invalid CSR principal", http.StatusBadRequest)
			return
		}
		if !allowed {
			s.audit(r.Context(), opType, "shed", "principal enrollment limit reached")
			http.Error(w, "est: principal enrollment rate limit", http.StatusTooManyRequests)
			return
		}
		// AN-7: run the issuance on the bounded pool; a saturated pool sheds fast.
		leafDER, rerr := s.runBounded(r.Context(), func(ctx context.Context) ([]byte, error) {
			// The Idempotency-Key (RFC-agnostic but honored when the client sends one)
			// makes a retried enrollment safe (AN-5).
			idem := r.Header.Get("Idempotency-Key")
			if idem == "" {
				idem = estFallbackIdempotencyKey(opType, csrDER)
			}
			return s.enroller.Enroll(ctx, csrDER, s.profile, "est", idem)
		})
		if errors.Is(rerr, bulkhead.ErrRejected) {
			s.audit(r.Context(), opType, "shed", "bulkhead full")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if rerr != nil {
			s.audit(r.Context(), opType, "deny", rerr.Error())
			http.Error(w, "enrollment refused", http.StatusForbidden)
			return
		}
		p7, err := crypto.DegeneratePKCS7([][]byte{leafDER})
		if err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
			return
		}
		s.audit(r.Context(), opType, "allow", "")
		writePKCS7(w, p7)
	}
}

func (s *Server) verifyChannelBinding(csrDER []byte) error {
	if !s.channelBindingRequired && len(s.channelBindingCertificateDER) == 0 {
		return nil
	}
	return crypto.VerifyESTChannelBinding(csrDER, s.channelBindingCertificateDER, s.channelBindingRequired)
}

func writeChannelBindingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, crypto.ErrESTChannelBindingMissing):
		http.Error(w, "est: channel binding required", http.StatusBadRequest)
	case errors.Is(err, crypto.ErrESTChannelBindingMismatch):
		http.Error(w, "est: channel binding mismatch", http.StatusConflict)
	default:
		http.Error(w, "est: channel binding invalid", http.StatusBadRequest)
	}
}

func (s *Server) allowPrincipalEnrollment(r *http.Request, csrDER []byte) (bool, error) {
	if s.principalLimit <= 0 || s.principalLimiter == nil {
		return true, nil
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		return false, err
	}
	key := s.profile + "|" + info.CommonName + "|" + requestIP(r)
	return s.principalLimiter.Allow(key, s.principalLimit, s.principalWindow), nil
}

func (s *Server) serverKeygenHandler(w http.ResponseWriter, r *http.Request) {
	const opType = "est-serverkeygen"
	if !s.serverKeygenEnabled || s.serverKeygen == nil {
		s.audit(r.Context(), opType, "deny", "serverkeygen disabled")
		http.NotFound(w, r)
		return
	}
	if !s.authorize(w, r, opType) {
		return
	}
	csrDER, err := parseEnrollBody(r.Body)
	if err != nil {
		if errors.Is(err, bodylimit.ErrTooLarge) {
			s.audit(r.Context(), opType, "deny", "request body too large")
			http.Error(w, "est: request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.audit(r.Context(), opType, "deny", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, rerr := s.runServerKeygenBounded(r.Context(), func(ctx context.Context) (ServerKeygenResult, error) {
		idem := r.Header.Get("Idempotency-Key")
		if idem == "" {
			idem = estFallbackIdempotencyKey(opType, csrDER)
		}
		return s.serverKeygen.ServerKeygen(ctx, csrDER, s.profile, opType, idem)
	})
	if errors.Is(rerr, bulkhead.ErrRejected) {
		s.audit(r.Context(), opType, "shed", "bulkhead full")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if rerr != nil {
		s.audit(r.Context(), opType, "deny", rerr.Error())
		http.Error(w, "serverkeygen refused", http.StatusForbidden)
		return
	}
	if len(result.CertificateDER) == 0 || len(result.EnvelopedKeyDER) == 0 {
		s.audit(r.Context(), opType, "deny", "empty serverkeygen result")
		http.Error(w, "serverkeygen unavailable", http.StatusInternalServerError)
		return
	}
	if err := crypto.IsEnvelopedData(result.EnvelopedKeyDER); err != nil {
		s.audit(r.Context(), opType, "deny", "invalid CMS envelope")
		http.Error(w, "serverkeygen encode error", http.StatusInternalServerError)
		return
	}
	certsOnly, err := crypto.DegeneratePKCS7([][]byte{result.CertificateDER})
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), opType, "allow", "")
	if err := writeServerKeygenMultipart(w, certsOnly, result.EnvelopedKeyDER); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
}

type limitedAuthenticator interface {
	Authenticator
	TooManyFailures(*http.Request) bool
	RecordFailure(*http.Request)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, opType string) bool {
	if isMTLSRoute(r.Context()) {
		if err := crypto.VerifyTLSClientCertificate(r.TLS, s.mtlsClientCAsDER); err != nil {
			s.audit(r.Context(), opType, "deny", "mTLS client certificate rejected")
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return false
		}
		return true
	}
	if limiter, ok := s.auth.(limitedAuthenticator); ok && limiter.TooManyFailures(r) {
		s.audit(r.Context(), opType, "shed", "basic auth failures over limit")
		http.Error(w, "too many failed enrollment attempts", http.StatusTooManyRequests)
		return false
	}
	if s.auth == nil || !s.auth.Authenticate(r) {
		if limiter, ok := s.auth.(limitedAuthenticator); ok {
			limiter.RecordFailure(r)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func estFallbackIdempotencyKey(opType string, csrDER []byte) string {
	return opType + ":" + crypto.SHA256Hex(csrDER)
}

// runBounded executes fn on the pool (AN-7); a nil pool runs inline.
func (s *Server) runBounded(ctx context.Context, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if s.pool == nil {
		return fn(ctx)
	}
	type res struct {
		der []byte
		err error
	}
	done := make(chan res, 1)
	if err := s.pool.Submit(func() { d, e := fn(ctx); done <- res{d, e} }); err != nil {
		return nil, bulkhead.ErrRejected
	}
	r := <-done
	return r.der, r.err
}

func (s *Server) runServerKeygenBounded(ctx context.Context, fn func(context.Context) (ServerKeygenResult, error)) (ServerKeygenResult, error) {
	if s.pool == nil {
		return fn(ctx)
	}
	type res struct {
		result ServerKeygenResult
		err    error
	}
	done := make(chan res, 1)
	if err := s.pool.Submit(func() { d, e := fn(ctx); done <- res{d, e} }); err != nil {
		return ServerKeygenResult{}, bulkhead.ErrRejected
	}
	r := <-done
	return r.result, r.err
}

// audit emits an AN-2 enrollment event (actor attached from ctx). A nil log is a
// no-op.
func (s *Server) audit(ctx context.Context, opType, decision, reason string) {
	if s.log == nil {
		return
	}
	payload, _ := json.Marshal(struct {
		Op       string `json:"op"`
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
		Profile  string `json:"profile,omitempty"`
	}{opType, decision, reason, s.profile})
	// CORRECT-004: account for a dropped audit emit (metric + WARN) instead of
	// swallowing the append error with `_, _ =`.
	_ = auditsink.Emit(ctx, auditsink.AuditorFunc(func(ctx context.Context, et, tid string, d []byte) error {
		_, err := s.log.Append(ctx, events.Event{Type: et, TenantID: tid, Data: d})
		return err
	}), nil, "protocol.est."+opType, tenantFromCtx(ctx), payload)
}

// tenantFromCtx resolves the tenant the EST endpoint serves. EST endpoints are
// tenant-scoped by their mount (S15.0); when unset (standalone/tests) the event is
// honestly unattributed to a tenant.
func tenantFromCtx(ctx context.Context) string {
	if t, ok := ctx.Value(tenantKey{}).(string); ok {
		return t
	}
	return ""
}

type tenantKey struct{}

// WithTenant tags ctx with the tenant an EST request serves (used by the live mount).
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}
