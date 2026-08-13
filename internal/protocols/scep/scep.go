// SPDX-License-Identifier: MPL-2.0

package scep

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
)

const (
	// EventRequestObserved records a parsed, tenant-bound SCEP request before
	// challenge validation or issuance. It is the immutable requested-stage
	// evidence used by the MDM trace; a transaction id in a correlation row is
	// only a join key and cannot substitute for this event.
	EventRequestObserved = "protocol.scep.request.observed"
	// EventIssuanceObserved records the terminal issuance outcome for that exact
	// transaction. Successful values include the minted certificate identity;
	// failures include a bounded operator-facing reason and no invented cert.
	EventIssuanceObserved = "protocol.scep.issuance.observed"
)

// AttemptEvidence is the public, secret-free event payload that joins an MDM
// device to one SCEP attempt. DeviceSerial is taken from the verified CSR common
// name (the documented Intune/Jamf profile convention), never from an MDM row.
// The certificate fields exist only after the enroller returned a parseable leaf.
type AttemptEvidence struct {
	TransactionID          string    `json:"transaction_id"`
	DeviceSerial           string    `json:"device_serial"`
	Profile                string    `json:"profile,omitempty"`
	Outcome                string    `json:"outcome"`
	Detail                 string    `json:"detail,omitempty"`
	CertificateSerial      string    `json:"certificate_serial,omitempty"`
	CertificateFingerprint string    `json:"certificate_fingerprint,omitempty"`
	CertificateNotAfter    time.Time `json:"certificate_not_after,omitempty"`
}

// Enroller brokers a SCEP enrollment to the platform issuance path: it validates the CSR
// against profileName (S8.1) and mints a certificate idempotently (AN-5/AN-6). Same
// contract as the EST Enroller; a real implementation wraps the issuance service, tests
// inject a double.
type Enroller interface {
	Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (leafDER []byte, err error)
}

// ChallengeRequest is the full input to a SCEP challenge-password decision.
type ChallengeRequest struct {
	TenantID      string
	Challenge     string
	CSRDER        []byte
	TransactionID string
}

// ChallengeValidator validates a SCEP challengePassword before issuance.
type ChallengeValidator func(context.Context, ChallengeRequest) error

// Server is the RFC 8894 SCEP endpoint set (GetCACaps, GetCACert, PKIOperation), served
// under /scep. The S15.0 assembly mounts Handler() in the live control plane.
type Server struct {
	enroller      Enroller
	caChain       [][]byte // CA chain (DER) for GetCACert
	raCertDER     []byte   // RA/CA cert for CMS decrypt + reply signing
	raKeyPKCS8    []byte   // RA/CA RSA key (PKCS#8) — loaded from the sealed server RA identity
	profile       string
	pool          *bulkhead.Pool
	log           *events.Log
	challenge     ChallengeValidator // optional MDM challenge-password validator (S8.5)
	deviceLimit   int
	deviceWindow  time.Duration
	deviceLimiter *deviceWindowCounter
	onFailure     func(context.Context, enrollmentdiag.Diagnosis)
	mux           *http.ServeMux
}

// Config wires a Server. RACertDER/RAKeyPKCS8 are the RSA key pair SCEP uses for CMS
// transport (decrypt the request envelope, sign the reply) — deliberately distinct from
// the platform CA signing key in the isolated signer (AN-4): SCEP's transport key never
// enters the signer process. The served composition persists this identity sealed at
// rest so SCEP clients can cache GetCACert material across restarts/replicas.
type Config struct {
	Enroller    Enroller
	CAChainDER  [][]byte
	RACertDER   []byte
	RAKeyPKCS8  []byte
	ProfileName string
	Pool        *bulkhead.Pool // AN-7; nil runs inline
	Log         *events.Log    // AN-2; nil disables audit
	// ChallengeValidator, when set, validates the SCEP challengePassword (from the CSR)
	// before issuance — the Intune/JAMF MDM gate (S8.5). nil means no challenge required.
	ChallengeValidator ChallengeValidator
	// MaxEnrollmentsPerDevice caps enrollments per tenant/profile/device subject in
	// DeviceRateLimitWindow. Zero disables the limiter; served deployments should
	// use a non-zero cap for MDM-backed profiles so one device cannot flood issuance.
	MaxEnrollmentsPerDevice int
	DeviceRateLimitWindow   time.Duration
	// FailureDiagnosis receives typed refusal evidence for tenant-scoped durable
	// projection by the served assembly.
	FailureDiagnosis func(context.Context, enrollmentdiag.Diagnosis)
}

// New builds the SCEP server.
func New(cfg Config) *Server {
	s := &Server{
		enroller: cfg.Enroller, caChain: cfg.CAChainDER, raCertDER: cfg.RACertDER,
		raKeyPKCS8: cfg.RAKeyPKCS8, profile: cfg.ProfileName, pool: cfg.Pool, log: cfg.Log,
		challenge: cfg.ChallengeValidator, deviceLimit: cfg.MaxEnrollmentsPerDevice,
		deviceWindow: cfg.DeviceRateLimitWindow, deviceLimiter: newDeviceWindowCounter(nil), onFailure: cfg.FailureDiagnosis,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/scep", s.handle)
	mux.HandleFunc("/scep/pkiclient.exe", s.handle) // the path many SCEP clients default to
	s.mux = mux
	return s
}

// Handler returns the SCEP http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

const maxPKIBody = 1 << 18 // 256 KiB; a pkiMessage is small — bound untrusted input.

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case "GetCACaps":
		s.getCACaps(w)
	case "GetCACert":
		s.getCACert(w)
	case "PKIOperation":
		s.pkiOperation(w, r)
	default:
		http.Error(w, "scep: unknown operation", http.StatusBadRequest)
	}
}

func (s *Server) getCACaps(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "Renewal\nPOSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\n")
}

func (s *Server) getCACert(w http.ResponseWriter) {
	switch len(s.caChain) {
	case 0:
		http.Error(w, "scep: CA unavailable", http.StatusServiceUnavailable)
	case 1:
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		_, _ = w.Write(s.caChain[0])
	default:
		p7, err := crypto.DegeneratePKCS7(s.caChain)
		if err != nil {
			http.Error(w, "scep: CA unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
		_, _ = w.Write(p7)
	}
}

func (s *Server) pkiOperation(w http.ResponseWriter, r *http.Request) {
	body, err := readPKIMessage(r)
	if err != nil {
		s.audit(r.Context(), "deny", err.Error(), "")
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepOrder, "badRequest", err),
			r.Method+" "+r.URL.Path, "")
		if errors.Is(err, bodylimit.ErrTooLarge) {
			http.Error(w, "scep: request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := crypto.ParseSCEPRequest(body, s.raCertDER, s.raKeyPKCS8)
	if err != nil {
		s.audit(r.Context(), "deny", "malformed pkiMessage", "")
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepOrder, "badMessageCheck", err),
			r.Method+" "+r.URL.Path, "")
		http.Error(w, "scep: bad request", http.StatusBadRequest)
		return
	}
	deviceSerial, err := scepDeviceSerial(req.CSRDER)
	if err != nil {
		s.audit(r.Context(), "deny", "invalid csr", req.TransactionID)
		s.emitAttempt(r.Context(), EventIssuanceObserved, AttemptEvidence{
			TransactionID: req.TransactionID, Profile: s.profile, Outcome: "failed", Detail: "The certificate request could not be inspected.",
		})
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepOrder, "badRequest", err),
			"scep:"+req.TransactionID, "csr-sha256:"+crypto.SHA256Hex(req.CSRDER))
		http.Error(w, "scep: bad request", http.StatusBadRequest)
		return
	}
	identityRef := scepIdentityRef(req.CSRDER, deviceSerial)
	baseEvidence := AttemptEvidence{
		TransactionID: req.TransactionID, DeviceSerial: deviceSerial, Profile: s.profile,
	}
	requestEvidence := baseEvidence
	requestEvidence.Outcome = "ok"
	requestEvidence.Detail = "The SCEP request was parsed and bound to this transaction and device serial."
	s.emitAttempt(r.Context(), EventRequestObserved, requestEvidence)
	if s.challenge != nil {
		pw, _ := crypto.ChallengePasswordFromCSR(req.CSRDER)
		cerr := s.challenge(r.Context(), ChallengeRequest{
			TenantID:      tenantFromCtx(r.Context()),
			Challenge:     pw,
			CSRDER:        req.CSRDER,
			TransactionID: req.TransactionID,
		})
		if cerr != nil {
			s.audit(r.Context(), "deny", "challenge rejected", req.TransactionID)
			failed := baseEvidence
			failed.Outcome = "failed"
			failed.Detail = "Challenge validation rejected the request; verify the MDM challenge trust, audience, expiry, and one-time nonce."
			s.emitAttempt(r.Context(), EventIssuanceObserved, failed)
			s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepAuthorize, "badMessageCheck", cerr),
				"scep:"+req.TransactionID, identityRef)
			http.Error(w, "scep: challenge rejected", http.StatusForbidden)
			return
		}
	}
	allowed, err := s.allowDeviceEnrollment(r.Context(), req.CSRDER)
	if err != nil {
		s.audit(r.Context(), "deny", "invalid csr", req.TransactionID)
		failed := baseEvidence
		failed.Outcome = "failed"
		failed.Detail = "The certificate request did not satisfy the device enrollment checks."
		s.emitAttempt(r.Context(), EventIssuanceObserved, failed)
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepAuthorize, "badRequest", err),
			"scep:"+req.TransactionID, identityRef)
		http.Error(w, "scep: bad request", http.StatusBadRequest)
		return
	}
	if !allowed {
		s.audit(r.Context(), "shed", "device rate limit", req.TransactionID)
		failed := baseEvidence
		failed.Outcome = "failed"
		failed.Detail = "The per-device SCEP rate limit refused this attempt; wait for the configured window before retrying."
		s.emitAttempt(r.Context(), EventIssuanceObserved, failed)
		s.emitFailure(r, enrollmentdiag.Diagnose(enrollmentdiag.ProtocolSCEP, enrollmentdiag.StepOrder, enrollmentdiag.CauseRateLimited),
			"scep:"+req.TransactionID, identityRef)
		http.Error(w, "scep: device rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	issuedEvidence := baseEvidence
	reply, rerr := s.runBounded(r.Context(), func(ctx context.Context) ([]byte, error) {
		// The transaction id makes a retried enrollment idempotent (AN-5).
		leaf, err := s.enroller.Enroll(ctx, req.CSRDER, s.profile, "scep", "scep:"+req.TransactionID)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(leaf)
		if err != nil {
			return nil, errors.New("scep: enroller returned an invalid certificate")
		}
		issuedEvidence.Outcome = "ok"
		issuedEvidence.Detail = "The signer-backed issuance path minted this certificate for the SCEP transaction."
		issuedEvidence.CertificateSerial = info.SerialNumber
		issuedEvidence.CertificateFingerprint = info.SHA256Fingerprint
		issuedEvidence.CertificateNotAfter = info.NotAfter.UTC()
		return crypto.BuildSCEPSuccess(leaf, s.raCertDER, s.raKeyPKCS8, req)
	})
	switch {
	case errors.Is(rerr, bulkhead.ErrRejected):
		s.audit(r.Context(), "shed", "bulkhead full", req.TransactionID)
		failed := baseEvidence
		failed.Outcome = "failed"
		failed.Detail = "The bounded SCEP worker pool was full; retry this same transaction."
		s.emitAttempt(r.Context(), EventIssuanceObserved, failed)
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepIssue, "badRequest", rerr),
			"scep:"+req.TransactionID, identityRef)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	case rerr != nil:
		s.audit(r.Context(), "deny", rerr.Error(), req.TransactionID)
		failed := baseEvidence
		failed.Outcome = "failed"
		failed.Detail = "The signer-backed issuance path refused this request; inspect the profile and signer evidence before retrying."
		s.emitAttempt(r.Context(), EventIssuanceObserved, failed)
		s.emitFailure(r, enrollmentdiag.ClassifySCEP(enrollmentdiag.StepIssue, "badRequest", rerr),
			"scep:"+req.TransactionID, identityRef)
		http.Error(w, "scep: enrollment refused", http.StatusForbidden)
	default:
		s.audit(r.Context(), "allow", "", req.TransactionID)
		s.emitAttempt(r.Context(), EventIssuanceObserved, issuedEvidence)
		w.Header().Set("Content-Type", "application/x-pki-message")
		_, _ = w.Write(reply)
	}
}

func (s *Server) emitFailure(r *http.Request, diagnosis enrollmentdiag.Diagnosis, operationRef, identityRef string) {
	if s.onFailure == nil || r == nil {
		return
	}
	s.onFailure(r.Context(), diagnosis.WithEvidence(enrollmentdiag.Evidence{
		OperationRef: operationRef, IdentityRef: identityRef, EndpointRef: strings.TrimSpace(r.Host),
	}))
}

func scepIdentityRef(csrDER []byte, deviceSerial string) string {
	if info, err := crypto.InspectCSR(csrDER); err == nil && len(info.DNSNames) > 0 {
		if name := strings.ToLower(strings.TrimSpace(info.DNSNames[0])); name != "" {
			return "dns:" + name
		}
	}
	return "device:" + deviceSerial
}

func scepDeviceSerial(csrDER []byte) (string, error) {
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		return "", err
	}
	serial := strings.ToUpper(strings.TrimSpace(info.CommonName))
	if serial == "" {
		return "", errors.New("scep: device CSR common name is empty")
	}
	return serial, nil
}

// readPKIMessage reads the pkiMessage DER from a POST body or a base64 GET "message".
func readPKIMessage(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		b, err := bodylimit.ReadAll(r.Body, maxPKIBody)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, errors.New("scep: empty PKIOperation body")
		}
		return b, nil
	}
	msg := r.URL.Query().Get("message")
	if msg == "" {
		return nil, errors.New("scep: missing message")
	}
	// FUZZ-005: the GET form decodes the base64 `message` directly, bypassing the
	// POST body cap. Reject an over-cap encoded value BEFORE base64 decode (the
	// decoded DER is bounded by maxPKIBody, and base64 inflates by 4/3), so a
	// hostile GET cannot allocate an unbounded decode buffer. Surface ErrTooLarge
	// so the handler maps it to 413 exactly like the POST path.
	if len(msg) > base64.StdEncoding.EncodedLen(maxPKIBody) {
		return nil, bodylimit.ErrTooLarge
	}
	der, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return nil, errors.New("scep: message is not valid base64")
	}
	return der, nil
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

func (s *Server) allowDeviceEnrollment(ctx context.Context, csrDER []byte) (bool, error) {
	if s.deviceLimit <= 0 {
		return true, nil
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		return false, err
	}
	subject := info.CommonName
	if subject == "" && len(info.DNSNames) > 0 {
		subject = info.DNSNames[0]
	}
	if subject == "" {
		subject = base64.StdEncoding.EncodeToString(csrDER)
	}
	key := tenantFromCtx(ctx) + "|" + s.profile + "|" + subject
	return s.deviceLimiter.Allow(key, s.deviceLimit, s.deviceWindow), nil
}

func (s *Server) audit(ctx context.Context, decision, reason, txid string) {
	if s.log == nil {
		return
	}
	payload, _ := json.Marshal(struct {
		Op            string `json:"op"`
		Decision      string `json:"decision"`
		Reason        string `json:"reason,omitempty"`
		TransactionID string `json:"transaction_id,omitempty"`
		Profile       string `json:"profile,omitempty"`
	}{"scep-enroll", decision, reason, txid, s.profile})
	// CORRECT-004: account for a dropped audit emit (metric + WARN) instead of
	// swallowing the append error with `_, _ =`.
	_ = auditsink.Emit(ctx, auditsink.AuditorFunc(func(ctx context.Context, et, tid string, d []byte) error {
		_, err := s.log.Append(ctx, events.Event{Type: et, TenantID: tid, Data: d})
		return err
	}), nil, "protocol.scep.enroll", tenantFromCtx(ctx), payload)
}

func (s *Server) emitAttempt(ctx context.Context, eventType string, evidence AttemptEvidence) {
	if s.log == nil {
		return
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		return
	}
	_ = auditsink.Emit(ctx, auditsink.AuditorFunc(func(ctx context.Context, et, tid string, d []byte) error {
		_, err := s.log.Append(ctx, events.Event{Type: et, TenantID: tid, Data: d})
		return err
	}), nil, eventType, tenantFromCtx(ctx), payload)
}

type tenantKey struct{}

func tenantFromCtx(ctx context.Context) string {
	if t, ok := ctx.Value(tenantKey{}).(string); ok {
		return t
	}
	return ""
}

// WithTenant tags ctx with the tenant a SCEP request serves (used by the live mount).
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}
