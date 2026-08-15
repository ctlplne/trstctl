// SPDX-License-Identifier: MPL-2.0

// Package cmp implements the RFC 4210 / CMPv3 enrollment server (the p10cr flow) over
// HTTP (RFC 6712), for 5G/telco and industrial PKI. Issuance is profile-gated (S8.1),
// idempotent and outbox-mediated through the injected Enroller (AN-5/AN-6), audited
// (AN-2), and bulkheaded (AN-7). All ASN.1/CMS handling lives behind the crypto boundary
// (internal/crypto; AN-3); this package only moves bytes and enforces the platform gates.
package cmp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
)

// Enroller brokers a CMP enrollment to the platform issuance path: validate the CSR
// against profileName (S8.1) and mint idempotently (AN-5/AN-6). Same contract as EST/SCEP.
type Enroller interface {
	Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (leafDER []byte, err error)
}

// Server serves CMP over HTTP under /cmp.
type Server struct {
	enroller   Enroller
	caCertDER  []byte
	caKeyPKCS8 []byte
	profile    string
	pool       *bulkhead.Pool
	log        *events.Log
	verifyCSR  func([]byte) error
	mux        *http.ServeMux

	// clientAnchors is the PRE-PARSED trust-anchor set a PKIMessage's
	// protection identity must chain to — parsed once at New, opaque so this
	// package never imports crypto/x509 (AN-3, E3/V33). anchorsErr records a
	// construction-time parse failure; requests then fail closed as
	// unavailable. allowAnonymous is the deliberate escape hatch for harnesses.
	clientAnchors  *crypto.CMPTrustAnchors
	anchorsErr     error
	allowAnonymous bool
}

// Config wires a Server. CACertDER/CAKeyPKCS8 sign the CMP response protection. In
// the served composition this is the sealed protocol RA transport identity, not the
// issuing CA key.
type Config struct {
	Enroller    Enroller
	CACertDER   []byte
	CAKeyPKCS8  []byte
	ProfileName string
	Pool        *bulkhead.Pool // AN-7; nil runs inline
	Log         *events.Log    // AN-2; nil disables audit
	// CSRVerifier is the feature-neutral production seam for subject algorithms
	// not yet understood by the Go toolchain, mirroring EST's. It verifies only
	// the carried PKCS#10; PKIMessage protection is always verified by the core
	// parser. Nil uses the strict internal/crypto classical parser.
	CSRVerifier func([]byte) error
	// ClientTrustAnchorsDER are the anchors a PKIMessage's protection identity
	// must chain to. CMP carries that identity in the message's own extraCerts,
	// so without anchors the protection check proves only that the sender signed
	// their own message — a self-signed pair is sufficient to enroll. Empty means
	// the caller has NO credential check and every request is trusted; the served
	// endpoint refuses to start in that state (see New).
	ClientTrustAnchorsDER [][]byte
	// AllowUnauthenticatedClients must be set deliberately to run without
	// anchors. It exists for differential harnesses that drive the parser
	// directly; production wiring never sets it.
	AllowUnauthenticatedClients bool
}

// New builds the CMP server. The trust anchors are parsed ONCE here rather
// than per message (AUD-201 follow-up E3/V33); a malformed anchor is recorded
// and every request then fails closed as unavailable, because a mount whose
// trust configuration cannot be loaded must not guess.
func New(cfg Config) *Server {
	anchors, anchorsErr := crypto.NewCMPTrustAnchors(cfg.ClientTrustAnchorsDER)
	s := &Server{
		enroller: cfg.Enroller, caCertDER: cfg.CACertDER, caKeyPKCS8: cfg.CAKeyPKCS8,
		profile: cfg.ProfileName, pool: cfg.Pool, log: cfg.Log,
		verifyCSR:      cfg.CSRVerifier,
		clientAnchors:  anchors,
		anchorsErr:     anchorsErr,
		allowAnonymous: cfg.AllowUnauthenticatedClients,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cmp", s.handle)
	s.mux = mux
	return s
}

// Handler returns the CMP http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

const maxCMPBody = 1 << 18 // 256 KiB

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "cmp: POST required (RFC 6712)", http.StatusMethodNotAllowed)
		return
	}
	body, err := bodylimit.ReadAll(r.Body, maxCMPBody)
	if errors.Is(err, bodylimit.ErrTooLarge) {
		s.audit(r.Context(), "deny", "request body too large", "")
		http.Error(w, "cmp: request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil || len(body) == 0 {
		s.audit(r.Context(), "deny", "empty body", "")
		http.Error(w, "cmp: empty PKIMessage", http.StatusBadRequest)
		return
	}
	if s.anchorsErr != nil {
		// The configured anchors did not parse at construction; guessing per
		// message would be worse than refusing.
		s.audit(r.Context(), "deny", "invalid client trust anchors", "")
		http.Error(w, "cmp: enrollment unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.clientAnchors.Empty() && !s.allowAnonymous {
		// Fail closed rather than enrol anyone who can compose a PKIMessage.
		s.audit(r.Context(), "deny", "no client trust anchors configured", "")
		http.Error(w, "cmp: enrollment unavailable", http.StatusServiceUnavailable)
		return
	}
	req, err := crypto.ParseCMPRequestWithTrust(body, s.verifyCSR, s.clientAnchors)
	if err != nil {
		s.audit(r.Context(), "deny", "malformed pkiMessage", "")
		http.Error(w, "cmp: bad request", http.StatusBadRequest)
		return
	}
	txid := hex.EncodeToString(req.TransactionID)
	reply, rerr := s.runBounded(r.Context(), func(ctx context.Context) ([]byte, error) {
		leaf, err := s.enroller.Enroll(ctx, req.CSRDER, s.profile, "cmp", "cmp:"+txid)
		if err != nil {
			return nil, err
		}
		return crypto.BuildCMPResponse(leaf, s.caCertDER, s.caKeyPKCS8, req)
	})
	switch {
	case errors.Is(rerr, bulkhead.ErrRejected):
		s.audit(r.Context(), "shed", "bulkhead full", txid)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	case rerr != nil:
		s.audit(r.Context(), "deny", rerr.Error(), txid)
		http.Error(w, "cmp: enrollment refused", http.StatusForbidden)
	default:
		s.audit(r.Context(), "allow", "", txid)
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(reply)
	}
}

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
	}{"cmp-enroll", decision, reason, txid, s.profile})
	// CORRECT-004: account for a dropped audit emit (metric + WARN) instead of
	// swallowing the append error with `_, _ =`.
	_ = auditsink.Emit(ctx, auditsink.AuditorFunc(func(ctx context.Context, et, tid string, d []byte) error {
		_, err := s.log.Append(ctx, events.Event{Type: et, TenantID: tid, Data: d})
		return err
	}), nil, "protocol.cmp.enroll", tenantFromCtx(ctx), payload)
}

type tenantKey struct{}

func tenantFromCtx(ctx context.Context) string {
	if t, ok := ctx.Value(tenantKey{}).(string); ok {
		return t
	}
	return ""
}

// WithTenant tags ctx with the tenant a CMP request serves (used by the live mount).
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}
