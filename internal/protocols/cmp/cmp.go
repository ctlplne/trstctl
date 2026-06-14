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
	"io"
	"net/http"

	"trustctl.io/trustctl/internal/bulkhead"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/events"
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
	mux        *http.ServeMux
}

// Config wires a Server. CACertDER/CAKeyPKCS8 sign the CMP response protection.
type Config struct {
	Enroller    Enroller
	CACertDER   []byte
	CAKeyPKCS8  []byte
	ProfileName string
	Pool        *bulkhead.Pool // AN-7; nil runs inline
	Log         *events.Log    // AN-2; nil disables audit
}

// New builds the CMP server.
func New(cfg Config) *Server {
	s := &Server{
		enroller: cfg.Enroller, caCertDER: cfg.CACertDER, caKeyPKCS8: cfg.CAKeyPKCS8,
		profile: cfg.ProfileName, pool: cfg.Pool, log: cfg.Log,
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
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCMPBody))
	if err != nil || len(body) == 0 {
		s.audit(r.Context(), "deny", "empty body", "")
		http.Error(w, "cmp: empty PKIMessage", http.StatusBadRequest)
		return
	}
	req, err := crypto.ParseCMPRequest(body)
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
	_, _ = s.log.Append(ctx, events.Event{Type: "protocol.cmp.enroll", TenantID: tenantFromCtx(ctx), Data: payload})
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
