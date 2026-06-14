package scep

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"trustctl.io/trustctl/internal/bulkhead"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/events"
)

// Enroller brokers a SCEP enrollment to the platform issuance path: it validates the CSR
// against profileName (S8.1) and mints a certificate idempotently (AN-5/AN-6). Same
// contract as the EST Enroller; a real implementation wraps the issuance service, tests
// inject a double.
type Enroller interface {
	Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) (leafDER []byte, err error)
}

// Server is the RFC 8894 SCEP endpoint set (GetCACaps, GetCACert, PKIOperation), served
// under /scep. The S15.0 assembly mounts Handler() in the live control plane.
type Server struct {
	enroller   Enroller
	caChain    [][]byte // CA chain (DER) for GetCACert
	raCertDER  []byte   // RA/CA cert for CMS decrypt + reply signing
	raKeyPKCS8 []byte   // RA/CA RSA key (PKCS#8) — held only here, inside the server
	profile    string
	pool       *bulkhead.Pool
	log        *events.Log
	mux        *http.ServeMux
}

// Config wires a Server. RACertDER/RAKeyPKCS8 are the RSA key pair SCEP uses for CMS
// transport (decrypt the request envelope, sign the reply) — deliberately distinct from
// the platform CA signing key in the isolated signer (AN-4): SCEP's transport key never
// enters the signer process.
type Config struct {
	Enroller    Enroller
	CAChainDER  [][]byte
	RACertDER   []byte
	RAKeyPKCS8  []byte
	ProfileName string
	Pool        *bulkhead.Pool // AN-7; nil runs inline
	Log         *events.Log    // AN-2; nil disables audit
}

// New builds the SCEP server.
func New(cfg Config) *Server {
	s := &Server{
		enroller: cfg.Enroller, caChain: cfg.CAChainDER, raCertDER: cfg.RACertDER,
		raKeyPKCS8: cfg.RAKeyPKCS8, profile: cfg.ProfileName, pool: cfg.Pool, log: cfg.Log,
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := crypto.ParseSCEPRequest(body, s.raCertDER, s.raKeyPKCS8)
	if err != nil {
		s.audit(r.Context(), "deny", "malformed pkiMessage", "")
		http.Error(w, "scep: bad request", http.StatusBadRequest)
		return
	}
	reply, rerr := s.runBounded(r.Context(), func(ctx context.Context) ([]byte, error) {
		// The transaction id makes a retried enrollment idempotent (AN-5).
		leaf, err := s.enroller.Enroll(ctx, req.CSRDER, s.profile, "scep", "scep:"+req.TransactionID)
		if err != nil {
			return nil, err
		}
		return crypto.BuildSCEPSuccess(leaf, s.raCertDER, s.raKeyPKCS8, req)
	})
	switch {
	case errors.Is(rerr, bulkhead.ErrRejected):
		s.audit(r.Context(), "shed", "bulkhead full", req.TransactionID)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	case rerr != nil:
		s.audit(r.Context(), "deny", rerr.Error(), req.TransactionID)
		http.Error(w, "scep: enrollment refused", http.StatusForbidden)
	default:
		s.audit(r.Context(), "allow", "", req.TransactionID)
		w.Header().Set("Content-Type", "application/x-pki-message")
		_, _ = w.Write(reply)
	}
}

// readPKIMessage reads the pkiMessage DER from a POST body or a base64 GET "message".
func readPKIMessage(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxPKIBody))
		if err != nil || len(b) == 0 {
			return nil, errors.New("scep: empty PKIOperation body")
		}
		return b, nil
	}
	msg := r.URL.Query().Get("message")
	if msg == "" {
		return nil, errors.New("scep: missing message")
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
	_, _ = s.log.Append(ctx, events.Event{Type: "protocol.scep.enroll", TenantID: tenantFromCtx(ctx), Data: payload})
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
