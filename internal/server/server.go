// Package server is the composition root of the certctl control plane (S7.7): it
// wires the configuration, datastore, event log, projections, orchestrator, and
// REST API into one serving process, provisions an issuing CA whose key lives in
// the out-of-process signer (AN-4), and shuts everything down in order. It is the
// integration seam — it introduces no new product capability, only the assembly
// of capabilities that already exist and are tested as packages.
package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"certctl.io/certctl/internal/agent/enroll"
	"certctl.io/certctl/internal/api"
	"certctl.io/certctl/internal/audit"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/jose"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/projections"
	"certctl.io/certctl/internal/signing"
	"certctl.io/certctl/internal/store"
	"certctl.io/certctl/internal/webui"
)

// SignerProvider yields the current connected signer client, or nil when no
// signer is healthy. The signing.Supervisor satisfies it.
type SignerProvider interface {
	Client() *signing.Client
}

// Deps are the wired dependencies of the serving control plane. Tests inject an
// embedded store/log and an in-process signer; production wires the real ones.
type Deps struct {
	Store           *store.Store
	Log             *events.Log
	Signer          SignerProvider       // may be nil → issuance is unavailable (fail closed)
	OutboxHandler   orchestrator.Handler // delivers outbox entries; defaults to a no-op success
	APIOptions      []api.Option         // auth/audit/etc.
	SignTimeout     time.Duration        // per-issuance signer deadline (slow → fail closed)
	CACommonName    string
	AuditSigningKey *jose.SigningKey // persistent audit export key; when set, wires the audit endpoints (R2.1)
}

// Server is the assembled control plane.
type Server struct {
	store     *store.Store
	log       *events.Log
	outbox    *orchestrator.Outbox
	obHandler orchestrator.Handler
	handler   http.Handler

	signer    SignerProvider
	caSigner  crypto.DigestSigner // a *signing.RemoteSigner — the CA key lives in the signer
	caCertDER []byte
	signTO    time.Duration
}

// Build assembles the control plane over the given dependencies in dependency
// order: it catches the projections up from the event log, constructs the
// orchestrator and API, mounts /healthz + the API + the web UI, and provisions an
// issuing CA whose key is generated inside the signer (never in-process). It does
// not start an HTTP listener — call Handler (tests) or Run (production).
func Build(ctx context.Context, d Deps) (*Server, error) {
	if d.Store == nil || d.Log == nil {
		return nil, errors.New("server: store and log are required")
	}
	s := &Server{
		store:     d.Store,
		log:       d.Log,
		signer:    d.Signer,
		signTO:    d.SignTimeout,
		obHandler: d.OutboxHandler,
	}
	if s.signTO <= 0 {
		s.signTO = 10 * time.Second
	}

	// 1) Read model catches up from the event log (AN-2): the relational state is
	// a projection, so we replay before serving reads.
	proj := projections.New(d.Store)
	if err := proj.Project(ctx, d.Log); err != nil {
		return nil, fmt.Errorf("server: project event log: %w", err)
	}

	// 2) Orchestrator + outbox + API.
	s.outbox = orchestrator.NewOutbox(d.Store)
	orch := orchestrator.NewOrchestrator(d.Log, d.Store, s.outbox)
	idem := orchestrator.NewIdempotency(d.Store)

	// Agent enrollment (F3/F15, S5.1): mint one-time bootstrap tokens and sign
	// agents' CSRs into mTLS client certificates. Defaults are prepended so a
	// caller's APIOptions still override them.
	authority, err := enroll.NewAuthority("certctl Agent Enrollment CA")
	if err != nil {
		return nil, fmt.Errorf("server: create enrollment authority: %w", err)
	}
	ea := enrollAuthority{authority}
	defaults := []api.Option{api.WithAgentEnrollment(ea), api.WithAgentEnroller(ea)}
	// Wire the audit subsystem into the serving path (R2.1 / B5): the query and
	// export endpoints serve real data instead of HTTP 500. The signing key is
	// persistent (loaded from disk by Run), so signed evidence bundles verify
	// across restarts. A caller's APIOptions still override these defaults.
	if d.AuditSigningKey != nil {
		defaults = append(defaults, api.WithAudit(audit.NewService(d.Log, d.AuditSigningKey)))
	}
	apiOpts := append(defaults, d.APIOptions...)
	a := api.New(d.Store, idem, orch, apiOpts...)

	// 3) Provision the issuing CA inside the signer (AN-4). If no signer is
	// available, leave the CA unset — issuance then fails closed.
	if d.Signer != nil {
		if c := d.Signer.Client(); c != nil {
			if err := s.provisionCA(ctx, c, d.CACommonName); err != nil {
				return nil, fmt.Errorf("server: provision CA in signer: %w", err)
			}
		}
	}

	// 3a) Outbox handler. An explicit Deps.OutboxHandler wins (tests, custom
	// dispatchers). Otherwise, when an issuing CA is provisioned, the real
	// issuance dispatcher mints a certificate for a requested→issued transition
	// and records it in inventory; with no CA, issuance is unavailable so the
	// handler acknowledges (the entry cannot be served and must not dead-letter).
	switch {
	case s.obHandler != nil:
		// keep the injected handler
	case s.caSigner != nil:
		s.obHandler = &issuanceDispatcher{issue: s.IssueLeaf, orch: orch, idem: idem, store: d.Store}
	default:
		s.obHandler = orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return nil })
	}

	// 4) Root mux: health, API (/api + /auth), and the web UI at /.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("/api/", a)
	mux.Handle("/auth/", a)
	mux.Handle("/enroll/", a)
	mux.Handle("/", webui.Handler(webui.Assets()))
	s.handler = mux
	return s, nil
}

// provisionCA generates the CA signing key inside the signer and self-signs a CA
// certificate with it — so the private key never exists in the control plane's
// address space (AN-4).
func (s *Server) provisionCA(ctx context.Context, c *signing.Client, cn string) error {
	if cn == "" {
		cn = "certctl Issuing CA"
	}
	remote, err := c.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		return err
	}
	caDER, err := crypto.SelfSignedCACert(remote, cn, 90*24*time.Hour)
	if err != nil {
		return err
	}
	s.caSigner = remote
	s.caCertDER = caDER
	return nil
}

// Handler returns the assembled HTTP handler (for httptest and for Run).
func (s *Server) Handler() http.Handler { return s.handler }

// CACertPEM returns the issuing CA certificate, or nil when no CA is provisioned.
func (s *Server) CACertPEM() []byte {
	if s.caCertDER == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCertDER})
}

// OutOfProcessSigning reports whether the issuing CA key is held by the
// out-of-process signer (a *signing.RemoteSigner) rather than in-process. The
// control plane never signs in-process; this is the AN-4 assertion.
func (s *Server) OutOfProcessSigning() bool {
	_, remote := s.caSigner.(*signing.RemoteSigner)
	return s.caSigner != nil && remote
}

// IssueLeaf signs an end-entity certificate from a CSR using the CA key in the
// signer, and returns it PEM-encoded. It FAILS CLOSED — returning an error,
// never an in-process-signed certificate — when the signer is unavailable, slow,
// or returns a signature that does not verify.
func (s *Server) IssueLeaf(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
	if s.caSigner == nil || s.caCertDER == nil {
		return nil, errors.New("server: issuance unavailable — no out-of-process signer (fail closed)")
	}
	// The signer must be reachable and serving before we attempt to sign.
	if s.signer != nil {
		c := s.signer.Client()
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		healthy := c != nil && c.Healthy(hctx)
		cancel()
		if !healthy {
			return nil, errors.New("server: signer unavailable (fail closed)")
		}
	}
	// Bound the signing operation so a slow signer fails closed instead of
	// hanging the request.
	type result struct {
		der []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		der, err := crypto.SignLeafFromCSR(s.caCertDER, s.caSigner, csrDER, ttl)
		ch <- result{der, err}
	}()
	select {
	case <-time.After(s.signTO):
		return nil, errors.New("server: signer timed out (fail closed)")
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("server: issuance failed: %w", r.err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der}), nil
	}
}

// health reports readiness: the API is up; if a signer is configured it must be
// reachable.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if s.signer != nil {
		c := s.signer.Client()
		hctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		ok := c != nil && c.Healthy(hctx)
		cancel()
		if !ok {
			http.Error(w, `{"status":"degraded","signer":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// dispatchInterval is how often the running dispatcher sweeps the outbox for due
// entries.
const dispatchInterval = time.Second

// RunDispatcher runs the outbox dispatcher continuously until ctx is cancelled,
// delivering due entries (issuance, deployment, notifications) on a short
// interval — so external effects happen while the process runs, not only at
// shutdown. Per-entry failures are recorded on the row for retry inside Dispatch;
// only a transient store/transport fault returns from Dispatch, and the next tick
// retries. It is meant to run in its own goroutine.
func (s *Server) RunDispatcher(ctx context.Context) {
	t := time.NewTicker(dispatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.outbox.Dispatch(ctx, s.obHandler)
		}
	}
}

// Drain delivers any pending outbox entries through the configured handler — the
// shutdown step that guarantees no enqueued external effect is lost (AN-6).
func (s *Server) Drain(ctx context.Context) error {
	_, err := s.outbox.Dispatch(ctx, s.obHandler)
	return err
}

// Shutdown drains the outbox and closes the event log and datastore in order.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if err := s.Drain(ctx); err != nil {
		errs = append(errs, fmt.Errorf("drain outbox: %w", err))
	}
	if s.log != nil {
		if err := s.log.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close event log: %w", err))
		}
	}
	if s.store != nil {
		s.store.Close()
	}
	return errors.Join(errs...)
}
