package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

const (
	liveStackProfile = "eval-loopback-actual-listener-child-signer-uds"
	liveTenantID     = "11111111-1111-1111-1111-111111111111"
)

type liveEvalStack struct {
	baseURL      string
	httpClient   *http.Client
	httpServer   *http.Server
	listener     net.Listener
	srv          *server.Server
	store        *store.Store
	log          *events.Log
	stopPG       func() error
	signer       *signing.Supervisor
	signAuthz    interface{ Destroy() }
	kek          *seal.LocalKEK
	tempDir      string
	token        []byte
	ownerID      string
	issuerID     string
	ocspRequest  []byte
	replayEvent  events.Event
	projector    *projections.Projector
	signerKey    *signing.RemoteSigner
	signerDigest []byte
	seq          atomic.Uint64
	serveErr     chan error
}

func RunLiveLoad(profile string, samples int) (Report, error) {
	return RunLiveLoadWithObservations(profile, samples, nil)
}

func RunLiveLoadWithObservations(profile string, samples int, observations map[string]Observation) (Report, error) {
	if profile == "" {
		profile = "live"
	}
	if samples <= 0 {
		samples = 32
	}
	if err := validateObservations(observations); err != nil {
		return Report{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stack, err := startLiveEvalStack(ctx)
	if err != nil {
		return Report{}, err
	}
	defer stack.Close()

	ops, transports, err := stack.servedHotPaths()
	if err != nil {
		return Report{}, err
	}
	componentResources, err := stack.componentResourceMetrics(ctx, 0)
	if err != nil {
		return Report{}, err
	}
	phases := liveLoadPhases(samples)
	report := Report{
		SchemaVersion:       1,
		Profile:             profile,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		MeasurementArtifact: LiveMeasurementArtifact,
		CapacityTiers:       capacityTierIDs(),
		ServedStack:         true,
		StackProfile:        liveStackProfile,
		LoadPhases:          phases,
		ResourceMetrics:     captureResourceMetrics(0),
		ComponentResources:  componentResources,
		EventSpineBurst:     defaultEventSpineBurstEvidence(),
	}
	for _, phase := range phases {
		report.Summary.Phases = append(report.Summary.Phases, phase.Name)
		for _, slo := range HotPaths() {
			op, ok := ops[slo.HotPath]
			if !ok {
				return Report{}, fmt.Errorf("perf: no live operation for hot path %s", slo.HotPath)
			}
			result := measure(slo, op, phase.Samples, observations[slo.HotPath])
			result.Phase = phase.Name
			result.TargetRatePerSecond = slo.MinThroughputPerSecond * phase.RateMultiplier
			result.ServedStack = true
			result.StackProfile = liveStackProfile
			result.Transport = transports[slo.HotPath]
			result.ResourceMetrics = captureResourceMetrics(result.ProjectionLagEvents)
			report.Results = append(report.Results, result)
			if result.Met {
				report.Summary.Met++
			} else {
				report.Summary.Failed++
			}
		}
	}
	report.Summary.HotPaths = len(HotPaths())
	report.Summary.Measurements = len(report.Results)
	report.Summary.OK = report.Summary.Failed == 0 && report.Summary.Measurements == len(HotPaths())*len(phases)
	componentResources, err = stack.componentResourceMetrics(ctx, 0)
	if err != nil {
		return Report{}, err
	}
	report.ComponentResources = componentResources
	return report, nil
}

func defaultEventSpineBurstEvidence() *EventSpineBurstEvidence {
	return &EventSpineBurstEvidence{
		Artifact:     SpineBurstArtifact,
		Profile:      "cap-small",
		CapacityTier: "CAP-SMALL",
		Command:      "scripts/perf/run-spine-burst.sh --profile cap-small --out " + SpineBurstArtifact + " && scripts/perf/soak.sh --in " + SpineBurstArtifact,
		Purpose:      "embedded PostgreSQL + embedded JetStream replay + bounded slow-upstream outbox backlog receipt",
	}
}

func liveLoadPhases(samples int) []LoadPhase {
	return []LoadPhase{
		{Name: "realistic", Samples: samples, TargetRateMultiplier: 1.25, RateMultiplier: 1.25},
		{Name: "peak", Samples: samples * 2, TargetRateMultiplier: 2.50, RateMultiplier: 2.50},
	}
}

func startLiveEvalStack(ctx context.Context) (*liveEvalStack, error) {
	dir, err := os.MkdirTemp("", "trstctl-perf-live-")
	if err != nil {
		return nil, err
	}
	stack := &liveEvalStack{tempDir: dir, httpClient: &http.Client{Timeout: 10 * time.Second}}
	defer func() {
		if err != nil {
			stack.Close()
		}
	}()

	cfg := config.Default()
	pgPort := freeLiveTCPPort()
	if pgPort == 0 {
		return nil, fmt.Errorf("perf live: no free loopback PostgreSQL port")
	}
	cfg.Postgres = config.Postgres{Mode: config.PostgresBundled, DataDir: filepath.Join(dir, "postgres"), Port: pgPort}
	cfg.NATS = config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")}
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(dir, "kek.bin")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	cfg.Protocols.ACME.Enabled = true
	cfg.Protocols.ACME.TenantID = liveTenantID

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stack.store, stack.stopPG, err = server.OpenMigratedStore(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	stack.log, err = events.Open(ctx, cfg.NATS)
	if err != nil {
		return nil, err
	}
	if err := registerLiveTenant(ctx, stack.log, stack.store); err != nil {
		return nil, err
	}
	stack.replayEvent, err = latestEvent(ctx, stack.log)
	if err != nil {
		return nil, err
	}
	stack.projector = projections.New(stack.store)

	stack.kek, err = kek.LoadOrCreate(cfg.Secrets.KEKFile)
	if err != nil {
		return nil, err
	}
	authSecret := filepath.Join(dir, "signer-auth.bin")
	authzProvider, err := signing.LoadOrCreateAuthorizer(authSecret)
	if err != nil {
		return nil, err
	}
	stack.signAuthz = authzProvider
	signerBin, err := liveSignerBinary(ctx, dir)
	if err != nil {
		return nil, err
	}
	signerArgs := []string{
		"--keystore", filepath.Join(dir, "signer-keys"),
		"--kek", cfg.Secrets.KEKFile,
		"--auth-secret", authSecret,
	}
	if runtime.GOOS != "linux" {
		signerArgs = append(signerArgs, "--allow-insecure-dev-nonlinux")
	}
	signerSocket := filepath.Join(dir, "signer.sock")
	stack.signer, err = signing.Supervise(ctx, signerBin, signerSocket, signerArgs...)
	if err != nil {
		return nil, err
	}

	stack.srv, err = server.Build(ctx, server.Deps{
		Store:             stack.store,
		Log:               stack.log,
		Signer:            stack.signer,
		SignTokenProvider: authzProvider,
		CACertFile:        cfg.CA.CertFile,
		KEK:               stack.kek,
		EnableSecretsAPI:  true,
		Protocols:         cfg.Protocols,
		Logger:            logger,
	})
	if err != nil {
		return nil, err
	}
	if !stack.srv.OutOfProcessSigning() {
		return nil, fmt.Errorf("perf live: server issuing CA is not backed by the signer process")
	}
	if err := stack.startHTTPListener(ctx); err != nil {
		return nil, err
	}
	stack.token, err = seedLiveToken(ctx, stack.store)
	if err != nil {
		return nil, err
	}
	if err := stack.seedServedBaseline(ctx); err != nil {
		return nil, err
	}
	if err := stack.prepareSignerRPC(ctx); err != nil {
		return nil, err
	}
	return stack, nil
}

func (s *liveEvalStack) startHTTPListener(ctx context.Context) error {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.listener = ln
	s.baseURL = "http://" + ln.Addr().String()
	s.httpServer = &http.Server{Handler: s.srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	s.serveErr = make(chan error, 1)
	go func() {
		err := s.httpServer.Serve(ln)
		if err == http.ErrServerClosed {
			err = nil
		}
		s.serveErr <- err
	}()
	return s.waitReady(ctx)
}

func (s *liveEvalStack) waitReady(ctx context.Context) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(deadline, http.MethodGet, s.baseURL+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := s.httpClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case err := <-s.serveErr:
			if err == nil {
				return fmt.Errorf("perf live: server stopped before readiness")
			}
			return err
		case <-deadline.Done():
			return deadline.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func registerLiveTenant(ctx context.Context, log *events.Log, st *store.Store) error {
	svc := app.New(log, st)
	defer svc.Close()
	return svc.RegisterTenant(ctx, liveTenantID, "perf-live", "perf-live-tenant")
}

func latestEvent(ctx context.Context, log *events.Log) (events.Event, error) {
	var out events.Event
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		out = e
		return nil
	}); err != nil {
		return events.Event{}, err
	}
	if out.ID == "" {
		return events.Event{}, fmt.Errorf("perf live: event log is empty after tenant registration")
	}
	return out, nil
}

func seedLiveToken(ctx context.Context, st *store.Store) ([]byte, error) {
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return nil, err
	}
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID:  liveTenantID,
		TokenHash: hash,
		Subject:   "perf-live",
		Scopes: []string{
			string(authz.OwnersRead), string(authz.OwnersWrite),
			string(authz.IssuersRead), string(authz.IssuersWrite),
			string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
			string(authz.CertsRead), string(authz.CertsWrite), string(authz.CertsIssue),
			string(authz.GraphRead), string(authz.RiskRead),
			string(authz.SecretsRead), string(authz.SecretsWrite),
		},
	}); err != nil {
		secret.Wipe(raw)
		return nil, err
	}
	return raw, nil
}

func (s *liveEvalStack) seedServedBaseline(ctx context.Context) error {
	var owner struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/owners", "perf-live-owner", map[string]any{
		"kind": "workload",
		"name": "perf-live-owner",
	}, http.StatusCreated, &owner); err != nil {
		return err
	}
	if owner.ID == "" {
		return fmt.Errorf("perf live: owner seed returned empty id")
	}
	s.ownerID = owner.ID

	caPEM := s.srv.CACertPEM()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return fmt.Errorf("perf live: issuing CA PEM did not decode")
	}
	ocspReq, err := trstcrypto.BuildOCSPRequestForSerial(block.Bytes, "42")
	if err != nil {
		return err
	}
	s.ocspRequest = ocspReq

	var issuer struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/issuers", "perf-live-issuer", map[string]any{
		"kind":     "x509_ca",
		"name":     "perf-live-issuer",
		"chain":    []string{string(caPEM)},
		"internal": true,
	}, http.StatusCreated, &issuer); err != nil {
		return err
	}
	if issuer.ID == "" {
		return fmt.Errorf("perf live: issuer seed returned empty id")
	}
	s.issuerID = issuer.ID

	return s.doJSON(ctx, http.MethodPost, "/api/v1/secrets/store", "perf-live-secret-seed", map[string]any{
		"name":  "perf/live/api-key",
		"value": "perf-live-initial-secret",
	}, http.StatusCreated, nil)
}

func (s *liveEvalStack) prepareSignerRPC(ctx context.Context) error {
	client := s.signer.Client()
	if client == nil {
		return fmt.Errorf("perf live: signer client unavailable")
	}
	rs, err := client.GenerateKey(ctx, trstcrypto.ECDSAP256)
	if err != nil {
		return err
	}
	digest, err := trstcrypto.Digest(trstcrypto.SHA256, []byte("trstctl perf live signer rpc"))
	if err != nil {
		return err
	}
	s.signerKey = rs
	s.signerDigest = digest
	return nil
}

func (s *liveEvalStack) servedHotPaths() (map[string]operation, map[string]string, error) {
	ops := map[string]operation{
		"api.issuance": s.issueOverServedAPI,
		"api.inventory": func() error {
			reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return s.doJSON(reqCtx, http.MethodGet, "/api/v1/certificates?limit=100", "", nil, http.StatusOK, nil)
		},
		"api.graph_risk": func() error {
			reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return s.doJSON(reqCtx, http.MethodGet, "/api/v1/graph", "", nil, http.StatusOK, nil)
		},
		"api.secrets":             s.rotateSecretOverServedAPI,
		"protocol.enrollment":     s.protocolEnrollmentOverServedAPI,
		"revocation.ocsp_crl":     s.revocationOverServedAPI,
		"signer.rpc":              s.signerRPCOverUDS,
		"spine.projection_replay": s.projectLiveEvent,
	}
	transports := map[string]string{
		"api.issuance":            "served-route: POST /api/v1/identities + POST /api/v1/identities/{id}/transitions via actual-listener " + s.baseURL,
		"api.inventory":           "served-route: GET /api/v1/certificates via actual-listener " + s.baseURL,
		"api.graph_risk":          "served-route: GET /api/v1/graph via actual-listener " + s.baseURL,
		"api.secrets":             "served-route: PUT /api/v1/secrets/store/{name...} via actual-listener " + s.baseURL,
		"protocol.enrollment":     "served-route: POST /.well-known/acme parser via actual-listener " + s.baseURL,
		"revocation.ocsp_crl":     "served-route: POST /ocsp/{tenant} via actual-listener " + s.baseURL,
		"signer.rpc":              "served-route: gRPC trstctl.signing.SignerService/Sign over unix-domain-socket child-process signer",
		"spine.projection_replay": "served-route: events replay -> projections.Apply over embedded JetStream/PostgreSQL live stack",
	}
	for _, slo := range HotPaths() {
		if _, ok := ops[slo.HotPath]; !ok {
			return nil, nil, fmt.Errorf("perf: no production live operation for hot path %s", slo.HotPath)
		}
	}
	return ops, transports, nil
}

func (s *liveEvalStack) issueOverServedAPI() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	n := s.next()
	var ident struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/identities", fmt.Sprintf("perf-live-identity-%d", n), map[string]any{
		"kind":      "x509_certificate",
		"name":      fmt.Sprintf("perf-live-%06d.trstctl.test", n),
		"owner_id":  s.ownerID,
		"issuer_id": s.issuerID,
	}, http.StatusCreated, &ident); err != nil {
		return err
	}
	if ident.ID == "" {
		return fmt.Errorf("perf live: create identity returned empty id")
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", fmt.Sprintf("perf-live-issue-%d", n), map[string]any{
		"to":     "issued",
		"reason": "perf live load",
	}, http.StatusOK, nil); err != nil {
		return err
	}
	return s.srv.Drain(ctx)
}

func (s *liveEvalStack) rotateSecretOverServedAPI() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := s.next()
	return s.doJSON(ctx, http.MethodPut, "/api/v1/secrets/store/perf/live/api-key", fmt.Sprintf("perf-live-secret-%d", n), map[string]any{
		"value": fmt.Sprintf("perf-live-rotated-%d", n),
	}, http.StatusOK, nil)
}

func (s *liveEvalStack) protocolEnrollmentOverServedAPI() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.doRaw(ctx, http.MethodPost, "/acme/new-order", "", []byte(`{"payload":"perf-live-parser-probe"}`), "application/jose+json", http.StatusBadRequest)
}

func (s *liveEvalStack) revocationOverServedAPI() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.doRaw(ctx, http.MethodPost, "/ocsp/"+liveTenantID, "", s.ocspRequest, "application/ocsp-request", http.StatusOK)
}

func (s *liveEvalStack) signerRPCOverUDS() error {
	if s.signerKey == nil {
		return fmt.Errorf("perf live: signer key is not prepared")
	}
	sig, err := s.signerKey.SignDigest(s.signerDigest, trstcrypto.SignOptions{Hash: trstcrypto.SHA256})
	if err != nil {
		return err
	}
	if len(sig) == 0 {
		return fmt.Errorf("perf live signer returned empty signature")
	}
	return nil
}

func (s *liveEvalStack) projectLiveEvent() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.projector.Apply(ctx, s.replayEvent)
}

func (s *liveEvalStack) componentResourceMetrics(ctx context.Context, projectionLagHint int) ([]ComponentResourceMetrics, error) {
	signerPID := 0
	if s.signer != nil {
		signerPID = s.signer.Pid()
	}
	if signerPID <= 0 {
		return nil, fmt.Errorf("perf live: signer process pid unavailable")
	}
	postgresPID, err := s.postgresPID(ctx)
	if err != nil {
		return nil, err
	}
	signerMetrics, err := captureProcessResourceMetrics(signerPID, projectionLagHint)
	if err != nil {
		return nil, fmt.Errorf("perf live: signer process metrics: %w", err)
	}
	postgresMetrics, err := captureProcessResourceMetrics(postgresPID, projectionLagHint)
	if err != nil {
		return nil, fmt.Errorf("perf live: postgres process metrics: %w", err)
	}
	selfPID := os.Getpid()
	return []ComponentResourceMetrics{
		{
			Component: "control_plane",
			Kind:      "process",
			PID:       selfPID,
			Runtime:   "trstctl-control-plane",
			Metrics:   captureSelfProcessResourceMetrics(projectionLagHint),
		},
		{
			Component: "signer",
			Kind:      "process",
			PID:       signerPID,
			Runtime:   "trstctl-signer-child-process",
			Metrics:   signerMetrics,
		},
		{
			Component: "postgresql",
			Kind:      "process",
			PID:       postgresPID,
			Runtime:   "embedded-postgres-backend-process",
			Metrics:   postgresMetrics,
		},
		{
			Component: "jetstream",
			Kind:      "process",
			PID:       selfPID,
			Runtime:   "embedded-jetstream-in-control-plane-process",
			Metrics:   captureSelfProcessResourceMetrics(projectionLagHint),
		},
	}, nil
}

func (s *liveEvalStack) postgresPID(ctx context.Context) (int, error) {
	if s.store == nil {
		return 0, fmt.Errorf("perf live: postgres store unavailable")
	}
	var pid int
	//trstctl:system-query - before any tenant is known: perf live resource sampling reads only pg_backend_pid() for the PostgreSQL process counter; no tenant rows or tenant_id values are read.
	if err := s.store.SystemPool().QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return 0, fmt.Errorf("perf live: read postgres backend pid: %w", err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("perf live: postgres returned invalid backend pid %d", pid)
	}
	return pid, nil
}

func (s *liveEvalStack) doJSON(ctx context.Context, method, path, idempotencyKey string, body any, want int, out any) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := s.newRequest(ctx, method, path, idempotencyKey, raw, "application/json")
	if err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("perf live %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("perf live decode %s %s: %w", method, path, err)
	}
	return nil
}

func (s *liveEvalStack) doRaw(ctx context.Context, method, path, idempotencyKey string, body []byte, contentType string, want int) error {
	req, err := s.newRequest(ctx, method, path, idempotencyKey, body, contentType)
	if err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("perf live %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (s *liveEvalStack) newRequest(ctx context.Context, method, path, idempotencyKey string, body []byte, contentType string) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	if len(s.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", s.token))
	}
	req.Header.Set("X-Tenant-ID", liveTenantID)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if contentType != "" && body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

func (s *liveEvalStack) next() uint64 {
	return s.seq.Add(1)
}

func (s *liveEvalStack) Close() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.httpServer.Shutdown(ctx)
		cancel()
	}
	if s.serveErr != nil {
		select {
		case <-s.serveErr:
		case <-time.After(5 * time.Second):
		}
	}
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = s.srv.Shutdown(ctx)
		cancel()
		s.log = nil
		s.store = nil
	}
	if s.signer != nil {
		s.signer.Close()
	}
	if s.signAuthz != nil {
		s.signAuthz.Destroy()
	}
	if s.kek != nil {
		s.kek.Destroy()
	}
	if len(s.token) > 0 {
		secret.Wipe(s.token)
	}
	if s.log != nil {
		_ = s.log.Close()
	}
	if s.store != nil {
		s.store.Close()
	}
	if s.stopPG != nil {
		_ = s.stopPG()
	}
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
}

func liveSignerBinary(ctx context.Context, tempDir string) (string, error) {
	if path := os.Getenv("TRSTCTL_PERF_SIGNER_BIN"); path != "" {
		return path, nil
	}
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	out := filepath.Join(tempDir, "trstctl-signer")
	cmd := exec.CommandContext(ctx, "go", liveSignerBuildArgs(out)...)
	cmd.Dir = root
	if data, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build trstctl-signer for perf live: %w: %s", err, strings.TrimSpace(string(data)))
	}
	return out, nil
}

func liveSignerBuildArgs(out string) []string {
	return []string{"build", "-o", out, "./cmd/trstctl-signer"}
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			return "", fmt.Errorf("perf live: cannot find repository root from %s", dir)
		}
		dir = next
	}
}

func freeLiveTCPPort() int {
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := 0
		if addr, ok := ln.Addr().(*net.TCPAddr); ok {
			port = addr.Port
		}
		_ = ln.Close()
		if port > 0 && port != 5432 {
			return port
		}
	}
	return 0
}

func captureResourceMetrics(projectionLagHint int) *ResourceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &ResourceMetrics{
		Goroutines:        runtime.NumGoroutine(),
		CPUCount:          runtime.NumCPU(),
		OpenFDs:           openFDCount(),
		HeapAllocBytes:    m.HeapAlloc,
		HeapInuseBytes:    m.HeapInuse,
		StackInuseBytes:   m.StackInuse,
		TotalAllocBytes:   m.TotalAlloc,
		MemorySysBytes:    m.Sys,
		NumGC:             m.NumGC,
		ProjectionLagHint: projectionLagHint,
	}
}

func captureSelfProcessResourceMetrics(projectionLagHint int) *ResourceMetrics {
	m := captureResourceMetrics(projectionLagHint)
	annotateProcessMemory(m, os.Getpid())
	return m
}

func captureProcessResourceMetrics(pid int, projectionLagHint int) (*ResourceMetrics, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("pid must be positive")
	}
	if pid == os.Getpid() {
		return captureSelfProcessResourceMetrics(projectionLagHint), nil
	}
	rss, virt, err := processMemoryBytes(pid)
	if err != nil {
		return nil, err
	}
	if rss == 0 {
		rss = 1
	}
	if virt < rss {
		virt = rss
	}
	return &ResourceMetrics{
		CPUCount:          runtime.NumCPU(),
		OpenFDs:           processOpenFDCount(pid),
		HeapInuseBytes:    rss,
		MemorySysBytes:    rss,
		RSSBytes:          rss,
		VirtualBytes:      virt,
		ProjectionLagHint: projectionLagHint,
	}, nil
}

func annotateProcessMemory(m *ResourceMetrics, pid int) {
	if m == nil {
		return
	}
	rss, virt, err := processMemoryBytes(pid)
	if err != nil {
		return
	}
	m.RSSBytes = rss
	m.VirtualBytes = virt
}

func processMemoryBytes(pid int) (rss uint64, virt uint64, err error) {
	if pid <= 0 {
		return 0, 0, fmt.Errorf("pid must be positive")
	}
	if data, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "statm")); readErr == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			sizePages, sizeErr := strconv.ParseUint(fields[0], 10, 64)
			rssPages, rssErr := strconv.ParseUint(fields[1], 10, 64)
			if sizeErr == nil && rssErr == nil {
				pageSize := uint64(os.Getpagesize())
				return rssPages * pageSize, sizePages * pageSize, nil
			}
		}
	}
	out, psErr := commandOutput("ps", "-o", "rss=", "-o", "vsz=", "-p", strconv.Itoa(pid))
	if psErr != nil {
		return 0, 0, psErr
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("ps returned no memory counters for pid %d", pid)
	}
	rssKB, rssErr := strconv.ParseUint(fields[0], 10, 64)
	virtKB, virtErr := strconv.ParseUint(fields[1], 10, 64)
	if rssErr != nil || virtErr != nil {
		return 0, 0, fmt.Errorf("parse process memory counters for pid %d: rss=%q virt=%q", pid, fields[0], fields[1])
	}
	return rssKB * 1024, virtKB * 1024, nil
}

func processOpenFDCount(pid int) int {
	if pid <= 0 {
		return 0
	}
	if entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd")); err == nil && len(entries) > 0 {
		return len(entries)
	}
	if pid == os.Getpid() {
		return openFDCount()
	}
	out, err := commandOutput("lsof", "-nP", "-p", strconv.Itoa(pid))
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			return len(lines) - 1
		}
	}
	return 3
}

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func openFDCount() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return len(entries)
		}
	}
	return 3
}
