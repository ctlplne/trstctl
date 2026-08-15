//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tsa"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodEvalProtocolTenant = "7f1044c5-a9ab-4d2f-96b5-8cb49887ec11"
	dodEvalOtherTenant    = "7f1044c5-a9ab-4d2f-96b5-8cb49887ec12"
)

var dodEvalProtocolNames = []string{"acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"}

// TestDODEvalProtocolProfileProductionAssembly proves the shipped evaluation
// profile from the binary's production assembly seam. It never constructs Deps or
// a protocol registry: buildRunDeps resolves the named profile, Build mounts it,
// the authenticated activation route opens it, and a real TCP listener plus the
// production SPIFFE UDS carry seven protocol-shaped client exchanges. A separate
// digest-pinned process validates the resulting artifacts with OpenSSL/OpenSSH.
func TestDODEvalProtocolProfileProductionAssembly(t *testing.T) {
	_ = dodRuntimeSelection(t, "protocol_ergonomics.eval_profile")
	ctx := context.Background()
	dir := t.TempDir()
	external := proof.StartCommand(t, "protocol_ergonomics.eval_profile")

	scepConfig, scepChallenge := dodEvalIntuneChallenge(t, "eval-scep-device")
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(dir, "control-plane-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(dir, "signer-keys")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	cfg.Protocols.Profile = config.ProtocolProfileEval
	cfg.Protocols.EvalTenantID = dodEvalProtocolTenant
	cfg.Protocols.RAKeyFile = filepath.Join(dir, "protocol-ra.key")
	cfg.Protocols.TSACertFile = filepath.Join(dir, "tsa.crt")
	cfg.Protocols.SPIFFE.SocketPath = dodEvalLocalSocketPath(t)
	cfg.Protocols.SCEPIntuneChallenge = scepConfig
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate eval-profile production config: %v", err)
	}

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		t.Fatalf("load production secrets: %v", err)
	}
	t.Cleanup(runSecrets.Close)
	signer, reconnectSigner := dodEvalStartShippedSigner(t, dir)

	challengeAddress, stopChallenge := dodEvalStartChallengeServer(t)
	defer stopChallenge()
	validatorTransport := http.DefaultTransport.(*http.Transport).Clone()
	validatorTransport.Proxy = nil
	validatorTransport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dialCtx, network, challengeAddress)
	}
	validators := &acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{Client: &http.Client{Transport: validatorTransport, Timeout: 10 * time.Second}},
		DNS01:  acmesrv.DNS01Validator{},
	}

	firstServer := dodEvalBuildServer(t, ctx, cfg, st, log, signer, runSecrets, validators)
	first := dodEvalServeRuntime(t, ctx, firstServer)
	firstClosed := false
	defer func() {
		if !firstClosed {
			first.Close(t)
		}
	}()
	preActivation := dodEvalAssertFailClosed(t, first)

	otherToken := dodSeedAPIToken(t, ctx, st, dodEvalOtherTenant, "other-tenant-operator", []string{string(authz.IssuersWrite)})
	wrongStatus, wrongBody := dodEvalJSONRequest(t, first.Client(), http.MethodPost,
		first.BaseURL()+"/api/v1/setup/protocols/activate", otherToken, dodEvalOtherTenant,
		"eval-profile-cross-tenant-denied", nil)
	if wrongStatus != http.StatusForbidden {
		t.Fatalf("cross-tenant activation status=%d body=%s, want 403", wrongStatus, wrongBody)
	}
	_ = dodEvalAssertFailClosed(t, first)

	operatorToken := dodSeedAPIToken(t, ctx, st, dodEvalProtocolTenant, "eval-profile-operator", []string{
		string(authz.IssuersRead), string(authz.IssuersWrite),
	})
	activationRequest := dodEvalAPIRequest(t, http.MethodPost, "/api/v1/setup/protocols/activate",
		operatorToken, dodEvalProtocolTenant, "eval-profile-activate", nil)
	session := proof.Start(t, "protocol_ergonomics.eval_profile", firstServer.Handler(), activationRequest)
	if session.StatusCode() != http.StatusOK {
		t.Fatalf("activate eval profile status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	var activation api.ProtocolProfileStatus
	if err := json.Unmarshal(session.ResponseBody(), &activation); err != nil {
		t.Fatalf("decode activation response: %v; body=%s", err, session.ResponseBody())
	}
	if !activation.Active || activation.Profile != config.ProtocolProfileEval || !slices.Equal(activation.Protocols, dodEvalProtocolNames) {
		t.Fatalf("activation response=%+v, want exact active eval profile %v", activation, dodEvalProtocolNames)
	}
	if got := first.Server().ServedProtocols(); !slices.Equal(got, dodEvalProtocolNames) {
		t.Fatalf("served protocols after activation=%v, want %v", got, dodEvalProtocolNames)
	}
	dodEvalWaitForSocket(t, cfg.Protocols.SPIFFE.SocketPath)

	caPEM := first.Server().CACertPEM()
	caDER := dodEvalCACertDER(t, caPEM)
	estToken := dodSeedAPIToken(t, ctx, st, dodEvalProtocolTenant, "eval-est-device", []string{"certs:request"})
	// SSH issuance names its own principals, so it requires certs:issue.
	sshToken := dodSeedAPIToken(t, ctx, st, dodEvalProtocolTenant, "eval-ssh-operator", []string{"certs:issue"})
	artifacts := map[string]any{}
	artifacts["acme"] = dodEvalEnrollACME(t, first.Client(), first.BaseURL(), challengeAddress, caDER)
	artifacts["est"] = dodEvalEnrollEST(t, first.Client(), first.BaseURL(), estToken, caDER)
	artifacts["scep"] = dodEvalEnrollSCEP(t, first.Client(), first.BaseURL(), scepChallenge, caDER)
	artifacts["cmp"] = dodEvalEnrollCMP(t, first.Client(), first.BaseURL(), "eval-cmp-device-1", []byte("eval-profile-cmp-1"), caDER)
	sshArtifact, sshCA := dodEvalIssueSSH(t, first.Client(), first.BaseURL(), sshToken)
	artifacts["ssh"] = sshArtifact
	tsaArtifact, _ := dodEvalTimestamp(t, first.Client(), first.BaseURL(), "first-eval-timestamp")
	artifacts["tsa"] = tsaArtifact
	spiffeArtifact, _ := dodEvalFetchSPIFFE(t, cfg.Protocols.SPIFFE.SocketPath, caDER)
	artifacts["spiffe"] = spiffeArtifact

	firstSCEPCA := dodEvalGetBody(t, first.Client(), first.BaseURL()+"/scep?operation=GetCACert", http.StatusOK)
	firstESTCA := dodEvalGetBody(t, first.Client(), first.BaseURL()+"/.well-known/est/cacerts", http.StatusOK)
	firstDirectory := dodEvalGetBody(t, first.Client(), first.BaseURL()+"/directory", http.StatusOK)
	firstDirectoryCanonical := dodEvalCanonicalACMEDirectory(t, firstDirectory)
	first.Close(t)
	firstClosed = true
	signer = reconnectSigner()

	restartedStore, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("reopen PostgreSQL after server shutdown: %v", err)
	}
	restartedLog, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		restartedStore.Close()
		t.Fatalf("reopen event log after server shutdown: %v", err)
	}
	secondServer := dodEvalBuildServer(t, ctx, cfg, restartedStore, restartedLog, signer, runSecrets, validators)
	second := dodEvalServeRuntime(t, ctx, secondServer)
	defer second.Close(t)
	dodEvalWaitForSocket(t, cfg.Protocols.SPIFFE.SocketPath)
	if got := second.Server().ServedProtocols(); !slices.Equal(got, dodEvalProtocolNames) {
		t.Fatalf("restart served protocols=%v, want replayed %v", got, dodEvalProtocolNames)
	}
	statusCode, statusBody := dodEvalJSONRequest(t, second.Client(), http.MethodGet,
		second.BaseURL()+"/api/v1/setup/protocols", operatorToken, dodEvalProtocolTenant, "", nil)
	if statusCode != http.StatusOK {
		t.Fatalf("restart eval status=%d body=%s", statusCode, statusBody)
	}
	var replayed api.ProtocolProfileStatus
	if err := json.Unmarshal(statusBody, &replayed); err != nil || !replayed.Active || !slices.Equal(replayed.Protocols, dodEvalProtocolNames) {
		t.Fatalf("restart profile status=%+v err=%v", replayed, err)
	}

	restartReadbacks := map[string]string{}
	restartDirectory := dodEvalGetBody(t, second.Client(), second.BaseURL()+"/directory", http.StatusOK)
	restartDirectoryCanonical := dodEvalCanonicalACMEDirectory(t, restartDirectory)
	if !bytes.Equal(firstDirectoryCanonical, restartDirectoryCanonical) {
		t.Fatal("ACME directory changed across activation replay")
	}
	restartReadbacks["acme"] = crypto.SHA256Hex(restartDirectoryCanonical)
	restartESTCA := dodEvalGetBody(t, second.Client(), second.BaseURL()+"/.well-known/est/cacerts", http.StatusOK)
	if !bytes.Equal(firstESTCA, restartESTCA) {
		t.Fatal("EST CA readback changed across restart")
	}
	restartReadbacks["est"] = crypto.SHA256Hex(restartESTCA)
	restartSCEPCA := dodEvalGetBody(t, second.Client(), second.BaseURL()+"/scep?operation=GetCACert", http.StatusOK)
	if !bytes.Equal(firstSCEPCA, restartSCEPCA) {
		t.Fatal("SCEP RA/CA readback changed across restart")
	}
	restartReadbacks["scep"] = crypto.SHA256Hex(restartSCEPCA)
	restartCMP := dodEvalEnrollCMP(t, second.Client(), second.BaseURL(), "eval-cmp-device-2", []byte("eval-profile-cmp-2"), caDER)
	restartReadbacks["cmp"] = crypto.SHA256Hex(restartCMP["response_der"].([]byte))
	restartSSHCA := dodEvalGetBody(t, second.Client(), second.BaseURL()+"/ssh/ca", http.StatusOK)
	if !bytes.Equal(sshCA, restartSSHCA) {
		t.Fatal("SSH CA authority changed across restart")
	}
	restartReadbacks["ssh"] = crypto.SHA256Hex(restartSSHCA)
	_, restartTSA := dodEvalTimestamp(t, second.Client(), second.BaseURL(), "restart-eval-timestamp")
	restartReadbacks["tsa"] = crypto.SHA256Hex(restartTSA)
	_, restartSPIFFE := dodEvalFetchSPIFFE(t, cfg.Protocols.SPIFFE.SocketPath, caDER)
	restartReadbacks["spiffe"] = crypto.SHA256Hex(restartSPIFFE)

	eventCounts := dodEvalTenantEventCounts(t, restartedLog, dodEvalProtocolTenant)
	if eventCounts[protocolEvalProfileActivatedEvent] != 1 {
		t.Fatalf("activation tenant event count=%d, want exactly 1", eventCounts[protocolEvalProfileActivatedEvent])
	}
	if eventCounts["certificate.recorded"] < 5 || eventCounts["ssh.cert.issued"] < 1 ||
		eventCounts["tsa.timestamp.issued"] < 2 || eventCounts["spiffe.svid.issued"] < 2 {
		t.Fatalf("tenant protocol event counts are incomplete: %+v", eventCounts)
	}

	transcriptValue := map[string]any{
		"profile": config.ProtocolProfileEval, "tenant_id": dodEvalProtocolTenant,
		"pre_activation": preActivation, "cross_tenant_status": wrongStatus,
		"activation": map[string]any{"active": activation.Active, "protocols": activation.Protocols},
		"artifacts":  artifacts, "ca_pem": string(caPEM), "tenant_events": eventCounts,
		"restart": map[string]any{"active": replayed.Active, "protocols": replayed.Protocols, "readbacks": restartReadbacks},
	}
	transcript, err := json.Marshal(transcriptValue)
	if err != nil {
		t.Fatalf("marshal independent protocol transcript: %v", err)
	}
	verification := dodEvalExternalVerify(t, external.Endpoint(), transcript)
	readback := dodEvalExternalReadback(t, external.Endpoint())
	if !bytes.Equal(verification, readback) {
		t.Fatal("independent verifier readback did not match its accepted transcript receipt")
	}
	contract, err := os.ReadFile("../../tools/dodcensus/contracts/eval-protocol-interop-v1.json")
	if err != nil {
		t.Fatalf("read eval protocol interop contract: %v", err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity:      []byte("x/crypto/acme|RFC7030|RFC8894|RFC4210|OpenSSH|RFC3161|SPIFFE-Workload-API"),
		Transcript:          append(transcript, contract...),
		IndependentVerifier: readback,
		ExecutionReceipt:    executionReceipt,
	}))
}

// dodEvalLocalSocketPath keeps the Workload API UDS on the shipped runtime's
// local filesystem. The rest of the proof state intentionally lives on the
// parent-owned receipt mount, but Docker Desktop bind mounts are not a valid
// host-local Unix-socket substrate and can reject listen/chmod operations. This
// mirrors the production default (/tmp/trstctl-spiffe-workload.sock) while using
// a unique directory so concurrent proof processes cannot collide.
func dodEvalLocalSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "trstctl-dod-spiffe-")
	if err != nil {
		t.Fatalf("create runtime-local SPIFFE socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "workload.sock")
}

type dodEvalRuntime struct {
	srv        *Server
	listener   net.Listener
	httpServer *http.Server
	baseURL    string
	client     *http.Client
	cancel     context.CancelFunc
	spiffeDone chan struct{}
	serveDone  chan error
	closeOnce  sync.Once
}

func dodEvalBuildServer(t *testing.T, ctx context.Context, cfg *config.Config, st *store.Store, log *events.Log,
	signer runSigner, sec runSecrets, validators *acmesrv.Validators,
) *Server {
	t.Helper()
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		t.Fatalf("build eval-profile egress guard: %v", err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, sec,
		slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		t.Fatalf("production buildRunDeps: %v", err)
	}
	// The shipped ACME validator is still selected through Build. This test-only
	// transport makes its real HTTP-01 fetch deterministic on an isolated loopback
	// listener; it does not replace the protocol server or the production registry.
	deps.ACMEValidators = validators
	srv, err := Build(ctx, deps)
	if err != nil {
		t.Fatalf("Build production eval-profile deps: %v", err)
	}
	if !srv.OutOfProcessSigning() {
		_ = srv.Shutdown(context.Background())
		t.Fatal("eval protocol runtime did not use the shipped out-of-process signer")
	}
	return srv
}

func dodEvalServeRuntime(t *testing.T, ctx context.Context, srv *Server) *dodEvalRuntime {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.Shutdown(context.Background())
		t.Fatalf("listen for assembled eval-profile handler: %v", err)
	}
	httpServer := &http.Server{
		Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	spiffeCtx, cancel := context.WithCancel(ctx)
	spiffeDone := make(chan struct{})
	go func() {
		defer close(spiffeDone)
		srv.RunSPIFFE(spiffeCtx)
	}()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &dodEvalRuntime{
		srv: srv, listener: listener, httpServer: httpServer,
		baseURL: "http://" + listener.Addr().String(),
		client:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		cancel:  cancel, spiffeDone: spiffeDone, serveDone: serveDone,
	}
}

func (r *dodEvalRuntime) Server() *Server      { return r.srv }
func (r *dodEvalRuntime) BaseURL() string      { return r.baseURL }
func (r *dodEvalRuntime) Client() *http.Client { return r.client }

func (r *dodEvalRuntime) Close(t *testing.T) {
	t.Helper()
	r.closeOnce.Do(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = r.httpServer.Shutdown(closeCtx)
		if transport, ok := r.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		r.cancel()
		select {
		case <-r.spiffeDone:
		case <-time.After(10 * time.Second):
			t.Error("SPIFFE worker did not stop")
		}
		select {
		case err := <-r.serveDone:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("assembled HTTP server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("assembled HTTP server did not stop")
		}
		if err := r.srv.Shutdown(closeCtx); err != nil {
			t.Errorf("shutdown assembled eval-profile server: %v", err)
		}
	})
}

func dodEvalStartShippedSigner(t *testing.T, dir string) (runSigner, func() runSigner) {
	t.Helper()
	authFile := filepath.Join(dir, "signer-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("load signer content authorizer: %v", err)
	}
	t.Cleanup(authorizer.Destroy)
	return dodStartRestartableShippedSignerProcess(t, dir, "eval-protocols", authFile, "", authorizer)
}

func dodEvalStartChallengeServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for ACME HTTP-01 responder: %v", err)
	}
	mux := http.NewServeMux()
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = server.Close()
			<-done
		})
	}
	// The ACME helper registers challenge handlers on this exact mux through the
	// process-local registry below; it is a real TCP server, never httptest.
	dodEvalChallengeMuxes.Store(listener.Addr().String(), mux)
	return listener.Addr().String(), func() {
		dodEvalChallengeMuxes.Delete(listener.Addr().String())
		stop()
	}
}

var dodEvalChallengeMuxes sync.Map

func dodEvalAssertFailClosed(t *testing.T, runtime *dodEvalRuntime) map[string]any {
	t.Helper()
	checks := []struct {
		name, method, path, contentType string
		body                            []byte
	}{
		{name: "acme", method: http.MethodGet, path: "/directory"},
		{name: "est", method: http.MethodGet, path: "/.well-known/est/cacerts"},
		{name: "scep", method: http.MethodGet, path: "/scep?operation=GetCACert"},
		{name: "cmp", method: http.MethodPost, path: "/cmp", contentType: "application/pkixcmp", body: []byte{0x30, 0x00}},
		{name: "ssh", method: http.MethodGet, path: "/ssh/ca"},
		{name: "tsa", method: http.MethodPost, path: "/tsa", contentType: tsa.ContentTypeQuery, body: []byte{0x30, 0x00}},
	}
	observed := make(map[string]any, len(checks)+1)
	for _, check := range checks {
		request, err := http.NewRequest(check.method, runtime.BaseURL()+check.path, bytes.NewReader(check.body))
		if err != nil {
			t.Fatal(err)
		}
		if check.contentType != "" {
			request.Header.Set("Content-Type", check.contentType)
		}
		response, err := runtime.Client().Do(request)
		if err != nil {
			t.Fatalf("pre-activation %s request: %v", check.name, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatalf("pre-activation %s response: %v", check.name, readErr)
		}
		if response.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(body, []byte("eval protocol profile is not active")) {
			t.Fatalf("pre-activation %s status=%d body=%s, want fail-closed 503", check.name, response.StatusCode, body)
		}
		observed[check.name] = response.StatusCode
	}
	if got := runtime.Server().ServedProtocols(); len(got) != 0 {
		t.Fatalf("pre-activation ServedProtocols=%v, want none", got)
	}
	if _, err := os.Stat(runtime.Server().SPIFFESocket()); !os.IsNotExist(err) {
		t.Fatalf("pre-activation SPIFFE socket exists or is not fail-closed: %v", err)
	}
	conn, err := net.DialTimeout("unix", runtime.Server().SPIFFESocket(), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("pre-activation SPIFFE UDS accepted a connection")
	}
	observed["spiffe"] = "socket-absent"
	return observed
}

func dodEvalAPIRequest(t *testing.T, method, path, token, tenantID, idempotencyKey string, body any) *http.Request {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	} else if method != http.MethodGet && method != http.MethodHead {
		raw = []byte("{}")
	}
	request, err := http.NewRequest(method, "http://trstctl.invalid"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Tenant-ID", tenantID)
	if len(raw) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	return request
}

func dodEvalJSONRequest(t *testing.T, client *http.Client, method, target, token, tenantID, idempotencyKey string, body any) (int, []byte) {
	t.Helper()
	path := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		index := strings.Index(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"), "/")
		if index < 0 {
			t.Fatalf("target %q has no path", target)
		}
		schemeLength := len(target) - len(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"))
		path = target[schemeLength+index:]
	}
	request := dodEvalAPIRequest(t, method, path, token, tenantID, idempotencyKey, body)
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(strings.Split(target, path)[0], "http://")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s %s: %v", method, target, err)
	}
	return response.StatusCode, raw
}

func dodEvalGetBody(t *testing.T, client *http.Client, target string, wantStatus int) []byte {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatalf("read GET %s: %v", target, err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("GET %s status=%d body=%s, want %d", target, response.StatusCode, body, wantStatus)
	}
	return body
}

func dodEvalIntuneChallenge(t *testing.T, commonName string) (config.SCEPIntuneChallenge, string) {
	t.Helper()
	issuer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatalf("generate eval Intune challenge issuer: %v", err)
	}
	t.Cleanup(issuer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(issuer, "Eval Intune Connector", time.Hour)
	if err != nil {
		t.Fatalf("create eval Intune trust anchor: %v", err)
	}
	now := time.Now().UTC()
	encode := base64.RawURLEncoding.EncodeToString
	marshal := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encode(raw)
	}
	protected := marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	payload := marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(20 * time.Minute).Unix(),
		"nonce": "dod-eval-" + commonName, "device_name": commonName,
	})
	signingInput := protected + "." + payload
	signature, err := crypto.SignMessage(issuer, []byte(signingInput))
	if err != nil {
		t.Fatalf("sign eval Intune challenge: %v", err)
	}
	return config.SCEPIntuneChallenge{TrustAnchorsDER: [][]byte{trustDER}}, signingInput + "." + encode(signature)
}

type dodEvalWireRecorder struct {
	transport http.RoundTripper
	mu        sync.Mutex
	records   []string
}

func (r *dodEvalWireRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.transport.RoundTrip(request)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	r.mu.Lock()
	r.records = append(r.records, fmt.Sprintf("%s %s %d", request.Method, request.URL.EscapedPath(), status))
	r.mu.Unlock()
	return response, err
}

func (r *dodEvalWireRecorder) Records() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.records...)
}

func dodEvalEnrollACME(t *testing.T, client *http.Client, baseURL, challengeAddress string, caDER []byte) map[string]any {
	t.Helper()
	value, ok := dodEvalChallengeMuxes.Load(challengeAddress)
	if !ok {
		t.Fatal("ACME challenge mux is unavailable")
	}
	mux := value.(*http.ServeMux)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	recorder := &dodEvalWireRecorder{transport: transport}
	accountKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate ACME account key: %v", err)
	}
	defer accountKey.Destroy()
	acmeClient, err := acmekey.NewClientWithDigestSigner(baseURL+"/directory", &http.Client{Transport: recorder, Timeout: 20 * time.Second}, accountKey)
	if err != nil {
		t.Fatalf("create stock ACME client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	directory, err := acmeClient.Discover(ctx)
	if err != nil || directory.RevokeURL == "" {
		t.Fatalf("discover ACME directory: directory=%+v err=%v", directory, err)
	}
	if _, err := acmeClient.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register ACME account: %v", err)
	}
	const domain = "eval-profile-dod.local"
	order, err := acmeClient.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("create ACME order: %v", err)
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := acmeClient.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			t.Fatalf("get ACME authorization: %v", err)
		}
		var challenge *xacme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate.Type == "http-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			t.Fatal("eval ACME profile did not offer HTTP-01")
		}
		response, err := acmeClient.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			t.Fatalf("build HTTP-01 response: %v", err)
		}
		path := acmeClient.HTTP01ChallengePath(challenge.Token)
		mux.HandleFunc(path, func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, response) })
		if _, err := acmeClient.Accept(ctx, challenge); err != nil {
			t.Fatalf("accept HTTP-01 challenge: %v", err)
		}
		if _, err := acmeClient.WaitAuthorization(ctx, authorizationURL); err != nil {
			t.Fatalf("wait for HTTP-01 authorization: %v", err)
		}
	}
	order, err = acmeClient.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("wait for ACME order: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: domain, DNSNames: []string{domain}}, leafKey)
	if err != nil {
		t.Fatalf("create ACME CSR: %v", err)
	}
	chain, _, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("finalize ACME order: chain=%d err=%v", len(chain), err)
	}
	if err := crypto.VerifyLeafSignedByCA(chain[0], caDER); err != nil {
		t.Fatalf("ACME leaf does not chain to served CA: %v", err)
	}
	info, err := certinfo.Inspect(chain[0])
	if err != nil || !slices.Contains(info.DNSNames, domain) {
		t.Fatalf("ACME leaf SANs=%v err=%v", info.DNSNames, err)
	}
	wire := recorder.Records()
	if len(wire) < 8 {
		t.Fatalf("ACME exchange recorded only %d wire operations: %v", len(wire), wire)
	}
	return map[string]any{"certificate_der": chain[0], "csr_der": csrDER, "wire": wire}
}

func dodEvalEnrollEST(t *testing.T, client *http.Client, baseURL, token string, caDER []byte) map[string]any {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "eval-est-device"}, key)
	if err != nil {
		t.Fatalf("create EST CSR: %v", err)
	}
	requestBody := []byte(base64.StdEncoding.EncodeToString(csrDER))
	request, err := http.NewRequest(http.MethodPost, baseURL+"/.well-known/est/simpleenroll", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/pkcs10")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("EST simpleenroll: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("EST simpleenroll status=%d err=%v body=%s", response.StatusCode, err, body)
	}
	pkcs7DER, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(body)))
	if err != nil {
		t.Fatalf("decode EST PKCS7 response: %v", err)
	}
	certificates, err := crypto.CertsFromPKCS7(pkcs7DER)
	if err != nil || len(certificates) == 0 {
		t.Fatalf("parse EST PKCS7 response: certs=%d err=%v", len(certificates), err)
	}
	leaf := certificates[0]
	if err := crypto.VerifyLeafSignedByCA(leaf, caDER); err != nil {
		t.Fatalf("EST leaf does not chain to served CA: %v", err)
	}
	return map[string]any{"request_csr_der": csrDER, "response_pkcs7_der": pkcs7DER, "certificate_der": leaf}
}

func dodEvalClientMaterial(t *testing.T, commonName, challenge string) (certDER, keyPKCS8, csrDER []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	certDER, err = crypto.SelfSignedCACert(signer, commonName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err = crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: commonName, ChallengePassword: []byte(challenge),
	}, signer)
	if err != nil {
		secret.Wipe(keyPKCS8)
		t.Fatal(err)
	}
	return certDER, keyPKCS8, csrDER
}

func dodEvalSCEPRARecipient(t *testing.T, body []byte) []byte {
	t.Helper()
	certificates, err := crypto.CertsFromPKCS7(body)
	if err != nil {
		certificates = [][]byte{body}
	}
	for _, certificate := range certificates {
		info, inspectErr := certinfo.Inspect(certificate)
		if inspectErr == nil && info.KeyAlgorithm == "RSA" {
			return certificate
		}
	}
	t.Fatal("SCEP GetCACert response omitted its RSA RA recipient")
	return nil
}

func dodEvalEnrollSCEP(t *testing.T, client *http.Client, baseURL, challenge string, caDER []byte) map[string]any {
	t.Helper()
	caBody := dodEvalGetBody(t, client, baseURL+"/scep?operation=GetCACert", http.StatusOK)
	raCertDER := dodEvalSCEPRARecipient(t, caBody)
	clientCertDER, clientKeyPKCS8, csrDER := dodEvalClientMaterial(t, "eval-scep-device", challenge)
	defer secret.Wipe(clientKeyPKCS8)
	requestDER, err := crypto.BuildSCEPRequest(csrDER, clientCertDER, clientKeyPKCS8, raCertDER, "dod-eval-scep-transaction")
	if err != nil {
		t.Fatalf("build SCEP PKIOperation: %v", err)
	}
	response, err := client.Post(baseURL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(requestDER))
	if err != nil {
		t.Fatalf("SCEP PKIOperation: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseDER, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("SCEP PKIOperation status=%d err=%v body=%x", response.StatusCode, err, responseDER)
	}
	issuedDER, err := crypto.ParseSCEPResponse(responseDER, clientCertDER, clientKeyPKCS8)
	if err != nil {
		t.Fatalf("parse SCEP CertRep: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issuedDER, caDER); err != nil {
		t.Fatalf("SCEP leaf does not chain to served CA: %v", err)
	}
	return map[string]any{"request_der": requestDER, "response_der": responseDER, "certificate_der": issuedDER, "get_ca_der": caBody}
}

func dodEvalEnrollCMP(t *testing.T, client *http.Client, baseURL, commonName string, transactionID, caDER []byte) map[string]any {
	t.Helper()
	clientCertDER, clientKeyPKCS8, csrDER := dodEvalClientMaterial(t, commonName, "")
	defer secret.Wipe(clientKeyPKCS8)
	nonce := crypto.SHA256Sum(append([]byte("cmp-nonce:"), transactionID...))[:16]
	requestDER, err := crypto.BuildCMPRequest(csrDER, clientCertDER, clientKeyPKCS8, transactionID, nonce)
	if err != nil {
		t.Fatalf("build CMP p10cr: %v", err)
	}
	response, err := client.Post(baseURL+"/cmp", "application/pkixcmp", bytes.NewReader(requestDER))
	if err != nil {
		t.Fatalf("CMP p10cr: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseDER, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CMP p10cr status=%d err=%v body=%x", response.StatusCode, err, responseDER)
	}
	issuedDER, err := crypto.ParseCMPResponse(responseDER)
	if err != nil {
		t.Fatalf("parse CMP response: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issuedDER, caDER); err != nil {
		t.Fatalf("CMP leaf does not chain to served CA: %v", err)
	}
	return map[string]any{"request_der": requestDER, "response_der": responseDER, "certificate_der": issuedDER}
}

func dodEvalIssueSSH(t *testing.T, client *http.Client, baseURL, bearer string) (map[string]any, []byte) {
	t.Helper()
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	publicKey, err := crypto.SSHPublicKeyFromSigner(subject)
	if err != nil {
		t.Fatalf("create SSH subject public key: %v", err)
	}
	requestBody, err := json.Marshal(sshIssueRequest{
		PublicKey: string(publicKey), KeyID: "eval-user@trstctl", Principals: []string{"eval-user"}, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	issueRequest, err := http.NewRequest(http.MethodPost, baseURL+"/ssh/issue/user", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	issueRequest.Header.Set("Content-Type", "application/json")
	issueRequest.Header.Set("Authorization", "Bearer "+bearer)
	response, err := client.Do(issueRequest)
	if err != nil {
		t.Fatalf("issue SSH user certificate: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var issued sshIssueResponse
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("SSH issue status=%d body=%s", response.StatusCode, body)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&issued); err != nil {
		t.Fatalf("decode SSH issue response: %v", err)
	}
	if issued.Certificate == "" || issued.Serial == 0 {
		t.Fatalf("SSH issue response is incomplete: %+v", issued)
	}
	caKey := dodEvalGetBody(t, client, baseURL+"/ssh/ca", http.StatusOK)
	return map[string]any{"certificate": issued.Certificate, "ca": string(caKey), "serial": issued.Serial}, caKey
}

type dodEvalASN1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type dodEvalASN1MessageImprint struct {
	HashAlgorithm dodEvalASN1AlgorithmIdentifier
	HashedMessage []byte
}

type dodEvalASN1TimeStampRequest struct {
	Version        int
	MessageImprint dodEvalASN1MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

func dodEvalTimestamp(t *testing.T, client *http.Client, baseURL, label string) (map[string]any, []byte) {
	t.Helper()
	imprint := crypto.SHA256Sum([]byte("trstctl eval protocol timestamp: " + label))
	requestDER, err := asn1.Marshal(dodEvalASN1TimeStampRequest{
		Version: 1,
		MessageImprint: dodEvalASN1MessageImprint{
			HashAlgorithm: dodEvalASN1AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
			HashedMessage: imprint,
		},
		Nonce: big.NewInt(time.Now().UnixNano()), CertReq: true,
	})
	if err != nil {
		t.Fatalf("marshal RFC 3161 TimeStampReq: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/tsa", bytes.NewReader(requestDER))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", tsa.ContentTypeQuery)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST RFC 3161 TimeStampReq: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseDER, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != tsa.ContentTypeReply {
		t.Fatalf("TSA status=%d content-type=%q err=%v body=%x", response.StatusCode, response.Header.Get("Content-Type"), err, responseDER)
	}
	return map[string]any{"request_der": requestDER, "response_der": responseDER}, responseDER
}

func dodEvalFetchSPIFFE(t *testing.T, socket string, caDER []byte) (map[string]any, []byte) {
	t.Helper()
	connection, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create SPIFFE Workload API client: %v", err)
	}
	defer func() { _ = connection.Close() }()
	client := workloadpb.NewSpiffeWorkloadAPIClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(spiffe.SecurityHeaderKey, spiffe.SecurityHeaderValue))
	stream, err := client.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	response, err := stream.Recv()
	if err != nil || len(response.GetSvids()) == 0 {
		t.Fatalf("receive X509SVIDResponse: svids=%d err=%v", len(response.GetSvids()), err)
	}
	svid := response.GetSvids()[0]
	if svid.GetSpiffeId() != "spiffe://"+config.DefaultEvalSPIFFETrustDomain+"/workload" || len(svid.GetX509SvidKey()) == 0 || len(svid.GetBundle()) == 0 {
		t.Fatalf("SPIFFE SVID response is incomplete: id=%q key=%d bundle=%d", svid.GetSpiffeId(), len(svid.GetX509SvidKey()), len(svid.GetBundle()))
	}
	if err := crypto.VerifyLeafSignedByCA(svid.GetX509Svid(), caDER); err != nil {
		t.Fatalf("SPIFFE SVID does not chain to served CA: %v", err)
	}
	identity, err := crypto.SPIFFEIDFromCert(svid.GetX509Svid())
	if err != nil || identity != svid.GetSpiffeId() {
		t.Fatalf("SPIFFE SVID URI SAN=%q err=%v", identity, err)
	}
	privateKeyPresent := len(svid.GetX509SvidKey()) > 0
	secret.Wipe(svid.X509SvidKey)
	return map[string]any{
		"id": svid.GetSpiffeId(), "certificate_der": svid.GetX509Svid(),
		"bundle_der": svid.GetBundle(), "private_key_present": privateKeyPresent,
	}, svid.GetX509Svid()
}

func dodEvalCACertDER(t *testing.T, caPEM []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("assembled server CA output is not one canonical certificate PEM")
	}
	return append([]byte(nil), block.Bytes...)
}

func dodEvalWaitForSocket(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("SPIFFE Workload API socket %q did not become reachable", socket)
}

func dodEvalCanonicalACMEDirectory(t *testing.T, body []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode ACME directory for restart comparison: %v", err)
	}
	var canonicalize func(any) any
	canonicalize = func(current any) any {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				typed[key] = canonicalize(child)
			}
			return typed
		case []any:
			for index, child := range typed {
				typed[index] = canonicalize(child)
			}
			return typed
		case string:
			parsed, err := url.Parse(typed)
			if err == nil && parsed.IsAbs() && parsed.Host != "" {
				parsed.Scheme = ""
				parsed.Host = ""
				return parsed.String()
			}
		}
		return current
	}
	canonical, err := json.Marshal(canonicalize(value))
	if err != nil {
		t.Fatalf("encode canonical ACME directory: %v", err)
	}
	return canonical
}

func dodEvalTenantEventCounts(t *testing.T, log *events.Log, tenantID string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == tenantID {
			counts[event.Type]++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay tenant protocol events: %v", err)
	}
	return counts
}

func dodEvalExternalVerify(t *testing.T, endpoint string, transcript []byte) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint+"/dod/verify", bytes.NewReader(transcript))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 60 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("independent protocol verifier: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("independent protocol verifier status=%d bytes=%d err=%v body=%s", response.StatusCode, len(body), err, body)
	}
	return body
}

func dodEvalExternalReadback(t *testing.T, endpoint string) []byte {
	t.Helper()
	response, err := (&http.Client{Timeout: 10 * time.Second}).Get(endpoint + "/dod/readback")
	if err != nil {
		t.Fatalf("independent protocol verifier readback: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("independent verifier readback status=%d bytes=%d err=%v body=%s", response.StatusCode, len(body), err, body)
	}
	return body
}
