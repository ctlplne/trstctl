//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentk8s "trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodKubernetesTenant          = "d0d00000-0000-4000-8000-000000000084"
	dodKubernetesAgentServerName = "agent.trstctl.local"
	dodKubernetesNodeImage       = "kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b"
	dodKindConfigReadyTimeout    = 6 * time.Minute
	dodKindConfigAttemptTimeout  = 30 * time.Second
	dodKindConfigRetryDelay      = 500 * time.Millisecond
)

// TestDODKubernetesPostureRoutesProductionAssembly proves both former static
// descriptor routes through the shipped composition edge. A digest-pinned real
// kind cluster is reconciled by IssuerController, its result crosses the served
// agent mTLS channel, PostgreSQL projects the immutable event, and the
// authenticated HTTP route is independently compared with the live cluster.
func TestDODKubernetesPostureRoutesProductionAssembly(t *testing.T) {
	only := dodRuntimeSelection(t,
		"k8s_posture_routes.certificate_signing_requests",
		"k8s_posture_routes.trust_bundles",
	)
	if only == "" || only == "k8s_posture_routes.certificate_signing_requests" {
		external := proof.StartCommand(t, "k8s_posture_routes.certificate_signing_requests")
		dodRunKubernetesCSRPosture(t, external)
	}
	if only == "" || only == "k8s_posture_routes.trust_bundles" {
		external := proof.StartCommand(t, "k8s_posture_routes.trust_bundles")
		dodRunKubernetesTrustBundlePosture(t, external)
	}
}

func dodRunKubernetesCSRPosture(t *testing.T, external *proof.ExternalSubstrate) {
	t.Helper()
	dir := t.TempDir()
	srv := dodBuildKubernetesPostureServer(t, dir)
	runtime := dodServeKubernetesPostureRuntime(t, srv)
	report, reportReceipt, caPEM := dodReconcileAndReportKubernetesPosture(t, srv, runtime.agentAddress, external)

	token := dodSeedAPIToken(t, context.Background(), srv.store, dodKubernetesTenant, "dod-kind-route-reader", []string{string(authz.CertsRead)})
	request, err := http.NewRequest(http.MethodGet, "/api/v1/kubernetes/certificate-signing-requests", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	session := proof.Start(t, "k8s_posture_routes.certificate_signing_requests", srv.Handler(), request)
	route := dodDecodeKubernetesPostureRoute(t, session.StatusCode(), session.ResponseBody(), "CAP-K8S-04", report.ReportID, report.ClusterID)
	liveBody := runtime.get(t, "/api/v1/kubernetes/certificate-signing-requests", token)
	liveRoute := dodDecodeKubernetesPostureRoute(t, http.StatusOK, liveBody, "CAP-K8S-04", report.ReportID, report.ClusterID)
	dodAssertKubernetesRouteBindingsEqual(t, route, liveRoute)

	verifier, readback := dodVerifyKubernetesPosture(t, external, "k8s_posture_routes.certificate_signing_requests", route, report, caPEM)
	contract := dodKubernetesPostureContract(t)
	receiptJSON, err := json.Marshal(reportReceipt)
	if err != nil {
		t.Fatalf("marshal authenticated posture receipt: %v", err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity:      []byte(report.ReportID + "|" + report.ClusterID + "|dod-kind-controller"),
		Transcript:          bytes.Join([][]byte{session.ResponseBody(), liveBody, receiptJSON, contract}, []byte("\n")),
		IndependentVerifier: bytes.Join([][]byte{verifier, readback}, []byte("\n")),
		ExecutionReceipt:    executionReceipt,
	}))
}

func dodRunKubernetesTrustBundlePosture(t *testing.T, external *proof.ExternalSubstrate) {
	t.Helper()
	dir := t.TempDir()
	srv := dodBuildKubernetesPostureServer(t, dir)
	runtime := dodServeKubernetesPostureRuntime(t, srv)
	report, reportReceipt, caPEM := dodReconcileAndReportKubernetesPosture(t, srv, runtime.agentAddress, external)

	token := dodSeedAPIToken(t, context.Background(), srv.store, dodKubernetesTenant, "dod-kind-route-reader", []string{string(authz.CertsRead)})
	request, err := http.NewRequest(http.MethodGet, "/api/v1/kubernetes/trust-bundles", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	session := proof.Start(t, "k8s_posture_routes.trust_bundles", srv.Handler(), request)
	route := dodDecodeKubernetesPostureRoute(t, session.StatusCode(), session.ResponseBody(), "CAP-K8S-07", report.ReportID, report.ClusterID)
	liveBody := runtime.get(t, "/api/v1/kubernetes/trust-bundles", token)
	liveRoute := dodDecodeKubernetesPostureRoute(t, http.StatusOK, liveBody, "CAP-K8S-07", report.ReportID, report.ClusterID)
	dodAssertKubernetesRouteBindingsEqual(t, route, liveRoute)

	verifier, readback := dodVerifyKubernetesPosture(t, external, "k8s_posture_routes.trust_bundles", route, report, caPEM)
	contract := dodKubernetesPostureContract(t)
	receiptJSON, err := json.Marshal(reportReceipt)
	if err != nil {
		t.Fatalf("marshal authenticated posture receipt: %v", err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity:      []byte(report.ReportID + "|" + report.ClusterID + "|dod-kind-controller"),
		Transcript:          bytes.Join([][]byte{session.ResponseBody(), liveBody, receiptJSON, contract}, []byte("\n")),
		IndependentVerifier: bytes.Join([][]byte{verifier, readback}, []byte("\n")),
		ExecutionReceipt:    executionReceipt,
	}))
}

// dodBuildKubernetesPostureServer returns the *Server directly so the DoD
// tracer can follow Build(buildRunDeps(...)) into each literal proof.Start.
func dodBuildKubernetesPostureServer(t *testing.T, dir string) *Server {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(dir, "control-plane-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(dir, "signer-keys")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	cfg.AgentChannel.Enabled = true
	cfg.AgentChannel.CACertFile = filepath.Join(dir, "agent-ca.crt")
	cfg.AgentChannel.ServerName = dodKubernetesAgentServerName
	cfg.AgentChannel.HeartbeatInterval = "30s"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Kubernetes posture production config: %v", err)
	}

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open Kubernetes posture event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		t.Fatalf("load Kubernetes posture run secrets: %v", err)
	}
	t.Cleanup(runSecrets.Close)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		t.Fatalf("build Kubernetes posture egress guard: %v", err)
	}
	signer := dodStartKubernetesPostureSigner(t, dir)
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		t.Fatalf("production buildRunDeps for Kubernetes posture: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		t.Fatalf("Build Kubernetes posture production deps: %v", err)
	}
	if !srv.OutOfProcessSigning() || !srv.OutOfProcessAgentCA() || !srv.AgentChannelServed() {
		_ = srv.Shutdown(context.Background())
		t.Fatal("Kubernetes posture runtime did not assemble signer-custodied issuance and the served agent mTLS channel")
	}
	return srv
}

func dodStartKubernetesPostureSigner(t *testing.T, dir string) runSigner {
	t.Helper()
	authFile := filepath.Join(dir, "signer-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("load Kubernetes posture signer authorizer: %v", err)
	}
	t.Cleanup(authorizer.Destroy)
	return dodStartShippedSignerProcess(t, dir, "kubernetes-posture", authFile, "", authorizer)
}

type dodKubernetesPostureRuntime struct {
	srv          *Server
	baseURL      string
	agentAddress string
	client       *http.Client
	httpServer   *http.Server
	httpDone     chan error
	channelStop  context.CancelFunc
	channelDone  chan struct{}
	closeOnce    sync.Once
}

func dodServeKubernetesPostureRuntime(t *testing.T, srv *Server) *dodKubernetesPostureRuntime {
	t.Helper()
	httpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.Shutdown(context.Background())
		t.Fatalf("listen for Kubernetes posture HTTP route: %v", err)
	}
	agentListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = httpListener.Close()
		_ = srv.Shutdown(context.Background())
		t.Fatalf("listen for Kubernetes posture agent channel: %v", err)
	}
	httpServer := &http.Server{
		Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
	}
	httpDone := make(chan error, 1)
	go func() { httpDone <- httpServer.Serve(httpListener) }()
	channelCtx, channelStop := context.WithCancel(context.Background())
	channelDone := make(chan struct{})
	go func() {
		defer close(channelDone)
		srv.serveAgentChannel(channelCtx, agentListener)
	}()
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.Proxy = nil
	runtime := &dodKubernetesPostureRuntime{
		srv: srv, baseURL: "http://" + httpListener.Addr().String(), agentAddress: agentListener.Addr().String(),
		client:     &http.Client{Transport: clientTransport, Timeout: 30 * time.Second},
		httpServer: httpServer, httpDone: httpDone, channelStop: channelStop, channelDone: channelDone,
	}
	t.Cleanup(func() { runtime.close(t) })
	return runtime
}

func (r *dodKubernetesPostureRuntime) get(t *testing.T, path, token string) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := r.client.Do(request)
	if err != nil {
		t.Fatalf("served Kubernetes posture TCP readback: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("served Kubernetes posture TCP readback status=%d err=%v body=%s", response.StatusCode, err, body)
	}
	return body
}

func (r *dodKubernetesPostureRuntime) close(t *testing.T) {
	t.Helper()
	r.closeOnce.Do(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r.channelStop()
		select {
		case <-r.channelDone:
		case <-time.After(10 * time.Second):
			t.Error("Kubernetes posture agent channel did not stop")
		}
		_ = r.httpServer.Shutdown(closeCtx)
		select {
		case err := <-r.httpDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("Kubernetes posture HTTP server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Kubernetes posture HTTP server did not stop")
		}
		if transport, ok := r.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		if err := r.srv.Shutdown(closeCtx); err != nil {
			t.Errorf("shutdown Kubernetes posture server: %v", err)
		}
	})
}

type dodKindConfig struct {
	SchemaVersion int    `json:"schema_version"`
	APIPort       int    `json:"api_port"`
	CAPEM         string `json:"ca_pem"`
	Token         string `json:"token"`
	Namespace     string `json:"namespace"`
	ClusterName   string `json:"cluster_name"`
	NodeImage     string `json:"node_image"`
}

type dodKindClient struct {
	client    *agentk8s.Client
	caPEM     []byte
	namespace string
}

type dodKindConfigHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type dodKindConfigPollClock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

func dodKindClientFromSubstrate(t *testing.T, external *proof.ExternalSubstrate) dodKindClient {
	t.Helper()
	endpoint, err := url.Parse(external.Endpoint())
	if err != nil || endpoint == nil || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "host.docker.internal") {
		t.Fatalf("kind substrate endpoint is not a gate-owned loopback bridge: %q", external.Endpoint())
	}
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.Proxy = nil
	defer clientTransport.CloseIdleConnections()
	fixture, err := dodPollKindConfig(
		external.Endpoint()+"/dod/config",
		&http.Client{Transport: clientTransport},
		time.Now().Add(dodKindConfigReadyTimeout),
		dodKindConfigPollClock{now: time.Now, sleep: time.Sleep},
	)
	if err != nil {
		t.Fatal(err)
	}

	if fixture.SchemaVersion != 1 || fixture.APIPort < 1 || fixture.APIPort > 65535 || fixture.Namespace == "" || fixture.ClusterName == "" || fixture.NodeImage != dodKubernetesNodeImage {
		t.Fatalf("real-kind fixture config is incomplete or unpinned: %+v", fixture)
	}
	caPEM, err := base64.StdEncoding.Strict().DecodeString(fixture.CAPEM)
	if err != nil || len(caPEM) < 64 {
		t.Fatalf("decode real-kind CA: %v", err)
	}
	token, err := base64.StdEncoding.Strict().DecodeString(fixture.Token)
	if err != nil || len(token) < 16 {
		t.Fatalf("decode real-kind service-account token: %v", err)
	}
	defer secret.Wipe(token)
	// The kind kubeconfig is pinned to 127.0.0.1 and its apiserver certificate
	// therefore carries that IP SAN. The broker may route the TCP connection via
	// host.docker.internal, but certificate verification remains bound to the
	// kubeconfig's authenticated 127.0.0.1 identity.
	kubernetesTransport, err := mtls.AgentHTTPTransport(nil, caPEM, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("build real-kind trusted transport: %v", err)
	}
	kubernetesTransport.Proxy = nil
	apiURL := "https://" + net.JoinHostPort(endpoint.Hostname(), strconv.Itoa(fixture.APIPort))
	client := agentk8s.New(apiURL, secrettext.String(token), fixture.Namespace, &http.Client{Transport: kubernetesTransport, Timeout: 30 * time.Second})
	return dodKindClient{client: client, caPEM: caPEM, namespace: fixture.Namespace}
}

func dodPollKindConfig(endpoint string, client dodKindConfigHTTPClient, deadline time.Time, clock dodKindConfigPollClock) (dodKindConfig, error) {
	if clock.now == nil {
		clock.now = time.Now
	}
	if clock.sleep == nil {
		clock.sleep = time.Sleep
	}
	var lastReadinessFailure error
	for {
		attemptStarted := clock.now()
		if !attemptStarted.Before(deadline) {
			if lastReadinessFailure == nil {
				return dodKindConfig{}, errors.New("real-kind fixture readiness deadline elapsed before the first request")
			}
			return dodKindConfig{}, fmt.Errorf("real-kind fixture did not become ready before its deadline: %w", lastReadinessFailure)
		}
		attemptDeadline := attemptStarted.Add(dodKindConfigAttemptTimeout)
		if deadline.Before(attemptDeadline) {
			attemptDeadline = deadline
		}
		requestContext, cancel := context.WithDeadline(context.Background(), attemptDeadline)
		request, requestErr := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
		if requestErr != nil {
			cancel()
			return dodKindConfig{}, fmt.Errorf("create real-kind fixture request: %w", requestErr)
		}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			cancel()
			if dodRetryableKindConfigTransport(requestErr) {
				lastReadinessFailure = fmt.Errorf("poll real-kind fixture: %w", requestErr)
				dodWaitKindConfigRetry(deadline, clock)
				continue
			}
			return dodKindConfig{}, fmt.Errorf("poll real-kind fixture: %w", requestErr)
		}
		if response == nil || response.Body == nil {
			cancel()
			return dodKindConfig{}, errors.New("poll real-kind fixture returned no response body")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		cancel()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
			return dodKindConfig{}, fmt.Errorf("real-kind fixture status=%d body=%s read_err=%v close_err=%v", response.StatusCode, body, readErr, closeErr)
		}
		if readErr != nil {
			if !dodRetryableKindConfigTransport(readErr) {
				return dodKindConfig{}, fmt.Errorf("read real-kind fixture: %w", readErr)
			}
			lastReadinessFailure = fmt.Errorf("read real-kind fixture: %w", readErr)
			dodWaitKindConfigRetry(deadline, clock)
			continue
		}
		if closeErr != nil {
			return dodKindConfig{}, fmt.Errorf("close real-kind fixture response: %w", closeErr)
		}
		switch response.StatusCode {
		case http.StatusOK:
			var fixture dodKindConfig
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&fixture); err != nil {
				return dodKindConfig{}, fmt.Errorf("decode real-kind fixture config: %w; body=%s", err, body)
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				return dodKindConfig{}, fmt.Errorf("decode real-kind fixture config: trailing JSON; body=%s", body)
			}
			return fixture, nil
		case http.StatusAccepted:
			lastReadinessFailure = fmt.Errorf("real-kind fixture is not ready: %s", body)
			dodWaitKindConfigRetry(deadline, clock)
		}
	}
}

func dodRetryableKindConfigTransport(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && (dnsError.IsTimeout || dnsError.IsTemporary) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func dodWaitKindConfigRetry(deadline time.Time, clock dodKindConfigPollClock) {
	remaining := deadline.Sub(clock.now())
	if remaining <= 0 {
		return
	}
	delay := dodKindConfigRetryDelay
	if remaining < delay {
		delay = remaining
	}
	clock.sleep(delay)
}

func dodReconcileAndReportKubernetesPosture(t *testing.T, srv *Server, agentAddress string, external *proof.ExternalSubstrate) (agentk8s.ControllerPostureReport, *transport.KubernetesPostureResponse, []byte) {
	t.Helper()
	kind := dodKindClientFromSubstrate(t, external)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controller := agentk8s.NewIssuerController(kind.client, agentk8s.SignerFunc(func(ctx context.Context, csrDER []byte) ([]byte, error) {
		return srv.IssueLeaf(ctx, csrDER, time.Hour)
	}), agentk8s.DefaultIssuerGroup)
	result, err := controller.Reconcile(ctx, kind.namespace)
	if err != nil {
		t.Fatalf("reconcile real kind cluster: %v", err)
	}
	if result.ClusterIssuersReady != 1 || result.KubernetesCSRsSigned != 1 || result.TrustBundlesDistributed != 1 ||
		!result.KubernetesCSRComplete || !result.TrustBundleComplete || len(result.KubernetesCSRPosture) != 1 || len(result.TrustBundlePosture) != 1 ||
		result.KubernetesCSRPosture[0].State != "ready" || result.TrustBundlePosture[0].State != "ready" ||
		result.KubernetesCSRPosture[0].ResourceVersion == "" || result.TrustBundlePosture[0].ResourceVersion == "" {
		t.Fatalf("real-kind reconcile result is incomplete: %+v", result)
	}
	report := result.PostureReport(kind.client.ClusterID(), 30*time.Second)

	bootstrapToken, err := srv.agentEnroll.IssueBootstrapToken(ctx, dodKubernetesTenant, "")
	if err != nil {
		t.Fatalf("issue Kubernetes controller bootstrap token: %v", err)
	}
	controllerAgent := agent.New(agent.Config{
		CommonName: "dod-kind-controller", BootstrapToken: bootstrapToken,
		ServerName: dodKubernetesAgentServerName, ServerCAPEM: srv.AgentCACertPEM(), Version: "dod-kind-controller/1",
	}, &dodKubernetesBootstrapEnroller{authority: srv.agentEnroll})
	if err := controllerAgent.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap Kubernetes controller agent: %v", err)
	}
	credentials, err := controllerAgent.Credentials()
	if err != nil {
		t.Fatalf("load Kubernetes controller mTLS credentials: %v", err)
	}
	connection, err := transport.Dial(agentAddress, credentials)
	if err != nil {
		t.Fatalf("dial served Kubernetes posture mTLS channel: %v", err)
	}
	defer func() { _ = connection.Close() }()
	receipt, err := transport.NewAgentClient(connection, transport.WithAgentVersion("dod-kind-controller/1")).ReportKubernetesPosture(ctx, dodKubernetesTransportReport(report))
	if err != nil {
		t.Fatalf("report real-kind posture over authenticated mTLS: %v", err)
	}
	if receipt.TenantID != dodKubernetesTenant || receipt.ReportID != report.ReportID || receipt.RecordedAtUnix <= 0 {
		t.Fatalf("authenticated Kubernetes posture receipt is not tenant/report bound: %+v", receipt)
	}
	return report, receipt, srv.CACertPEM()
}

type dodKubernetesBootstrapEnroller struct {
	authority interface {
		EnrollBootstrap(context.Context, []byte, []byte) ([]byte, error)
	}
}

func (e *dodKubernetesBootstrapEnroller) EnrollBootstrap(ctx context.Context, token, csrDER []byte) ([]byte, error) {
	return e.authority.EnrollBootstrap(ctx, token, csrDER)
}

func (*dodKubernetesBootstrapEnroller) EnrollRenewal(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("Kubernetes posture proof does not use direct renewal")
}

func dodKubernetesTransportReport(report agentk8s.ControllerPostureReport) *transport.KubernetesPostureRequest {
	convert := func(section agentk8s.PostureSection) transport.KubernetesPostureSection {
		resources := make([]transport.KubernetesPostureResource, 0, len(section.Resources))
		for _, resource := range section.Resources {
			resources = append(resources, transport.KubernetesPostureResource{
				Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID,
				ResourceVersion: resource.ResourceVersion, State: resource.State,
				Reason: resource.Reason, PublicHash: resource.PublicHash,
			})
		}
		return transport.KubernetesPostureSection{Complete: section.Complete, FailureCode: section.FailureCode, Resources: resources}
	}
	return &transport.KubernetesPostureRequest{
		ReportID: report.ReportID, ClusterID: report.ClusterID, ReconcileIntervalSeconds: report.ReconcileIntervalSeconds,
		CertificateSigning: convert(report.CertificateSigning), TrustBundles: convert(report.TrustBundles),
	}
}

func dodDecodeKubernetesPostureRoute(t *testing.T, status int, body []byte, capability, reportID, clusterID string) map[string]any {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("served Kubernetes posture status=%d body=%s", status, body)
	}
	var route map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&route); err != nil {
		t.Fatalf("decode served Kubernetes posture: %v; body=%s", err, body)
	}
	if route["capability"] != capability || route["served"] != true || route["last_sync"] == "" {
		t.Fatalf("served Kubernetes posture is not live controller state: %+v", route)
	}
	controllers, ok := route["controllers"].([]any)
	if !ok || len(controllers) != 1 {
		t.Fatalf("served Kubernetes posture controllers=%T/%v", route["controllers"], route["controllers"])
	}
	controller, ok := controllers[0].(map[string]any)
	if !ok || controller["report_id"] != reportID || controller["cluster_id"] != clusterID || controller["reconcile_complete"] != true {
		t.Fatalf("served Kubernetes posture is not bound to reconcile report %s/%s: %+v", reportID, clusterID, controller)
	}
	objects, ok := route["objects"].([]any)
	if !ok || len(objects) != 1 {
		t.Fatalf("served Kubernetes posture objects=%T/%v", route["objects"], route["objects"])
	}
	return route
}

func dodAssertKubernetesRouteBindingsEqual(t *testing.T, assembled, tcp map[string]any) {
	t.Helper()
	for _, key := range []string{"capability", "served", "last_sync", "summary", "controllers", "objects"} {
		if !reflect.DeepEqual(assembled[key], tcp[key]) {
			t.Fatalf("assembled-handler and real-TCP Kubernetes route differ at %s: assembled=%v tcp=%v", key, assembled[key], tcp[key])
		}
	}
}

func dodVerifyKubernetesPosture(t *testing.T, external *proof.ExternalSubstrate, entryID string, route map[string]any, report agentk8s.ControllerPostureReport, caPEM []byte) ([]byte, []byte) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"entry_id": entryID, "tenant_id": dodKubernetesTenant,
		"report_id": report.ReportID, "cluster_id": report.ClusterID,
		"ca_pem": string(caPEM), "route": route,
	})
	if err != nil {
		t.Fatalf("encode Kubernetes posture verifier payload: %v", err)
	}
	verifier := dodKubernetesSubstrateRequest(t, http.MethodPost, external.Endpoint()+"/dod/verify", payload)
	readback := dodKubernetesSubstrateRequest(t, http.MethodGet, external.Endpoint()+"/dod/readback", nil)
	if !bytes.Equal(verifier, readback) {
		t.Fatalf("Kubernetes posture verifier and independent readback differ: verify=%s readback=%s", verifier, readback)
	}
	return verifier, readback
}

func dodKubernetesSubstrateRequest(t *testing.T, method, endpoint string, body []byte) []byte {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.Proxy = nil
	client := &http.Client{Transport: clientTransport, Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Kubernetes substrate %s %s: %v", method, endpoint, err)
	}
	defer func() {
		_ = response.Body.Close()
		clientTransport.CloseIdleConnections()
	}()
	result, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(result) < 16 {
		t.Fatalf("Kubernetes substrate %s status=%d bytes=%d err=%v body=%s", method, response.StatusCode, len(result), err, result)
	}
	return result
}

func dodKubernetesPostureContract(t *testing.T) []byte {
	t.Helper()
	contract, err := os.ReadFile("../../tools/dodcensus/contracts/kubernetes-kind-posture-v1.json")
	if err != nil {
		t.Fatalf("read Kubernetes posture substrate contract: %v", err)
	}
	return contract
}

func TestDODKindConfigPollRecoversWithinReadinessWall(t *testing.T) {
	t.Parallel()

	now := time.Now()
	client := &dodKindConfigPollClient{steps: []dodKindConfigPollStep{
		{err: syscall.ETIMEDOUT},
		{status: http.StatusAccepted, body: `{"status":"starting"}`},
		{status: http.StatusOK, body: dodValidKindConfigJSON()},
	}}
	config, err := dodPollKindConfig(
		"http://host.docker.internal:61443/dod/config",
		client,
		now.Add(6*time.Minute),
		dodKindConfigPollClock{
			now: func() time.Time { return now },
			sleep: func(delay time.Duration) {
				now = now.Add(delay)
			},
		},
	)
	if err != nil {
		t.Fatalf("poll after recoverable transport failure: %v", err)
	}
	if config.SchemaVersion != 1 || config.ClusterName != "dod-kind" {
		t.Fatalf("decoded config = %+v", config)
	}
	if client.calls != 3 {
		t.Fatalf("requests = %d, want 3", client.calls)
	}
	if client.closedBodies != 2 {
		t.Fatalf("closed response bodies = %d, want 2", client.closedBodies)
	}
	for _, deadline := range client.requestDeadlines {
		if deadline.After(now.Add(30 * time.Second)) {
			t.Fatalf("request deadline %s exceeds per-attempt bound from %s", deadline, now)
		}
	}
}

func TestDODKindConfigPollRecoversFromReadFailure(t *testing.T) {
	t.Parallel()

	now := time.Now()
	client := &dodKindConfigPollClient{steps: []dodKindConfigPollStep{
		{status: http.StatusOK, readErr: io.ErrUnexpectedEOF},
		{status: http.StatusOK, body: dodValidKindConfigJSON()},
	}}
	if _, err := dodPollKindConfig(
		"http://host.docker.internal:61443/dod/config",
		client,
		now.Add(time.Minute),
		dodKindConfigPollClock{
			now: func() time.Time { return now },
			sleep: func(delay time.Duration) {
				now = now.Add(delay)
			},
		},
	); err != nil {
		t.Fatalf("poll after recoverable read failure: %v", err)
	}
	if client.calls != 2 || client.closedBodies != 2 {
		t.Fatalf("requests/closed bodies = %d/%d, want 2/2", client.calls, client.closedBodies)
	}
}

func TestDODKindConfigPollReportsLastTransportFailureAtDeadline(t *testing.T) {
	t.Parallel()

	now := time.Now()
	readinessDeadline := now.Add(750 * time.Millisecond)
	client := &dodKindConfigPollClient{steps: []dodKindConfigPollStep{
		{err: fmt.Errorf("bridge timeout one: %w", syscall.ETIMEDOUT)},
		{err: fmt.Errorf("bridge timeout two: %w", syscall.ETIMEDOUT)},
	}}
	_, err := dodPollKindConfig(
		"http://host.docker.internal:61443/dod/config",
		client,
		readinessDeadline,
		dodKindConfigPollClock{
			now: func() time.Time { return now },
			sleep: func(delay time.Duration) {
				now = now.Add(delay)
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "bridge timeout two") {
		t.Fatalf("deadline error = %v, want last transport failure", err)
	}
	if client.calls != 2 {
		t.Fatalf("requests = %d, want 2", client.calls)
	}
	for _, requestDeadline := range client.requestDeadlines {
		if !requestDeadline.Equal(readinessDeadline) {
			t.Fatalf("request deadline = %s, want remaining-wall cap %s", requestDeadline, readinessDeadline)
		}
	}
}

func TestDODKindConfigPollFailsFastOnSemanticResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		step dodKindConfigPollStep
		want string
	}{
		{
			name: "substrate setup failure",
			step: dodKindConfigPollStep{status: http.StatusServiceUnavailable, body: "kind setup failed"},
			want: "status=503",
		},
		{
			name: "unexpected status",
			step: dodKindConfigPollStep{status: http.StatusTeapot, body: "unexpected"},
			want: "status=418",
		},
		{
			name: "malformed complete response",
			step: dodKindConfigPollStep{status: http.StatusOK, body: `{"schema_version":1,"unknown":true}`},
			want: "decode real-kind fixture config",
		},
		{
			name: "substrate setup failure with truncated body",
			step: dodKindConfigPollStep{status: http.StatusServiceUnavailable, readErr: io.ErrUnexpectedEOF},
			want: "status=503",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			client := &dodKindConfigPollClient{steps: []dodKindConfigPollStep{test.step}}
			_, err := dodPollKindConfig(
				"http://host.docker.internal:61443/dod/config",
				client,
				now.Add(6*time.Minute),
				dodKindConfigPollClock{
					now:   func() time.Time { return now },
					sleep: func(time.Duration) { t.Fatal("semantic response was retried") },
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if client.calls != 1 || client.closedBodies != 1 {
				t.Fatalf("requests/closed bodies = %d/%d, want 1/1", client.calls, client.closedBodies)
			}
		})
	}
}

func TestDODKindConfigPollFailsFastOnPermanentRequestError(t *testing.T) {
	t.Parallel()

	now := time.Now()
	client := &dodKindConfigPollClient{steps: []dodKindConfigPollStep{
		{err: errors.New("unsupported protocol scheme")},
	}}
	_, err := dodPollKindConfig(
		"http://host.docker.internal:61443/dod/config",
		client,
		now.Add(6*time.Minute),
		dodKindConfigPollClock{
			now:   func() time.Time { return now },
			sleep: func(time.Duration) { t.Fatal("permanent request error was retried") },
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol scheme") {
		t.Fatalf("error = %v, want permanent request failure", err)
	}
	if client.calls != 1 {
		t.Fatalf("requests = %d, want 1", client.calls)
	}
}

type dodKindConfigPollStep struct {
	status  int
	body    string
	err     error
	readErr error
}

type dodKindConfigPollClient struct {
	steps            []dodKindConfigPollStep
	calls            int
	closedBodies     int
	requestDeadlines []time.Time
}

func (c *dodKindConfigPollClient) Do(request *http.Request) (*http.Response, error) {
	if deadline, ok := request.Context().Deadline(); ok {
		c.requestDeadlines = append(c.requestDeadlines, deadline)
	}
	index := c.calls
	c.calls++
	if index >= len(c.steps) {
		index = len(c.steps) - 1
	}
	step := c.steps[index]
	if step.err != nil {
		return nil, step.err
	}
	reader := io.Reader(strings.NewReader(step.body))
	if step.readErr != nil {
		reader = dodKindConfigErrorReader{err: step.readErr}
	}
	return &http.Response{
		StatusCode: step.status,
		Body: &dodKindConfigTrackedBody{
			Reader:     reader,
			contextErr: request.Context().Err,
			closed:     func() { c.closedBodies++ },
		},
	}, nil
}

type dodKindConfigTrackedBody struct {
	io.Reader
	contextErr func() error
	closed     func()
}

func (b *dodKindConfigTrackedBody) Read(buffer []byte) (int, error) {
	if err := b.contextErr(); err != nil {
		return 0, err
	}
	return b.Reader.Read(buffer)
}

func (b *dodKindConfigTrackedBody) Close() error {
	b.closed()
	return nil
}

type dodKindConfigErrorReader struct {
	err error
}

func (r dodKindConfigErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func dodValidKindConfigJSON() string {
	return `{"schema_version":1,"api_port":6443,"ca_pem":"Y2E=","token":"dG9rZW4=","namespace":"trstctl-dod","cluster_name":"dod-kind","node_image":"` + dodKubernetesNodeImage + `"}`
}
