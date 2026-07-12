// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/transport"
	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestBootstrapTokenFileLoadsTrimmedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(path, []byte("  trst_bootstrap_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := bootstrapToken(agentOptions{tokenFile: path})
	if err != nil {
		t.Fatalf("bootstrapToken(token file): %v", err)
	}
	if !bytes.Equal(got, []byte("trst_bootstrap_secret")) {
		t.Fatalf("token = %q, want trimmed token", got)
	}
}

func TestKubernetesControllerPostureWireConversionIsMetadataOnly(t *testing.T) {
	report := k8s.ControllerPostureReport{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: k8s.PostureSection{Complete: true, Resources: []k8s.PostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
		}}},
		TrustBundles: k8s.PostureSection{Complete: false, FailureCode: "reconcile_failed", Resources: []k8s.PostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "failed", Reason: "controller_error",
		}}},
	}
	wire := transportKubernetesPostureReport(report)
	if wire.ReportID != report.ReportID || wire.CertificateSigning.Resources[0].ResourceVersion != "17" || wire.TrustBundles.FailureCode != "reconcile_failed" {
		t.Fatalf("wire report = %+v", wire)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(string(raw))
	for _, forbidden := range []string{"private_key", "ca_bundle_pem", "csr_der", "certificate_pem", "bearer", "token"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metadata-only Kubernetes report contains %q: %s", forbidden, raw)
		}
	}
}

func TestBootstrapTokenRejectsInlineArg(t *testing.T) {
	_, err := bootstrapToken(agentOptions{inlineToken: "inline-secret"})
	if err == nil {
		t.Fatal("bootstrapToken accepted an inline bootstrap token without the explicit development override")
	}
	if !strings.Contains(err.Error(), "--bootstrap-token-file") {
		t.Fatalf("error = %v, want token-file guidance", err)
	}
}

func TestBootstrapTokenRejectsAmbiguousSources(t *testing.T) {
	_, err := bootstrapToken(agentOptions{
		inlineToken:                       "inline",
		tokenFile:                         "token-file",
		allowInsecureDevBootstrapTokenArg: true,
	})
	if err == nil {
		t.Fatal("bootstrapToken accepted both inline and file bootstrap token sources")
	}
}

func TestServiceArgumentsNeverPersistInlineBootstrapToken(t *testing.T) {
	args := serviceArguments(agentOptions{
		enrollURL:   "https://cp.example/enroll",
		caBundle:    "/etc/trstctl/ca.pem",
		serverAddr:  "cp.example:9443",
		commonName:  "win-agent-1",
		keyPath:     "C:\\ProgramData\\trstctl\\agent.key",
		certPath:    "C:\\ProgramData\\trstctl\\agent.crt",
		rotateEvery: time.Hour,
		inlineToken: "inline-secret",
		tokenFile:   "C:\\ProgramData\\trstctl\\bootstrap-token.txt",
	})
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, "inline-secret") || strings.Contains(joined, "--bootstrap-token\x00") {
		t.Fatalf("service arguments persisted inline bootstrap token: %q", args)
	}
	if !strings.Contains(joined, "--bootstrap-token-file\x00C:\\ProgramData\\trstctl\\bootstrap-token.txt") {
		t.Fatalf("service arguments did not preserve the bootstrap token file path: %q", args)
	}
}

func TestBootstrapTokenFileNotRequiredAfterIdentityPersisted(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	certPath := filepath.Join(dir, "agent.crt")
	if err := os.WriteFile(keyPath, []byte("persisted key placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("persisted cert placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := bootstrapTokenForRun(agentOptions{
		tokenFile: filepath.Join(dir, "deleted-after-first-boot-token"),
		keyPath:   keyPath,
		certPath:  certPath,
	})
	if err != nil {
		t.Fatalf("persisted identity should not require bootstrap token file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("token = %q, want empty because persisted identity reload does not re-enroll", got)
	}
}

func TestAgentK8sIdentityFlagsAreExposed(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	out, _ := cmd.CombinedOutput()
	help := string(out)
	for _, want := range []string{
		"-key string",
		"-cert string",
		"-prepare-identity-dir string",
		"-prepare-identity-uid int",
		"-prepare-identity-gid int",
		"-k8s",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("trstctl-agent --help missing %q; output:\n%s", want, help)
		}
	}
}

func TestAgentBootstrapPinsCABundle(t *testing.T) {
	serverCert, err := mtls.SelfSignedServerCert([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := enrollmentHTTPClient(serverCert.TrustPEM)
	if err != nil {
		t.Fatalf("enrollmentHTTPClient(valid CA): %v", err)
	}
	if client.Transport == nil {
		t.Fatal("enrollmentHTTPClient returned client without explicit transport")
	}
	if _, err := enrollmentHTTPClient([]byte("not a certificate")); err == nil {
		t.Fatal("enrollmentHTTPClient accepted an invalid CA bundle")
	}
}

type inventoryChannel struct {
	requests []*agent.InventoryRequest
	err      error
}

func (*inventoryChannel) Heartbeat(context.Context, *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	return nil, errors.New("unexpected heartbeat")
}

func (*inventoryChannel) Renew(context.Context, *agent.RenewRequest) (*agent.RenewResponse, error) {
	return nil, errors.New("unexpected renewal")
}

func (c *inventoryChannel) ReportInventory(_ context.Context, req *agent.InventoryRequest) (*agent.InventoryResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	clone := &agent.InventoryRequest{SourceKind: req.SourceKind, Findings: append([]agent.InventoryFinding(nil), req.Findings...)}
	c.requests = append(c.requests, clone)
	return &agent.InventoryResponse{TenantID: "tenant-a", RunID: "run-a", Recorded: len(req.Findings)}, nil
}

func TestAgentInventoryReportsMetadataOnlyAcrossSources(t *testing.T) {
	dir := t.TempDir()
	serverCert, err := mtls.SelfSignedServerCert([]string{"inventory.test"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedServerCert: %v", err)
	}
	certPath := filepath.Join(dir, "service.crt")
	if err := os.WriteFile(certPath, serverCert.TrustPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	privatePEM, _, err := cryptoboundary.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPEM: %v", err)
	}
	keyPath := filepath.Join(dir, "service.key")
	if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range privatePEM {
		privatePEM[i] = 0
	}

	a := agent.New(agent.Config{CommonName: "inventory-agent", Version: "test"}, nil)
	channel := &inventoryChannel{}
	ctx := context.Background()
	if err := reportFilesystemInventory(ctx, a, channel, []string{dir}); err != nil {
		t.Fatalf("reportFilesystemInventory: %v", err)
	}
	if err := reportTrustStoreInventory(ctx, a, channel, agentOptions{
		inventoryOSTrustRoots:      []string{certPath},
		inventoryNSSTrustRoots:     []string{certPath},
		inventoryBrowserTrustRoots: []string{certPath},
	}); err != nil {
		t.Fatalf("reportTrustStoreInventory: %v", err)
	}
	if err := reportPrivateKeyInventory(ctx, a, channel, []string{dir}); err != nil {
		t.Fatalf("reportPrivateKeyInventory: %v", err)
	}

	if len(channel.requests) != 3 {
		t.Fatalf("inventory reports = %d, want filesystem, trust-store, and private-key", len(channel.requests))
	}
	if got := channel.requests[0]; got.SourceKind != agentdiscovery.SourceFilesystem || len(got.Findings) != 1 {
		t.Fatalf("filesystem report = %+v", got)
	}
	if got := channel.requests[1]; got.SourceKind != agentdiscovery.SourceTrustStore || len(got.Findings) != 3 {
		t.Fatalf("trust-store report = %+v", got)
	}
	privateReport := channel.requests[2]
	if privateReport.SourceKind != agentdiscovery.SourcePrivateKey || len(privateReport.Findings) != 1 {
		t.Fatalf("private-key report = %+v", privateReport)
	}
	finding := privateReport.Findings[0]
	if finding.Kind != "private_key" || finding.Fingerprint == "" || finding.Metadata["key_bytes_present"] != "false" || finding.Metadata["material_class"] != "private-key" {
		t.Fatalf("private-key finding leaked or omitted classification metadata: %+v", finding)
	}
	if finding.RiskScore != 85 || finding.Metadata["file_mode_restricted"] != "true" {
		t.Fatalf("private-key risk/mode classification = %+v", finding)
	}
}

func TestAgentInventoryEmptyAndFailureBehavior(t *testing.T) {
	a := agent.New(agent.Config{CommonName: "inventory-agent"}, nil)
	channel := &inventoryChannel{}
	if err := reportFoundInventory(context.Background(), a, channel, agentdiscovery.SourceFilesystem, nil, 10, "inventory"); err != nil {
		t.Fatalf("empty reportFoundInventory: %v", err)
	}
	if len(channel.requests) != 0 {
		t.Fatalf("empty inventory emitted %d reports", len(channel.requests))
	}
	if got := privateKeyInventoryFindings(nil); len(got) != 0 {
		t.Fatalf("empty private-key findings = %+v", got)
	}

	wantErr := errors.New("control plane unavailable")
	channel.err = wantErr
	err := reportFoundInventory(context.Background(), a, channel, agentdiscovery.SourceFilesystem, []agentdiscovery.Found{{
		Source: agentdiscovery.SourceFilesystem, Location: "/tmp/cert",
	}}, 10, "inventory")
	if !errors.Is(err, wantErr) {
		t.Fatalf("report error = %v, want %v", err, wantErr)
	}

	err = reportTrustStoreInventory(context.Background(), a, &inventoryChannel{}, agentOptions{
		inventoryJavaTrustStores: []string{filepath.Join(t.TempDir(), "missing-cacerts")},
	})
	if err == nil {
		t.Fatal("trust-store discovery with only a missing root succeeded")
	}
	if hasTrustStoreInventory(agentOptions{}) {
		t.Fatal("empty trust-store options reported configured")
	}
	if !hasTrustStoreInventory(agentOptions{inventoryJavaTrustStores: []string{"cacerts"}}) {
		t.Fatal("Java trust-store option was not detected")
	}
	if got := splitList(" one, ,two ,, three "); len(got) != 3 || got[0] != "one" || got[2] != "three" {
		t.Fatalf("splitList = %#v", got)
	}
}

func TestPrepareIdentityDirRejectsUnsafePathsAndPinsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		if err := prepareIdentityDir(`C:\trstctl\identity`, 0, 0); err == nil {
			t.Fatal("prepareIdentityDir succeeded on Windows despite its Unix-only ownership contract")
		}
		return
	}
	if err := prepareIdentityDir("relative/path", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("prepareIdentityDir accepted a relative path")
	}
	if err := prepareIdentityDir(string(os.PathSeparator), os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("prepareIdentityDir accepted the filesystem root")
	}
	if err := prepareIdentityDir(filepath.Join(t.TempDir(), "identity"), -1, os.Getgid()); err == nil {
		t.Fatal("prepareIdentityDir accepted a negative uid")
	}

	path := filepath.Join(t.TempDir(), "nested", "identity")
	if err := prepareIdentityDir(path, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("prepareIdentityDir: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("identity dir mode = %04o, want 0700", got)
	}
}

func TestResetTimerHandlesExpiredAndNonPositiveDelay(t *testing.T) {
	timer := time.NewTimer(time.Nanosecond)
	t.Cleanup(func() { timer.Stop() })
	<-timer.C
	resetTimer(timer, 0)
	select {
	case <-timer.C:
	case <-time.After(time.Second):
		t.Fatal("resetTimer did not re-arm an expired timer")
	}
}

type runAgentChannelService struct {
	heartbeats chan *transport.HeartbeatRequest
}

type renewalChannel struct {
	ca    *mtls.CA
	calls int
	err   error
}

func (*renewalChannel) Heartbeat(context.Context, *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	return nil, errors.New("unexpected heartbeat")
}

func (c *renewalChannel) Renew(_ context.Context, req *agent.RenewRequest) (*agent.RenewResponse, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	chain, err := c.ca.SignClientCSR(req.CSRDER, time.Hour)
	return &agent.RenewResponse{CertChainPEM: chain, NotAfterUnix: time.Now().Add(time.Hour).Unix()}, err
}

func (*renewalChannel) ReportInventory(context.Context, *agent.InventoryRequest) (*agent.InventoryResponse, error) {
	return nil, errors.New("unexpected inventory")
}

func TestRenewWithBackoffSucceedsAndBoundsFailure(t *testing.T) {
	ca, err := mtls.NewCA("renewal-test")
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(agent.Config{CommonName: "renewing-agent"}, nil)
	success := &renewalChannel{ca: ca}
	renewWithBackoff(context.Background(), a, success, time.Second, rand.New(rand.NewSource(1)))
	if success.calls != 1 || a.CertificateSerial() == "" {
		t.Fatalf("successful renewal calls=%d serial=%q", success.calls, a.CertificateSerial())
	}

	failure := &renewalChannel{ca: ca, err: errors.New("control plane unavailable")}
	renewWithBackoff(context.Background(), a, failure, time.Nanosecond, rand.New(rand.NewSource(2)))
	if failure.calls != 1 {
		t.Fatalf("bounded failed renewal calls=%d, want one", failure.calls)
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := &renewalChannel{ca: ca, err: errors.New("control plane unavailable")}
	renewWithBackoff(cancelledCtx, a, cancelled, 2*time.Second, rand.New(rand.NewSource(3)))
	if cancelled.calls != 1 {
		t.Fatalf("cancelled renewal calls=%d, want one", cancelled.calls)
	}
}

func (s *runAgentChannelService) Heartbeat(_ context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	clone := *req
	// Notify after the local response has had time to cross the gRPC codec. The
	// test cancels the long-running agent when it receives this signal; sending it
	// inline would race cancellation against delivery of the successful response.
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.heartbeats <- &clone
	}()
	return &transport.HeartbeatResponse{TenantID: "tenant-a", NextHeartbeatSeconds: 30}, nil
}

func (*runAgentChannelService) Renew(context.Context, *transport.RenewRequest) (*transport.RenewResponse, error) {
	return nil, errors.New("unexpected renewal")
}

func (*runAgentChannelService) ReportInventory(context.Context, *transport.InventoryRequest) (*transport.InventoryResponse, error) {
	return nil, errors.New("unexpected inventory")
}

func TestRunAgentBootstrapsOverPinnedHTTPSAndConnectsMTLSChannel(t *testing.T) {
	agentCA, err := mtls.NewCA("agent-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	enrollmentCert, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	enrollmentServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/enroll/bootstrap" {
			http.Error(w, "unexpected enrollment route", http.StatusNotFound)
			return
		}
		var request struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad enrollment request", http.StatusBadRequest)
			return
		}
		csr, err := base64.StdEncoding.DecodeString(request.CSR)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		chain, err := agentCA.SignClientCSRWithTenant(csr, "tenant-a", time.Hour)
		if err != nil {
			http.Error(w, "sign csr", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(chain)})
	})}
	go func() { _ = enrollmentCert.ServeHTTPS(enrollmentServer, enrollmentListener) }()
	t.Cleanup(func() { _ = enrollmentServer.Close() })

	serverCreds, err := agentCA.ServerCredentials([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	channelService := &runAgentChannelService{heartbeats: make(chan *transport.HeartbeatRequest, 1)}
	grpcServer := transport.NewServer(serverCreds, channelService)
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(grpcListener) }()
	t.Cleanup(grpcServer.Stop)

	dir := t.TempDir()
	caBundle := append(bytes.Clone(enrollmentCert.TrustPEM), agentCA.BundlePEM()...)
	caPath := filepath.Join(dir, "control-plane-ca.pem")
	if err := os.WriteFile(caPath, caBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "bootstrap-token")
	if err := os.WriteFile(tokenPath, []byte("one-time-bootstrap-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := agentOptions{
		enrollURL:   "https://" + enrollmentListener.Addr().String(),
		tokenFile:   tokenPath,
		caBundle:    caPath,
		serverAddr:  grpcListener.Addr().String(),
		serverName:  "agent.trstctl.local",
		commonName:  "agent-one",
		keyPath:     filepath.Join(dir, "agent.key"),
		certPath:    filepath.Join(dir, "agent.crt"),
		rotateEvery: time.Hour,
	}
	runCtx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runAgent(runCtx, options) }()

	select {
	case heartbeat := <-channelService.heartbeats:
		if heartbeat.AgentID != "agent-one" || heartbeat.Status != "active" || heartbeat.CertSerial == "" {
			t.Fatalf("initial heartbeat = %+v", heartbeat)
		}
		cancel()
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("agent did not reach the mTLS steady-state channel")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runAgent: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop after context cancellation")
	}
	for _, path := range []string{options.keyPath, options.certPath} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("persisted identity %s: info=%v err=%v", path, info, err)
		}
	}
}
