// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestAgentRestartRecoversTerminalReportBeforeClaiming(t *testing.T) {
	testAgentRestartRecoversTerminalReport(t, false)
}

func TestAgentRestartRecoversReportWithClaimingDisabled(t *testing.T) {
	testAgentRestartRecoversTerminalReport(t, true)
}

func testAgentRestartRecoversTerminalReport(t *testing.T, disableClaiming bool) {
	t.Helper()
	ca, err := mtls.NewCA("report-restart-ca")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("report-restart-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Destroy)
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "restart-tenant", []string{mtls.AgentRoleHost}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	keyPath, certPath, caPath := filepath.Join(dir, "agent.key"), filepath.Join(dir, "agent.crt"), filepath.Join(dir, "ca.pem")
	if err := id.Save(keyPath, certPath); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("ca.pem", ca.BundlePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := json.Marshal(relay.HostProfile{AllowedRoots: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("profile.json", profile, 0o600); err != nil {
		t.Fatal(err)
	}
	// The CA bundle is public trust material; the real executor installs it.
	intent := relay.TrustDistributionIntent{RunID: "restart", WaveID: "one", IdentityID: "restart-anchor", Operation: relay.TrustInstall,
		AnchorPath: filepath.Join(dir, "anchor.pem"), AnchorPEM: ca.BundlePEM()}
	// The executor accepts a fingerprint computed independently from its PEM.
	certDER, err := mtls.FirstCertDER(intent.AnchorPEM)
	if err != nil {
		t.Fatal(err)
	}
	intent.AnchorFingerprint, err = mtls.CertFingerprintSHA256(certDER)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var phase atomic.Int32
	phase.Store(1)
	var claims atomic.Int32
	var acknowledged atomic.Bool
	seen, recovered := make(chan struct{}, 1), make(chan struct{}, 1)
	var mu sync.Mutex
	var original *transport.ReportJobResultRequest
	var installed os.FileInfo
	svc := &receiptRetryChannelServer{}
	svc.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
		if phase.Load() == 2 && !acknowledged.Load() {
			t.Error("restarted agent claimed work before recovering its original terminal report")
		}
		if claims.Add(1) == 1 {
			return &transport.ClaimJobsResponse{Jobs: []transport.ClaimedJob{{JobID: 51, Attempt: 1, Kind: relay.KindTrustDistribute, Payload: payload}}}, nil
		}
		return &transport.ClaimJobsResponse{}, nil
	}
	svc.report = func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		actual, err := root.ReadFile("anchor.pem")
		if err != nil || !bytes.Equal(actual, intent.AnchorPEM) {
			t.Errorf("real trust installation missing: %v", err)
		}
		info, err := root.Stat("anchor.pem")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		if original == nil {
			copy := *req
			original, installed = &copy, info
		} else if req.JobID != original.JobID || req.Attempt != original.Attempt || req.Outcome != original.Outcome || req.Detail != original.Detail || req.EvidenceDigest != original.EvidenceDigest || !os.SameFile(installed, info) || !installed.ModTime().Equal(info.ModTime()) {
			t.Error("restart changed the original observation or repeated the trust write")
		}
		mu.Unlock()
		if phase.Load() == 1 {
			select {
			case seen <- struct{}{}:
			default:
			}
			return nil, status.Error(codes.Unavailable, "owned report outage")
		}
		acknowledged.Store(true)
		select {
		case recovered <- struct{}{}:
		default:
		}
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	}
	creds, err := ca.ServerCredentials([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := transport.NewServer(creds, svc)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	options := agentOptions{caBundle: caPath, keyPath: keyPath, certPath: certPath, commonName: "report-restart-agent",
		serverName: "agent.trstctl.local", serverAddr: listener.Addr().String(), enrollURL: "https://127.0.0.1:1",
		relayClaim: true, relayPollEvery: 50 * time.Millisecond, rotateEvery: time.Hour, hostExecProfile: filepath.Join(dir, "profile.json")}
	run := func(wait <-chan struct{}) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- runAgent(ctx, options) }()
		select {
		case <-wait:
		case err := <-done:
			cancel()
			t.Fatalf("agent exited before report: %v", err)
		case <-time.After(4 * time.Second):
			cancel()
			<-done
			t.Fatal("agent did not report its original terminal result")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("agent did not stop")
		}
	}
	run(seen)
	phase.Store(2)
	if disableClaiming {
		options.relayClaim = false
	}
	run(recovered)
}
