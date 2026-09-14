// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

type blockedJobChannel struct {
	claimed chan struct{}
	beat    chan struct{}
	once    sync.Once
	active  atomic.Bool
	claims  atomic.Int64
	release chan struct{}
	renewed chan bool
}

func (s *blockedJobChannel) Heartbeat(context.Context, *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	if s.active.Load() {
		select {
		case s.beat <- struct{}{}:
		default:
		}
	}
	return &transport.HeartbeatResponse{TenantID: "tenant-a", NextHeartbeatSeconds: 1}, nil
}

func (s *blockedJobChannel) ClaimJobs(ctx context.Context, _ *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
	s.claims.Add(1)
	s.active.Store(true)
	s.once.Do(func() { close(s.claimed) })
	select {
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-s.release:
		s.active.Store(false)
		return &transport.ClaimJobsResponse{}, nil
	}
}

func (s *blockedJobChannel) Renew(context.Context, *transport.RenewRequest) (*transport.RenewResponse, error) {
	select {
	case s.renewed <- s.active.Load():
	default:
	}
	return nil, status.Error(codes.Unimplemented, "fixture ends at rotation request")
}
func (*blockedJobChannel) ReportInventory(context.Context, *transport.InventoryRequest) (*transport.InventoryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unexpected inventory")
}
func (*blockedJobChannel) ReportJobResult(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unexpected result")
}
func (*blockedJobChannel) RedeemJobCredential(context.Context, *transport.RedeemJobCredentialRequest) (*transport.RedeemJobCredentialResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unexpected redemption")
}
func (*blockedJobChannel) SignJobCSR(context.Context, *transport.SignJobCSRRequest) (*transport.SignJobCSRResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unexpected signing")
}
func (*blockedJobChannel) FetchWorkloadSVID(context.Context, *transport.FetchWorkloadSVIDRequest) (*transport.FetchWorkloadSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unexpected workload")
}

// Run the actual assembled agent loop against a real pinned mTLS channel. A
// slow job RPC must not suppress the independent heartbeat, and shutdown must
// cancel and join its worker before the channel closes.
func TestAgentHeartbeatsWhileJobChannelIsBlocked(t *testing.T) {
	ca, err := mtls.NewCA("pending-job-heartbeat-ca")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := mtls.GenerateAgentKey("pending-job-agent")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "tenant-a", []string{mtls.AgentRoleNetwork}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, certPath, caPath := filepath.Join(dir, "agent.key"), filepath.Join(dir, "agent.crt"), filepath.Join(dir, "ca.pem")
	if err := identity.Save(keyPath, certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca.BundlePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := ca.ServerCredentials([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := &blockedJobChannel{claimed: make(chan struct{}), beat: make(chan struct{}, 1), release: make(chan struct{}), renewed: make(chan bool, 1)}
	server := transport.NewServer(creds, svc)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, agentOptions{caBundle: caPath, keyPath: keyPath, certPath: certPath,
			commonName: "pending-job-agent", serverName: "agent.trstctl.local", serverAddr: listener.Addr().String(),
			enrollURL: "https://127.0.0.1:1", relayClaim: true, relayPollEvery: 10 * time.Millisecond, rotateEvery: time.Millisecond})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not join the cancelled job")
		}
	})
	select {
	case <-svc.claimed:
	case err := <-done:
		done <- err
		t.Fatalf("agent stopped before claiming: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("agent never reached job channel")
	}
	select {
	case <-svc.beat:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked job suppressed the agent heartbeat")
	}
	// Cross the one-second minimum rotation timer. The worker must keep the
	// same mTLS identity, without starting another worker, until it finishes.
	select {
	case <-svc.renewed:
		t.Fatal("agent rotated its channel identity while a job was active")
	case <-time.After(1500 * time.Millisecond):
	}
	if svc.claims.Load() != 1 {
		t.Fatalf("concurrent claim workers=%d, want one", svc.claims.Load())
	}
	close(svc.release)
	select {
	case wasActive := <-svc.renewed:
		if wasActive {
			t.Fatal("rotation preceded completion of the active job")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not resume its pending identity rotation")
	}
}
