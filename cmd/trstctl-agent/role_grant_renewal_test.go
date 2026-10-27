// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// roleGrantChannelService stands in for a control plane holding an operator's
// pending network-role grant: heartbeats ask for a renewal until one has
// signed the grant, and the renewal signs the granted roles.
type roleGrantChannelService struct {
	ca         *mtls.CA
	renewals   atomic.Int32
	heartbeats chan *transport.HeartbeatRequest
}

func (s *roleGrantChannelService) Heartbeat(_ context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	clone := *req
	go func() { s.heartbeats <- &clone }()
	return &transport.HeartbeatResponse{TenantID: "tenant-a", NextHeartbeatSeconds: 30, RenewCertificate: s.renewals.Load() == 0}, nil
}

func (s *roleGrantChannelService) Renew(_ context.Context, req *transport.RenewRequest) (*transport.RenewResponse, error) {
	s.renewals.Add(1)
	chain, err := s.ca.SignClientCSRWithTenant(req.CSRDER, "tenant-a", []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, time.Hour)
	if err != nil {
		return nil, err
	}
	return &transport.RenewResponse{CertChainPEM: chain, NotAfterUnix: time.Now().Add(time.Hour).Unix()}, nil
}

func (*roleGrantChannelService) ReportInventory(context.Context, *transport.InventoryRequest) (*transport.InventoryResponse, error) {
	return &transport.InventoryResponse{}, nil
}

// A191: a host agent whose heartbeat says its roles changed renews at once,
// well before its scheduled rotation, and reconnects with the certificate that
// carries the granted role; once the grant is signed it stops renewing.
func TestAgentRenewsWhenTheControlPlaneSaysItsRolesChanged(t *testing.T) {
	agentCA, err := mtls.NewCA("role-grant-test-ca")
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
	enrollmentServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // #nosec G112 -- local test listener owned and torn down by the test (CWE-400)
		var request struct {
			CSR string `json:"csr"`
		}
		if r.URL.Path != "/enroll/bootstrap" || json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "unexpected enrollment request", http.StatusBadRequest)
			return
		}
		csr, err := base64.StdEncoding.DecodeString(request.CSR)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		chain, err := agentCA.SignClientCSRWithTenant(csr, "tenant-a", []string{mtls.AgentRoleHost}, time.Hour)
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
	service := &roleGrantChannelService{ca: agentCA, heartbeats: make(chan *transport.HeartbeatRequest, 8)}
	grpcServer := transport.NewServer(serverCreds, service)
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(grpcListener) }()
	t.Cleanup(grpcServer.Stop)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "control-plane-ca.pem")
	if err := os.WriteFile(caPath, append(append([]byte(nil), enrollmentCert.TrustPEM...), agentCA.BundlePEM()...), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "bootstrap-token")
	if err := os.WriteFile(tokenPath, []byte("one-time-bootstrap-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "agent.crt")
	options := agentOptions{
		enrollURL:   "https://" + enrollmentListener.Addr().String(),
		tokenFile:   tokenPath,
		caBundle:    caPath,
		serverAddr:  grpcListener.Addr().String(),
		serverName:  "agent.trstctl.local",
		commonName:  "edge-1",
		keyPath:     filepath.Join(dir, "agent.key"),
		certPath:    certPath,
		rotateEvery: time.Hour,
	}
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runAgent(runCtx, options) }()

	next := func() *transport.HeartbeatRequest {
		t.Helper()
		select {
		case beat := <-service.heartbeats:
			return beat
		case err := <-result:
			t.Fatalf("agent stopped: %v", err)
		case <-time.After(20 * time.Second):
			t.Fatal("no heartbeat")
		}
		return nil
	}
	first := next()
	second := next()
	if first.CertSerial == "" || second.CertSerial == first.CertSerial {
		t.Fatalf("the agent did not reconnect with a renewed certificate: %q then %q", first.CertSerial, second.CertSerial)
	}
	if n := service.renewals.Load(); n != 1 {
		t.Fatalf("renewals = %d, want exactly one for the grant", n)
	}
	chain, err := os.ReadFile(certPath) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	if roles, err := mtls.AgentRolesFromClientCert(leaf); err != nil || !slices.Contains(roles, mtls.AgentRoleNetwork) {
		t.Fatalf("the persisted certificate carries roles %v, %v; want the granted network role", roles, err)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("agent shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop")
	}
}
