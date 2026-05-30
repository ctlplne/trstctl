package agent_test

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"certctl.io/certctl/internal/agent"
	"certctl.io/certctl/internal/agent/enroll"
	"certctl.io/certctl/internal/agent/transport"
	"certctl.io/certctl/internal/crypto/mtls"
)

// countingEnroller wraps an Enroller and counts bootstrap calls, and captures the
// last CSR submitted, so tests can assert what crossed the wire.
type countingEnroller struct {
	inner      agent.Enroller
	mu         sync.Mutex
	bootstraps int
	lastCSR    []byte
}

func (c *countingEnroller) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	c.mu.Lock()
	c.bootstraps++
	c.lastCSR = append([]byte(nil), csrDER...)
	c.mu.Unlock()
	return c.inner.EnrollBootstrap(ctx, token, csrDER)
}

func (c *countingEnroller) EnrollRenewal(ctx context.Context, csrDER []byte) ([]byte, error) {
	c.mu.Lock()
	c.lastCSR = append([]byte(nil), csrDER...)
	c.mu.Unlock()
	return c.inner.EnrollRenewal(ctx, csrDER)
}

// startCP starts a mutual-TLS gRPC server (the control plane) serving a health
// check, and returns its address. The caller can stop it to simulate a restart.
func startCP(t *testing.T, authority *enroll.Authority) (addr string, stop func()) {
	t.Helper()
	creds, err := authority.ServerCredentials([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := transport.NewServer(creds) // already registers a SERVING health service
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), srv.Stop
}

// checkHealth dials addr with creds and confirms a health RPC succeeds over mTLS.
func checkHealth(t *testing.T, addr string, creds *agent.Agent) {
	t.Helper()
	tc, err := creds.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	conn, err := transport.Dial(addr, tc)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check over mTLS: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("health status = %v, want SERVING", resp.Status)
	}
}

func newAgent(t *testing.T, en agent.Enroller, authority *enroll.Authority, serverName, token string) *agent.Agent {
	t.Helper()
	dir := t.TempDir()
	return agent.New(agent.Config{
		CommonName:     "agent-1",
		BootstrapToken: token,
		KeyPath:        filepath.Join(dir, "agent.key"),
		CertPath:       filepath.Join(dir, "agent.crt"),
		ServerName:     serverName,
		ServerCAPEM:    authority.CABundlePEM(),
		RefreshBefore:  time.Hour,
	}, en)
}

// TestAgentRegistersAndEstablishesMTLS is the acceptance: the agent registers via
// a bootstrap token and establishes mTLS with the control plane.
func TestAgentRegistersAndEstablishesMTLS(t *testing.T) {
	authority, err := enroll.NewAuthority("certctl Control Plane")
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.IssueBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	addr, stop := startCP(t, authority)
	defer stop()

	a := newAgent(t, authority, authority, "localhost", token)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	checkHealth(t, addr, a)
}

// TestKeysGeneratedLocallyNeverTransmitted: the agent generates its key on the
// host and sends only a CSR; the private key never crosses the enrollment wire.
func TestKeysGeneratedLocallyNeverTransmitted(t *testing.T) {
	authority, _ := enroll.NewAuthority("cp")
	token, _ := authority.IssueBootstrapToken()
	ce := &countingEnroller{inner: authority}

	a := newAgent(t, ce, authority, "localhost", token)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	ce.mu.Lock()
	captured := ce.lastCSR
	ce.mu.Unlock()
	if !mtls.IsCSR(captured) {
		t.Error("what was transmitted to the enroller is not a PKCS#10 CSR (a key may have leaked)")
	}
	if mtls.LooksLikePrivateKey(captured) {
		t.Error("a private key was transmitted to the enroller")
	}
	// The agent nonetheless holds a usable local key (it has an issued cert).
	if a.CertificateSerial() == "" {
		t.Error("agent has no issued certificate after bootstrap")
	}
}

// TestClientCertRotates is the acceptance: the agent's client certificate rotates
// to a fresh one, and mTLS continues to work with the rotated identity.
func TestClientCertRotates(t *testing.T) {
	authority, _ := enroll.NewAuthority("cp")
	token, _ := authority.IssueBootstrapToken()
	addr, stop := startCP(t, authority)
	defer stop()

	a := newAgent(t, authority, authority, "localhost", token)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := a.CertificateSerial()
	checkHealth(t, addr, a)

	if err := a.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	second := a.CertificateSerial()
	if first == "" || second == "" || first == second {
		t.Errorf("certificate did not rotate: first=%q second=%q", first, second)
	}
	checkHealth(t, addr, a) // mTLS still works with the rotated cert
}

// TestSurvivesControlPlaneRestart is the acceptance: after the control plane
// restarts, the agent reconnects using its persisted identity without
// re-bootstrapping.
func TestSurvivesControlPlaneRestart(t *testing.T) {
	authority, _ := enroll.NewAuthority("cp")
	token, _ := authority.IssueBootstrapToken()
	ce := &countingEnroller{inner: authority}

	addr1, stop1 := startCP(t, authority)
	dir := t.TempDir()
	cfg := agent.Config{
		CommonName: "agent-1", BootstrapToken: token,
		KeyPath: filepath.Join(dir, "agent.key"), CertPath: filepath.Join(dir, "agent.crt"),
		ServerName: "localhost", ServerCAPEM: authority.CABundlePEM(), RefreshBefore: time.Hour,
	}
	a := agent.New(cfg, ce)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkHealth(t, addr1, a)
	stop1() // control plane goes down

	// The control plane restarts (same CA), on a new address.
	addr2, stop2 := startCP(t, authority)
	defer stop2()

	// A fresh agent process with the same data dir reloads its identity and
	// reconnects — it does not bootstrap again.
	a2 := agent.New(cfg, ce)
	if err := a2.Bootstrap(context.Background()); err != nil {
		t.Fatalf("restart Bootstrap: %v", err)
	}
	ce.mu.Lock()
	bootstraps := ce.bootstraps
	ce.mu.Unlock()
	if bootstraps != 1 {
		t.Errorf("enroller bootstrap called %d times, want 1 (identity should be reloaded, not re-bootstrapped)", bootstraps)
	}
	checkHealth(t, addr2, a2)
}
