package agent_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"trustctl.io/trustctl/internal/agent"
	"trustctl.io/trustctl/internal/agent/enroll"
	"trustctl.io/trustctl/internal/agent/transport"
	"trustctl.io/trustctl/internal/crypto/mtls"
)

// authorityEnroller adapts a server-side *enroll.Authority to the client-side
// agent.Enroller interface for these tests. EnrollBootstrap maps straight through.
// EnrollRenewal must supply the caller's VERIFIED peer chain — in production the mTLS
// transport does this and the handler reads r.TLS.VerifiedChains (WIRE-006). Here the
// adapter stands in for that transport by reading the agent's currently-persisted
// client certificate from certPath and presenting its leaf as the peer chain, so a
// rotation authenticates exactly as it would over mTLS. When certPath is empty (a
// bootstrap-only test that never renews) renewal gets no peer cert and the authority
// fails it closed — the intended hardened behavior.
type authorityEnroller struct {
	authority *enroll.Authority
	certPath  string // the agent's persisted cert chain (PEM); read at renewal to form the peer chain
}

func (a authorityEnroller) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	return a.authority.EnrollBootstrap(ctx, token, csrDER)
}

func (a authorityEnroller) EnrollRenewal(ctx context.Context, csrDER []byte) ([]byte, error) {
	var peer [][]byte
	if a.certPath != "" {
		if pem, err := os.ReadFile(a.certPath); err == nil {
			if der, err := mtls.FirstCertDER(pem); err == nil {
				peer = [][]byte{der}
			}
		}
	}
	return a.authority.EnrollRenewal(ctx, peer, csrDER)
}

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
	srv := transport.NewServer(creds, nil) // already registers a SERVING health service
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
	authority, err := enroll.NewAuthority("trustctl Control Plane", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	if err != nil {
		t.Fatal(err)
	}
	addr, stop := startCP(t, authority)
	defer stop()

	a := newAgent(t, authorityEnroller{authority: authority}, authority, "localhost", token)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	checkHealth(t, addr, a)
}

// TestKeysGeneratedLocallyNeverTransmitted: the agent generates its key on the
// host and sends only a CSR; the private key never crosses the enrollment wire.
func TestKeysGeneratedLocallyNeverTransmitted(t *testing.T) {
	authority, _ := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	token, _ := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	ce := &countingEnroller{inner: authorityEnroller{authority: authority}}

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
// to a fresh one, and mTLS continues to work with the rotated identity. The
// adapter presents the agent's current persisted cert as the verified peer chain at
// renewal, mirroring the production mTLS path the hardened EnrollRenewal requires
// (WIRE-006).
func TestClientCertRotates(t *testing.T) {
	authority, _ := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	token, _ := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	addr, stop := startCP(t, authority)
	defer stop()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	a := agent.New(agent.Config{
		CommonName: "agent-1", BootstrapToken: token,
		KeyPath: filepath.Join(dir, "agent.key"), CertPath: certPath,
		ServerName: "localhost", ServerCAPEM: authority.CABundlePEM(), RefreshBefore: time.Hour,
	}, authorityEnroller{authority: authority, certPath: certPath})
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
	authority, _ := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	token, _ := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	ce := &countingEnroller{inner: authorityEnroller{authority: authority}}

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
