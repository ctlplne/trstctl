package server

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// withAgentChannel enables the served agent steady-state mTLS gRPC channel
// (WIRE-004 / OPS-005) on a served harness. The channel binds an ephemeral port via
// serveAgentChannel in the test, so AgentChannelAddr is not bound here.
func withAgentChannel(d *Deps) {
	d.EnableAgentChannel = true
	d.AgentChannelServerName = "agent.trstctl.local"
	d.AgentHeartbeatInterval = 15 * time.Second
}

// channelClientAdapter adapts a *transport.AgentClient to agent.ChannelClient for the
// test (the same shape cmd/trstctl-agent uses).
type channelClientAdapter struct{ c *transport.AgentClient }

func (a channelClientAdapter) Heartbeat(ctx context.Context, req *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	resp, err := a.c.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: req.AgentID, Version: req.Version, Status: req.Status, CertSerial: req.CertSerial, Inventory: req.Inventory,
	})
	if err != nil {
		return nil, err
	}
	return &agent.HeartbeatResponse{TenantID: resp.TenantID, NextHeartbeatSeconds: resp.NextHeartbeatSeconds}, nil
}

func (a channelClientAdapter) Renew(ctx context.Context, req *agent.RenewRequest) (*agent.RenewResponse, error) {
	resp, err := a.c.Renew(ctx, &transport.RenewRequest{CSRDER: req.CSRDER})
	if err != nil {
		return nil, err
	}
	return &agent.RenewResponse{CertChainPEM: resp.CertChainPEM, NotAfterUnix: resp.NotAfterUnix}, nil
}

// enrollAgent issues a one-time bootstrap token through the served enrollment
// authority and bootstraps an in-memory agent (key generated locally, only the CSR
// submitted), returning the agent and its mTLS credentials. The issued certificate is
// signed by the SAME signer-custodied agent CA the channel trusts (WIRE-004), so the
// agent can connect to the steady-state channel with the cert it bootstrap-enrolled.
func enrollAgent(t *testing.T, h *servedHarness, cn, serverName string) *agent.Agent {
	t.Helper()
	ctx := context.Background()
	tok, err := h.srv.agentEnroll.IssueBootstrapToken(ctx, h.tenant, "")
	if err != nil {
		t.Fatalf("issue bootstrap token: %v", err)
	}
	a := agent.New(agent.Config{
		CommonName:     cn,
		BootstrapToken: tok,
		ServerName:     serverName,
		ServerCAPEM:    h.srv.AgentCACertPEM(),
		Version:        "test-1.0",
	}, &bootstrapOnlyEnroller{a: h.srv.agentEnroll})
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("agent bootstrap: %v", err)
	}
	return a
}

// bootstrapOnlyEnroller drives the agent's bootstrap directly through the served
// enrollment authority (in-process, no HTTP), so the e2e test gets a cert signed by
// the served agent CA without standing up the HTTP enroll route. Renewal over this
// path is unused (the test renews over the gRPC channel).
type bootstrapOnlyEnroller struct {
	a interface {
		EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error)
	}
}

func (e *bootstrapOnlyEnroller) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	return e.a.EnrollBootstrap(ctx, token, csrDER)
}
func (e *bootstrapOnlyEnroller) EnrollRenewal(ctx context.Context, csrDER []byte) ([]byte, error) {
	return nil, context.Canceled // unused in the channel e2e
}

// TestServedAgentChannelEndToEnd is the WIRE-004 / OPS-005 acceptance proof: the SERVED
// control plane mounts the agent steady-state mTLS gRPC channel, an enrolled agent
// connects over mutual TLS with the cert it bootstrap-enrolled, heartbeats (the server
// records it tenant-scoped, AN-1, and emits an event, AN-2), and renews its own
// certificate (a NEW cert is minted through the signer-custodied agent CA, AN-3/AN-4,
// idempotent AN-5, event-sourced AN-2). It MUST fail pre-wiring (no served listener /
// no agent RPCs) and PASS after. An untrusted/unpinned client is rejected.
func TestServedAgentChannelEndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)

	// Wire-in assertions: the channel is served and the agent CA is signer-custodied.
	if !h.srv.AgentChannelServed() {
		t.Fatal("agent channel is not served — wire-in failed (WIRE-004)")
	}
	if !h.srv.OutOfProcessAgentCA() {
		t.Fatal("agent CA key is not held by the out-of-process signer — AN-4 violated (WIRE-004)")
	}

	// Serve the channel on an ephemeral listener (RunAgentChannel binds the configured
	// :9443; the test uses its own port so siblings don't collide).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	addr := ln.Addr().String()

	const serverName = "agent.trstctl.local"
	a := enrollAgent(t, h, "edge-agent-1", serverName)
	oldSerial := a.CertificateSerial()
	if oldSerial == "" {
		t.Fatal("agent has no bootstrap certificate")
	}

	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(addr, creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ch := channelClientAdapter{transport.NewAgentClient(conn)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1) Heartbeat: the server records the agent under its certificate-derived tenant.
	hbResp, err := a.Heartbeat(ctx, ch, map[string]int64{"certs": 3})
	if err != nil {
		t.Fatalf("heartbeat over mTLS channel failed: %v", err)
	}
	if hbResp.TenantID != h.tenant {
		t.Fatalf("heartbeat tenant = %q, want the agent's cert tenant %q (AN-1)", hbResp.TenantID, h.tenant)
	}
	// AN-1: the agent is recorded, tenant-scoped (only under its own tenant).
	agents, err := h.store.ListAgentsPage(ctx, h.tenant, nil, store.ZeroUUID, 20)
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	found := false
	for _, ag := range agents {
		if ag.Name == "edge-agent-1" {
			found = true
			if ag.Version != "test-1.0" {
				t.Errorf("recorded agent version = %q, want test-1.0", ag.Version)
			}
		}
	}
	if !found {
		t.Fatal("heartbeat did not record the agent in its tenant (AN-1)")
	}
	if !h.hasEvent(t, "agent.heartbeat") {
		t.Error("no agent.heartbeat event — the heartbeat was not event-sourced (AN-2)")
	}

	// 2) Renew: a NEW certificate is minted through the signer-custodied agent CA.
	if err := a.RenewOverChannel(ctx, ch); err != nil {
		t.Fatalf("renew over channel failed: %v", err)
	}
	newSerial := a.CertificateSerial()
	if newSerial == "" || newSerial == oldSerial {
		t.Fatalf("renewal did not mint a new certificate (old=%s new=%s)", oldSerial, newSerial)
	}
	// The renewed cert chains to the agent CA and carries the same tenant SPIFFE SAN.
	leafDER, err := mtls.FirstCertDER(a.CertificatePEM())
	if err != nil {
		t.Fatalf("renewed cert PEM: %v", err)
	}
	tenantFromCert, err := mtls.TenantFromClientCert(leafDER)
	if err != nil {
		t.Fatalf("renewed cert tenant SAN: %v", err)
	}
	if tenantFromCert != h.tenant {
		t.Fatalf("renewed cert tenant = %q, want %q (AN-1)", tenantFromCert, h.tenant)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, h.srv.agentCACertDER); err != nil {
		t.Fatalf("renewed cert does not chain to the agent CA: %v", err)
	}
	if !h.hasEvent(t, "agent.cert.renewed") {
		t.Error("no agent.cert.renewed event — the renewal was not event-sourced (AN-2)")
	}

	// 3) AN-5: a RETRIED renewal over the SAME presented certificate with the SAME CSR
	// returns the ORIGINAL minted chain rather than minting a second certificate. We
	// re-dial with the agent's CURRENT (already-renewed) cert so the presented serial is
	// stable across the two calls, submit one fixed CSR twice, and require identical
	// responses.
	creds2, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := transport.Dial(addr, creds2)
	if err != nil {
		t.Fatalf("re-dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	rawClient := transport.NewAgentClient(conn2)
	csrDER := newAgentCSR(t, "edge-agent-1")
	first, err := rawClient.Renew(ctx, &transport.RenewRequest{CSRDER: csrDER})
	if err != nil {
		t.Fatalf("first idempotent renew: %v", err)
	}
	second, err := rawClient.Renew(ctx, &transport.RenewRequest{CSRDER: csrDER})
	if err != nil {
		t.Fatalf("second idempotent renew: %v", err)
	}
	if string(first.CertChainPEM) != string(second.CertChainPEM) {
		t.Fatal("a retried renewal (same presented cert + CSR) minted a DIFFERENT certificate — AN-5 idempotency violated")
	}
}

// newAgentCSR builds a PKCS#10 CSR for a fresh agent key through the mtls boundary, for
// the idempotent-renewal assertion (a fixed CSR submitted twice).
func newAgentCSR(t *testing.T, cn string) []byte {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestServedAgentChannelRejectsUntrustedClient is the WIRE-004 negative: a client whose
// certificate was NOT issued by the agent CA (a different CA), or which presents no
// client certificate, is rejected by the channel's mutual-TLS handshake — the channel
// is fail-closed, not "any cert" or plaintext.
func TestServedAgentChannelRejectsUntrustedClient(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	if !h.srv.AgentChannelServed() {
		t.Fatal("agent channel is not served — wire-in failed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	addr := ln.Addr().String()
	const serverName = "agent.trstctl.local"

	heartbeat := func(creds credentials.TransportCredentials) error {
		conn, err := transport.Dial(addr, creds)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, err = transport.NewAgentClient(conn).Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "imposter"})
		return err
	}

	// (a) An UNTRUSTED CA's client cert is refused (it does not chain to the agent CA).
	other, err := mtls.NewCA("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	rogueCert, err := other.IssueClientCertificate("imposter", mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	rogueCreds, err := mtls.AgentClientCredentials(mtls.StaticSource(rogueCert), h.srv.AgentCACertPEM(), serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := heartbeat(rogueCreds); err == nil {
		t.Fatal("agent channel accepted a client cert from an untrusted CA (fail-closed mTLS expected)")
	}

	// (b) A client presenting NO certificate is refused.
	noCertCreds, err := mtls.AgentClientCredentials(nil, h.srv.AgentCACertPEM(), serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := heartbeat(noCertCreds); err == nil {
		t.Fatal("agent channel accepted a connection with no client certificate")
	}
}
