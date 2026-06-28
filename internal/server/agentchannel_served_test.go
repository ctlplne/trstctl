package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/destination/certstore"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
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

func (a channelClientAdapter) ReportInventory(ctx context.Context, req *agent.InventoryRequest) (*agent.InventoryResponse, error) {
	findings := make([]transport.InventoryFinding, 0, len(req.Findings))
	for _, f := range req.Findings {
		findings = append(findings, transport.InventoryFinding{
			Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: f.Metadata,
		})
	}
	resp, err := a.c.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: req.SourceKind, Findings: findings})
	if err != nil {
		return nil, err
	}
	return &agent.InventoryResponse{TenantID: resp.TenantID, RunID: resp.RunID, Recorded: resp.Recorded, Rejected: resp.Rejected}, nil
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
		BootstrapToken: []byte(tok),
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

func (e *bootstrapOnlyEnroller) EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error) {
	return e.a.EnrollBootstrap(ctx, string(token), csrDER)
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
	metrics := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(metrics, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `trstctl_agent_heartbeats_total{result="success"} 1`) {
		t.Fatalf("served /metrics did not expose successful agent heartbeat count:\n%s", metrics.Body.String())
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

func TestAgentCertRevocationIsEventSourced(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	const (
		serverName = "agent.trstctl.local"
		agentName  = "edge-agent-revocation-source"
	)
	a := enrollAgent(t, h, agentName, serverName)
	serial := a.CertificateSerial()
	leafDER, err := mtls.FirstCertDER(a.CertificatePEM())
	if err != nil {
		t.Fatalf("agent certificate PEM: %v", err)
	}
	fingerprint, err := mtls.CertFingerprintSHA256(leafDER)
	if err != nil {
		t.Fatalf("agent cert fingerprint: %v", err)
	}
	agentID := agentRowID(h.tenant, agentName)
	token := seedScopedToken(t, h.store, h.tenant, "agents:write")

	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/"+agentID+"/cert-revocations", token, "agent-revoke-event-sourced", map[string]any{
		"agent":       agentName,
		"serial":      strings.ToUpper(serial),
		"fingerprint": "sha256:" + fingerprint,
		"reason":      "lost host",
	})
	if code != http.StatusCreated {
		t.Fatalf("revoke agent cert: status %d body %s", code, body)
	}
	if !h.hasEvent(t, projections.EventAgentCertRevoked) {
		t.Fatal("agent certificate revocation did not emit agent.cert.revoked")
	}
	revoked, err := h.store.AgentCertRevoked(context.Background(), h.tenant, agentID, serial, fingerprint)
	if err != nil {
		t.Fatalf("query projected revocation: %v", err)
	}
	if !revoked {
		t.Fatal("agent certificate revocation event was not projected into the deny-list")
	}

	if err := projections.New(h.store).Rebuild(context.Background(), h.log); err != nil {
		t.Fatalf("rebuild read model: %v", err)
	}
	revoked, err = h.store.AgentCertRevoked(context.Background(), h.tenant, agentID, serial, fingerprint)
	if err != nil {
		t.Fatalf("query rebuilt revocation: %v", err)
	}
	if !revoked {
		t.Fatal("rebuilt read model lost the agent certificate revocation")
	}
}

func TestServedAgentChannelRevokedCertRejected(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	if !h.srv.AgentChannelServed() {
		t.Fatal("agent channel is not served - wire-in failed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })

	const (
		serverName = "agent.trstctl.local"
		agentName  = "edge-agent-revoked"
	)
	a := enrollAgent(t, h, agentName, serverName)
	agentID := agentRowID(h.tenant, agentName)
	token := seedScopedToken(t, h.store, h.tenant, "agents:write")
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/"+agentID+"/cert-revocations", token, "agent-revoked-cert-rejected", map[string]any{
		"agent":  agentName,
		"serial": a.CertificateSerial(),
		"reason": "compromised host",
	})
	if code != http.StatusCreated {
		t.Fatalf("revoke agent cert: status %d body %s", code, body)
	}

	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)

	before := servedEventCount(t, h, projections.EventAgentHeartbeat)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "attacker-controlled", Version: "test-1.0", Status: "active"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked agent heartbeat error = %v, want PermissionDenied", err)
	}
	after := servedEventCount(t, h, projections.EventAgentHeartbeat)
	if after != before {
		t.Fatalf("revoked heartbeat appended %d heartbeat events, want 0", after-before)
	}
}

// TestServedAgentInventoryOverChannelPopulatesDiscoveryAndGraph is the DISC-01
// acceptance proof: an enrolled agent reports host inventory over the served mTLS
// channel, the control plane derives the tenant from the verified client certificate
// (AN-1), records the findings through discovery events (AN-2), and exposes them
// through served discovery inventory and the credential graph. The findings carry
// only identifiers and metadata, never secret values.
func TestServedAgentInventoryOverChannelPopulatesDiscoveryAndGraph(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	if !h.srv.AgentChannelServed() {
		t.Fatal("agent channel is not served - wire-in failed")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })

	const serverName = "agent.trstctl.local"
	a := enrollAgent(t, h, "edge-agent-inventory", serverName)
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{
		SourceKind: "filesystem",
		Findings: []transport.InventoryFinding{
			{
				Kind:        "x509_certificate",
				Ref:         "/etc/ssl/private/web-leaf.pem",
				Provenance:  "filesystem:/etc/ssl/private/web-leaf.pem",
				Fingerprint: "sha256:agent-web-leaf",
				RiskScore:   35,
				Metadata:    map[string]string{"key_store": "filesystem", "host": "edge-1"},
			},
			{
				Kind:       "secret",
				Ref:        "k8s://apps/web/tls",
				Provenance: "k8s-secret:apps/web/tls",
				RiskScore:  50,
				Metadata:   map[string]string{"namespace": "apps", "name": "web-tls"},
			},
		},
	})
	if err != nil {
		t.Fatalf("report inventory over mTLS channel: %v", err)
	}
	if inv.TenantID != h.tenant {
		t.Fatalf("inventory tenant = %q, want certificate tenant %q", inv.TenantID, h.tenant)
	}
	if inv.RunID == "" || inv.Recorded != 2 || inv.Rejected != 0 {
		t.Fatalf("inventory response = %+v, want two recorded findings and a run id", inv)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "graph:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list agent discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string            `json:"kind"`
			Ref         string            `json:"ref"`
			Provenance  string            `json:"provenance"`
			Fingerprint string            `json:"fingerprint"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode agent discovery findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 2 {
		t.Fatalf("agent discovery findings count = %d body %s, want 2", len(findings.Items), body)
	}
	byRef := map[string]struct {
		Kind        string
		Provenance  string
		Fingerprint string
		Metadata    map[string]string
	}{}
	for _, f := range findings.Items {
		byRef[f.Ref] = struct {
			Kind        string
			Provenance  string
			Fingerprint string
			Metadata    map[string]string
		}{f.Kind, f.Provenance, f.Fingerprint, f.Metadata}
	}
	if got := byRef["/etc/ssl/private/web-leaf.pem"]; got.Kind != "x509_certificate" || got.Fingerprint != "sha256:agent-web-leaf" || got.Metadata["host"] != "edge-1" {
		t.Fatalf("filesystem cert finding not recorded as metadata-only inventory: %+v", got)
	}
	if got := byRef["k8s://apps/web/tls"]; got.Kind != "secret" || got.Provenance != "k8s-secret:apps/web/tls" || got.Metadata["name"] != "web-tls" {
		t.Fatalf("kubernetes secret finding not recorded as metadata-only inventory: %+v", got)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph: status %d body %s", status, body)
	}
	var graphResp struct {
		Nodes []struct {
			ID    string            `json:"id"`
			Kind  string            `json:"kind"`
			Name  string            `json:"name"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &graphResp); err != nil {
		t.Fatalf("decode graph: %v (%s)", err, body)
	}
	var foundCert, foundSecret bool
	for _, n := range graphResp.Nodes {
		if n.Kind != "credential" {
			continue
		}
		switch n.Attrs["discovery_ref"] {
		case "/etc/ssl/private/web-leaf.pem":
			foundCert = n.Attrs["credential_kind"] == "x509_certificate" && n.Attrs["provenance"] == "filesystem:/etc/ssl/private/web-leaf.pem"
		case "k8s://apps/web/tls":
			foundSecret = n.Attrs["credential_kind"] == "secret" && n.Attrs["provenance"] == "k8s-secret:apps/web/tls"
		}
	}
	if !foundCert || !foundSecret {
		t.Fatalf("agent inventory findings did not appear in credential graph: cert=%v secret=%v nodes=%+v", foundCert, foundSecret, graphResp.Nodes)
	}

	for _, eventType := range []string{
		"discovery.source.upserted", "discovery.run.queued", "discovery.run.started",
		"discovery.finding.recorded", "discovery.run.completed",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; agent inventory ingest is not event-sourced", eventType)
		}
	}
}

// TestServedTrustStoreCollectorsReportOverAgentChannel is the DISC-02 acceptance
// proof: agent-side trust-store collectors enumerate public CA certificates from
// Linux, Java cacerts/JKS, NSS/browser export, and Windows-store fixtures, then reuse
// the served DISC-01 inventory channel so those metadata-only trust anchors land in
// served discovery inventory and the credential graph. Private key material is never
// read or sent.
func TestServedTrustStoreCollectorsReportOverAgentChannel(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })

	dir := t.TempDir()
	certs := map[string][]byte{
		"linux":   trustStoreFixturePEM(t, "linux-os-root.test"),
		"java":    trustStoreFixturePEM(t, "java-cacerts-root.test"),
		"nss":     trustStoreFixturePEM(t, "nss-profile-root.test"),
		"browser": trustStoreFixturePEM(t, "browser-profile-root.test"),
		"windows": trustStoreFixturePEM(t, "windows-root-store.test"),
	}
	linuxRoot := filepath.Join(dir, "linux", "anchors")
	mustWriteFile(t, filepath.Join(linuxRoot, "corp-root.pem"), certs["linux"])
	javaStore := filepath.Join(dir, "java", "cacerts")
	javaBlob, err := jks.EncodeTrustStoreDeterministic(map[string][]byte{"corp-java-root": certs["java"]}, "changeit")
	if err != nil {
		t.Fatalf("build java trust-store fixture: %v", err)
	}
	mustWriteFile(t, javaStore, javaBlob)
	nssProfile := filepath.Join(dir, "firefox", "default")
	mustWriteFile(t, filepath.Join(nssProfile, "certs", "corp-nss-root.pem"), certs["nss"])
	browserProfile := filepath.Join(dir, "chromium", "Default")
	mustWriteFile(t, filepath.Join(browserProfile, "trusted-root.der"), firstCertDERFromPEM(t, certs["browser"]))
	winStore := certstore.NewMemory()
	winRef := destination.StoreRef{Location: destination.LocalMachine, Name: "ROOT"}
	if err := winStore.AddCertificate(winRef, "corp-windows-root", certs["windows"]); err != nil {
		t.Fatalf("seed windows trust-store fixture: %v", err)
	}

	sources := []agentdiscovery.Source{
		agentdiscovery.NewOSTrustStoreSource("linux", linuxRoot),
		agentdiscovery.NewJavaTrustStoreSource(javaStore, "changeit"),
		agentdiscovery.NewNSSTrustStoreSource("firefox-default", nssProfile),
		agentdiscovery.NewBrowserTrustStoreSource("chromium", "Default", browserProfile),
		agentdiscovery.NewWindowsTrustStoreSource(winRef.String(), winStore),
	}
	var found []agentdiscovery.Found
	for _, src := range sources {
		got, err := src.Discover(context.Background())
		if err != nil {
			t.Fatalf("discover %s trust store: %v", src.Kind(), err)
		}
		found = append(found, got...)
	}
	if len(found) != len(certs) {
		t.Fatalf("trust-store collectors found %d certs, want %d: %+v", len(found), len(certs), found)
	}

	a := enrollAgent(t, h, "edge-agent-truststores", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{
		SourceKind: agentdiscovery.SourceTrustStore,
		Findings:   trustStoreInventoryFindings(found),
	})
	if err != nil {
		t.Fatalf("report trust-store inventory: %v", err)
	}
	if inv.TenantID != h.tenant || inv.Recorded != len(certs) || inv.Rejected != 0 || inv.RunID == "" {
		t.Fatalf("trust-store inventory response = %+v, want tenant %s and %d recorded", inv, h.tenant, len(certs))
	}

	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "graph:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list trust-store findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Ref         string            `json:"ref"`
			Provenance  string            `json:"provenance"`
			Fingerprint string            `json:"fingerprint"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode trust-store findings: %v (%s)", err, body)
	}
	if len(findings.Items) != len(certs) {
		t.Fatalf("served trust-store findings count = %d body %s, want %d", len(findings.Items), body, len(certs))
	}
	seenKinds := map[string]bool{}
	for _, f := range findings.Items {
		if !strings.HasPrefix(f.Provenance, agentdiscovery.SourceTrustStore+":") {
			t.Fatalf("trust-store finding has wrong provenance: %+v", f)
		}
		if f.Fingerprint == "" {
			t.Fatalf("trust-store finding missing fingerprint: %+v", f)
		}
		seenKinds[f.Metadata["trust_store_kind"]] = true
		if f.Metadata["private_key_present"] != "false" {
			t.Fatalf("trust-store finding claims private key material: %+v", f)
		}
	}
	for _, want := range []string{"os", "java", "nss", "browser", "windows"} {
		if !seenKinds[want] {
			t.Fatalf("missing %s trust-store finding in served inventory: %+v", want, findings.Items)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph after trust-store inventory: status %d body %s", status, body)
	}
	var graphResp struct {
		Nodes []struct {
			Kind  string            `json:"kind"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &graphResp); err != nil {
		t.Fatalf("decode graph: %v (%s)", err, body)
	}
	graphTrustAnchors := 0
	for _, n := range graphResp.Nodes {
		if n.Kind == "credential" && n.Attrs["credential_kind"] == "x509_certificate" && strings.HasPrefix(n.Attrs["provenance"], agentdiscovery.SourceTrustStore+":") {
			graphTrustAnchors++
		}
	}
	if graphTrustAnchors != len(certs) {
		t.Fatalf("credential graph has %d trust-store cert nodes, want %d", graphTrustAnchors, len(certs))
	}
}

// TestServedPrivateKeyMaterialDiscoveryReportsMetadataOnly is the DISC-03
// acceptance proof: an agent-side host fixture contains private-key material, the
// agent locates and classifies it without exfiltrating bytes, and the served mTLS
// inventory channel records only public-key-derived identifiers plus metadata.
func TestServedPrivateKeyMaterialDiscoveryReportsMetadataOnly(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })

	root := t.TempDir()
	keyDER, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate private-key fixture: %v", err)
	}
	defer secret.Wipe(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer secret.Wipe(keyPEM)
	keyPath := filepath.Join(root, "etc", "ssl", "private", "web-leaf.key")
	mustWriteFileMode(t, keyPath, keyPEM, 0o600)
	mustWriteFileMode(t, filepath.Join(root, "noise.txt"), []byte("not a key\n"), 0o644)

	found, err := agentdiscovery.NewPrivateKeySource(root).Discover(context.Background())
	if err != nil {
		t.Fatalf("discover private-key fixture: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("private-key discovery found %d keys, want 1: %+v", len(found), found)
	}
	if found[0].Location != keyPath || found[0].Algorithm != crypto.ECDSAP256 || found[0].Fingerprint == "" {
		t.Fatalf("private-key metadata was not classified from the fixture key: %+v", found[0])
	}

	a := enrollAgent(t, h, "edge-agent-private-keys", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{
		SourceKind: agentdiscovery.SourcePrivateKey,
		Findings:   privateKeyInventoryFindings(found),
	})
	if err != nil {
		t.Fatalf("report private-key inventory: %v", err)
	}
	if inv.TenantID != h.tenant || inv.Recorded != 1 || inv.Rejected != 0 || inv.RunID == "" {
		t.Fatalf("private-key inventory response = %+v, want one recorded finding for tenant %s", inv, h.tenant)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "graph:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list private-key findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "BEGIN PRIVATE KEY") || strings.Contains(string(body), "PRIVATE KEY-----") {
		t.Fatalf("served discovery response exposed private-key bytes:\n%s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string            `json:"kind"`
			Ref         string            `json:"ref"`
			Provenance  string            `json:"provenance"`
			Fingerprint string            `json:"fingerprint"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode private-key findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("served private-key findings count = %d body %s, want 1", len(findings.Items), body)
	}
	got := findings.Items[0]
	if got.Kind != "private_key" || got.Ref != keyPath || got.Provenance != agentdiscovery.SourcePrivateKey+":"+keyPath || got.Fingerprint == "" {
		t.Fatalf("served private-key finding has wrong identity metadata: %+v", got)
	}
	if got.Metadata["material_class"] != "private-key" || got.Metadata["key_algorithm"] != string(crypto.ECDSAP256) || got.Metadata["key_bytes_present"] != "false" {
		t.Fatalf("served private-key finding did not prove metadata-only classification: %+v", got.Metadata)
	}
	for k, v := range got.Metadata {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Fatalf("private-key metadata field %s exposed key material: %q", k, v)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph after private-key inventory: status %d body %s", status, body)
	}
	var graphResp struct {
		Nodes []struct {
			Kind  string            `json:"kind"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &graphResp); err != nil {
		t.Fatalf("decode graph: %v (%s)", err, body)
	}
	foundGraphKey := false
	for _, n := range graphResp.Nodes {
		if n.Kind == "credential" && n.Attrs["credential_kind"] == "private_key" && n.Attrs["discovery_ref"] == keyPath && n.Attrs["fingerprint"] == got.Fingerprint {
			foundGraphKey = true
			break
		}
	}
	if !foundGraphKey {
		t.Fatalf("credential graph did not include metadata-only private-key finding: %+v", graphResp.Nodes)
	}
}

func trustStoreFixturePEM(t *testing.T, commonName string) []byte {
	t.Helper()
	ca, err := mtls.NewCA(commonName)
	if err != nil {
		t.Fatal(err)
	}
	return ca.BundlePEM()
}

func firstCertDERFromPEM(t *testing.T, chain []byte) []byte {
	t.Helper()
	der, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	mustWriteFileMode(t, path, data, 0o644)
}

func mustWriteFileMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func trustStoreInventoryFindings(found []agentdiscovery.Found) []transport.InventoryFinding {
	out := make([]transport.InventoryFinding, 0, len(found))
	for _, f := range found {
		meta := map[string]string{
			"subject":             f.Cert.Subject,
			"issuer":              f.Cert.Issuer,
			"serial":              f.Cert.SerialNumber,
			"key_algorithm":       f.Cert.KeyAlgorithm,
			"not_after":           f.Cert.NotAfter.Format(time.RFC3339),
			"private_key_present": "false",
		}
		for k, v := range f.Metadata {
			meta[k] = v
		}
		out = append(out, transport.InventoryFinding{
			Kind:        "x509_certificate",
			Ref:         f.Location,
			Provenance:  f.Source + ":" + f.Location,
			Fingerprint: f.Cert.SHA256Fingerprint,
			RiskScore:   20,
			Metadata:    meta,
		})
	}
	return out
}

func privateKeyInventoryFindings(found []agentdiscovery.PrivateKeyFound) []transport.InventoryFinding {
	out := make([]transport.InventoryFinding, 0, len(found))
	for _, f := range found {
		meta := map[string]string{
			"material_class":        "private-key",
			"key_format":            f.Format,
			"key_algorithm":         string(f.Algorithm),
			"fingerprint_basis":     f.FingerprintBasis,
			"encrypted":             fmt.Sprintf("%t", f.Encrypted),
			"key_bytes_present":     "false",
			"file_mode_restricted":  fmt.Sprintf("%t", f.Restricted),
			"source_classification": f.Source,
		}
		for k, v := range f.Metadata {
			meta[k] = v
		}
		out = append(out, transport.InventoryFinding{
			Kind:        "private_key",
			Ref:         f.Location,
			Provenance:  f.Source + ":" + f.Location,
			Fingerprint: f.Fingerprint,
			RiskScore:   85,
			Metadata:    meta,
		})
	}
	return out
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
