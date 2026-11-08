// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// X5: only an agent holding the session-observer role may report the TLS
// sessions it read from its host's TLS libraries, and only as tls_session
// findings, which no other source may send. What it reports is kept as
// discovery findings that say no application data was read and turns host
// TLS sessions into an observed coverage class. When an operator removes the
// role, the agent's next renewal drops it from the certificate and the server
// refuses that agent's next session report.
func TestServedSessionObserverReportsOnlyWithTheRoleX5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := newRoleHarnessNamedWithEventOptions(t, "x5-session-observer", []string{mtls.AgentRoleHost, mtls.AgentRoleSessionObserver}, nil, nil)
	agentID := agentRowID(h.tenant, h.agent)
	registerInventoryAgent(t, h.client)
	dial := func(creds credentials.TransportCredentials) *transport.AgentClient {
		t.Helper()
		conn, err := transport.Dial(h.channelAddr, creds)
		if err != nil {
			t.Fatalf("dial agent channel: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		client := transport.NewAgentClient(conn)
		registerInventoryAgent(t, client)
		return client
	}
	hostAgent := enrollAgentWithRoles(t, h.servedHarness, "x5-host-only", h.serverName, []string{mtls.AgentRoleHost})
	hostCreds, err := hostAgent.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	host := dial(hostCreds)

	fp := strings.Repeat("a7897789", 8)
	sessions := []transport.InventoryFinding{
		{Kind: "tls_session", Ref: "tls-session|/usr/bin/curl|client|api.x5.test|TLSv1.3|TLS_AES_256_GCM_SHA384|X25519MLKEM768|" + fp,
			Provenance: "tls-session-observer:/usr/bin/curl", Fingerprint: fp, RiskScore: 10,
			Metadata: map[string]string{"protocol": "tls", "process": "curl", "executable": "/usr/bin/curl", "side": "client",
				"tls_version": "TLSv1.3", "group": "X25519MLKEM768", "pq_hybrid": "true", "peer_certificate_visible": "true",
				"peer_certificate_key_algorithm": "ECDSA", "peer_certificate_key_bits": "256", "application_data_read": "false", "sessions": "3"}},
		{Kind: "tls_session", Ref: "tls-session|/usr/sbin/nginx|server|db.x5.test|TLSv1.2|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|x25519|-",
			Provenance: "tls-session-observer:/usr/sbin/nginx", RiskScore: 30,
			Metadata: map[string]string{"protocol": "tls", "process": "nginx", "executable": "/usr/sbin/nginx", "side": "server",
				"tls_version": "TLSv1.2", "group": "x25519", "peer_certificate_visible": "false", "application_data_read": "false"}},
	}

	// An agent without the role is refused the work, and no other source may
	// carry sessions; the session source carries nothing else.
	if _, err := host.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "tls-session-observer", Findings: sessions}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a host agent reported TLS sessions: %v, want PermissionDenied", err)
	}
	if _, err := host.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem", Findings: sessions[:1]}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a host agent smuggled a TLS session under another source: %v, want InvalidArgument", err)
	}
	for _, kind := range []string{"private_key", "tls_handshake"} {
		if _, err := h.client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "tls-session-observer", Findings: []transport.InventoryFinding{
			{Kind: kind, Ref: "x5-not-a-session"},
		}}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("the session source reported a %s finding: %v, want InvalidArgument", kind, err)
		}
	}
	inv, err := h.client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "tls-session-observer", Findings: sessions})
	if err != nil || inv.Recorded != 2 || inv.Rejected != 0 {
		t.Fatalf("session observer report: %+v, %v", inv, err)
	}

	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, reader, nil)
	if code != http.StatusOK {
		t.Fatalf("session findings: HTTP %d %s", code, body)
	}
	var page struct {
		Items []struct {
			Kind        string            `json:"kind"`
			Fingerprint string            `json:"fingerprint"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil || len(page.Items) != 2 {
		t.Fatalf("session findings = %s", body)
	}
	for _, item := range page.Items {
		if item.Kind != "tls_session" || item.Metadata["application_data_read"] != "false" {
			t.Fatalf("a session finding %+v does not say it read no application data", item)
		}
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/coverage?class=host-tls-sessions", reader, nil)
	var cov struct {
		Classes []struct {
			Class  string `json:"class"`
			Status string `json:"status"`
		} `json:"classes"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &cov) != nil || len(cov.Classes) != 1 || cov.Classes[0].Status != "OBSERVED" {
		t.Fatalf("host-tls-sessions coverage = %d %s", code, body)
	}

	// The operator removes the role; the agent's renewal drops it, and the
	// renewed agent's report is refused.
	granter := seedScopedToken(t, h.store, h.tenant, "agents:relay.grant")
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/"+agentID+"/roles", granter, "x5-remove-role",
		map[string]any{"roles": []string{mtls.AgentRoleHost}, "reason": "stop observing TLS on this host"})
	if code != http.StatusOK {
		t.Fatalf("remove the session-observer role = %d %s", code, body)
	}
	if beat, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "x5", Status: "active"}); err != nil || !beat.RenewCertificate {
		t.Fatalf("heartbeat after the role was removed = %+v, %v; want a renewal request", beat, err)
	}
	renewed, err := mtls.GenerateAgentKey(h.agent)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := renewed.CSR()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: csr})
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if err := renewed.UseCertificate(resp.CertChainPEM); err != nil {
		t.Fatal(err)
	}
	if roles := renewed.Roles(); !slices.Equal(roles, []string{mtls.AgentRoleHost}) {
		t.Fatalf("renewed certificate roles = %v, want host only", roles)
	}
	creds, err := mtls.AgentClientCredentials(renewed, h.srv.AgentCACertPEM(), h.serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := dial(creds)
	if _, err := after.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "tls-session-observer", Findings: sessions}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the agent reported TLS sessions after its role was removed: %v, want PermissionDenied", err)
	}
}
