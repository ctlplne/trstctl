// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

// X1: only an agent holding the observer role may report what it saw on the
// wire, and only as observation kinds; what it reports is kept as discovery
// findings without payload, turns passive traffic into an observed coverage
// class, and reads the same after a cold restart.
func TestServedPassiveObserverReportsOnlyWithTheRoleX1(t *testing.T) {
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
	dial := func(cn string, roles []string) *transport.AgentClient {
		t.Helper()
		a := enrollAgentWithRoles(t, h, cn, "agent.trstctl.local", roles)
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
		registerInventoryAgent(t, client)
		return client
	}
	observer := dial("edge-observer", []string{"observer"})
	host := dial("edge-host-only", []string{"host"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	observed := []transport.InventoryFinding{
		{Kind: "tls_handshake", Ref: "tls 10.0.0.5:443 TLSv1.3 X25519MLKEM768 TLS_AES_256_GCM_SHA384", Provenance: "network-observer:eth1", RiskScore: 10,
			Metadata: map[string]string{"protocol": "tls", "server": "10.0.0.5:443", "tls_version": "TLSv1.3", "group": "X25519MLKEM768",
				"pq_hybrid": "true", "certificate_visible": "false", "payload_stored": "false", "connections": "12"}},
		{Kind: "tls_handshake", Ref: "tls 10.0.0.6:443 TLSv1.2 x25519 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 4f2a7c11d9e3b851", Provenance: "network-observer:eth1",
			Fingerprint: strings.Repeat("4f2a7c11d9e3b851", 4), RiskScore: 30,
			Metadata: map[string]string{"protocol": "tls", "server": "10.0.0.6:443", "tls_version": "TLSv1.2", "group": "x25519",
				"certificate_visible": "true", "certificate_key_algorithm": "RSA", "certificate_key_bits": "2048", "payload_stored": "false"}},
		{Kind: "ssh_kex", Ref: "ssh 10.0.0.7:22 mlkem768x25519-sha256 ssh-ed25519", Provenance: "network-observer:eth1", RiskScore: 10,
			Metadata: map[string]string{"protocol": "ssh", "server": "10.0.0.7:22", "kex_algorithm": "mlkem768x25519-sha256", "pq_hybrid": "true", "payload_stored": "false"}},
		{Kind: "plaintext_protocol", Ref: "plaintext http-request 10.0.0.8:80", Provenance: "network-observer:eth1", RiskScore: 90,
			Metadata: map[string]string{"protocol": "http", "server": "10.0.0.8:80", "plaintext_kind": "http-request", "payload_stored": "false"}},
	}

	// An agent without the observer role is refused observation work.
	if _, err := host.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: observed}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a host agent reported observations: %v, want PermissionDenied", err)
	}
	if _, err := host.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem", Findings: observed[:1]}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a host agent smuggled an observation under another source: %v, want InvalidArgument", err)
	}
	if _, err := observer.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: []transport.InventoryFinding{
		{Kind: "private_key", Ref: "/etc/ssl/private/x.key"},
	}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("the observer source reported a non-observation kind: %v, want InvalidArgument", err)
	}
	inv, err := observer.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: observed})
	if err != nil || inv.Recorded != 4 || inv.Rejected != 0 {
		t.Fatalf("observer report: %+v, %v", inv, err)
	}

	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	read := func(srv *servedHarness) (string, string) {
		t.Helper()
		status, findings := secretsReq(t, srv, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, reader, nil)
		if status != http.StatusOK {
			t.Fatalf("observation findings: HTTP %d %s", status, findings)
		}
		status, coverage := secretsReq(t, srv, http.MethodGet, "/api/v1/discovery/coverage?class=passive-wire-traffic", reader, nil)
		if status != http.StatusOK {
			t.Fatalf("coverage: HTTP %d %s", status, coverage)
		}
		return string(findings), string(coverage)
	}
	findings, coverage := read(h)
	var page struct {
		Items []struct {
			Kind     string            `json:"kind"`
			Ref      string            `json:"ref"`
			Metadata map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(findings), &page); err != nil || len(page.Items) != 4 {
		t.Fatalf("observation findings = %s", findings)
	}
	kinds := map[string]int{}
	for _, item := range page.Items {
		kinds[item.Kind]++
		if item.Metadata["payload_stored"] != "false" {
			t.Fatalf("an observation does not say it kept no payload: %+v", item)
		}
	}
	if kinds["tls_handshake"] != 2 || kinds["ssh_kex"] != 1 || kinds["plaintext_protocol"] != 1 {
		t.Fatalf("observation kinds = %v", kinds)
	}
	var cov struct {
		Classes []struct {
			Class  string `json:"class"`
			Status string `json:"status"`
		} `json:"classes"`
	}
	if err := json.Unmarshal([]byte(coverage), &cov); err != nil || len(cov.Classes) != 1 || cov.Classes[0].Status != "OBSERVED" {
		t.Fatalf("passive-wire-traffic coverage = %s", coverage)
	}

	// The same answers from a fresh assembly over the same spine.
	restarted, err := Build(t.Context(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: h.kek,
	})
	if err != nil {
		t.Fatalf("restart assembly: %v", err)
	}
	cleanupServedServer(t, restarted)
	restartedHTTP := httptest.NewServer(restarted.Handler())
	t.Cleanup(restartedHTTP.Close)
	cold := &servedHarness{srv: restarted, ts: restartedHTTP, store: h.store, log: h.log, tenant: h.tenant,
		signer: h.signer, authz: h.authz, caFile: h.caFile, kek: h.kek}
	coldFindings, coldCoverage := read(cold)
	if coldFindings != findings || !strings.Contains(coldCoverage, `"OBSERVED"`) {
		t.Fatalf("after a cold restart:\nfindings %s\ncoverage %s", coldFindings, coldCoverage)
	}
}
