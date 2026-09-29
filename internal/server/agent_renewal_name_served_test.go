// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Renewal rotates an agent's key; it must never change which agent it is. A valid
// agent that renews with a CSR naming another agent must not become that agent,
// on either the HTTP renewal listener or the gRPC channel: otherwise it can report
// as, and take the work of, any agent in its tenant.
func TestAgentRenewalKeepsTheAgentName(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ctx := context.Background()
	const victimName = "edge-name-victim"
	victim := enrollAgent(t, h, victimName, "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, victim)

	chLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(ctx)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, chLn) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpCtx, httpCancel := context.WithCancel(ctx)
	httpDone := make(chan struct{})
	go func() { defer close(httpDone); h.srv.serveAgentHTTPRenewal(httpCtx, httpLn) }()
	t.Cleanup(func() { httpCancel(); <-httpDone })

	// heartbeatAs reports as whatever agent the certificate names.
	heartbeatAs := func(id *mtls.AgentIdentity, version string) error {
		creds, err := mtls.AgentClientCredentials(id, h.srv.AgentCACertPEM(), "agent.trstctl.local", nil)
		if err != nil {
			return err
		}
		conn, err := transport.Dial(chLn.Addr().String(), creds)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err = transport.NewAgentClient(conn).Heartbeat(hbCtx, &transport.HeartbeatRequest{AgentID: victimName, Version: version, Status: "active"})
		return err
	}
	victimVersion := func() string {
		t.Helper()
		row, err := h.store.GetAgent(ctx, h.tenant, agentRowID(h.tenant, victimName))
		if err != nil {
			t.Fatalf("load victim agent: %v", err)
		}
		return row.Version
	}

	// HTTP renewal listener.
	httpAttacker := enrollAgent(t, h, "edge-name-http", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, httpAttacker)
	renamed, err := mtls.GenerateAgentKey(victimName)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := renamed.CSR()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csr)})
	status, data, err := postHTTPRenewal(agentHTTPRenewalClient(t, h, httpAttacker.Identity()), "https://"+httpLn.Addr().String(), body)
	if err == nil && status == http.StatusOK {
		var out struct {
			Certificate string `json:"certificate"`
		}
		if json.Unmarshal(data, &out) == nil && renamed.UseCertificate([]byte(out.Certificate)) == nil && heartbeatAs(renamed, "http-impostor") == nil && victimVersion() == "http-impostor" {
			t.Errorf("an agent renewed over HTTP into another agent's name and then reported as it")
		}
	}

	// gRPC channel renewal.
	chAttacker := enrollAgent(t, h, "edge-name-channel", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, chAttacker)
	renamed2, err := mtls.GenerateAgentKey(victimName)
	if err != nil {
		t.Fatal(err)
	}
	csr2, err := renamed2.CSR()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := chAttacker.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(chLn.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rnCtx, rnCancel := context.WithTimeout(ctx, 10*time.Second)
	defer rnCancel()
	resp, err := transport.NewAgentClient(conn).Renew(rnCtx, &transport.RenewRequest{CSRDER: csr2})
	if err == nil && renamed2.UseCertificate(resp.CertChainPEM) == nil && heartbeatAs(renamed2, "channel-impostor") == nil && victimVersion() == "channel-impostor" {
		t.Errorf("an agent renewed over the agent channel into another agent's name and then reported as it")
	}
}
