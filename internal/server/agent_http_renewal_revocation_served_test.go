// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// RV-14.1x: the HTTP agent-renewal listener must refuse a certificate the operator
// revoked, and any certificate of an offboarded agent, exactly as the gRPC agent
// channel does. Otherwise a revoked but unexpired agent mints itself a fresh,
// unrevoked identity and the revocation is undone.
func TestServedHTTPRenewalRefusesRevokedAndOffboardedAgents(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	if !h.srv.AgentHTTPRenewalServed() {
		t.Fatal("agent HTTP renewal listener is not served")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentHTTPRenewal(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	baseURL := "https://" + ln.Addr().String()
	token := seedScopedToken(t, h.store, h.tenant, "agents:write")
	renewalBody := func(cn string) []byte {
		t.Helper()
		successor, err := mtls.GenerateAgentKey(cn)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := successor.CSR()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csr)})
		return body
	}
	refused := func(what, cn string, src mtls.ClientCertSource) {
		t.Helper()
		status, data, err := postHTTPRenewal(agentHTTPRenewalClient(t, h, src), baseURL, renewalBody(cn))
		if err == nil && status == http.StatusOK {
			t.Errorf("%s renewed over HTTP (status 200, body %s); want 401 or 403", what, data)
			return
		}
		if err == nil && status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Errorf("%s renewal status = %d body %s; want 401 or 403", what, status, data)
		}
	}

	healthy := enrollAgent(t, h, "edge-http-healthy", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, healthy)
	if status, data, err := postHTTPRenewal(agentHTTPRenewalClient(t, h, healthy.Identity()), baseURL, renewalBody("edge-http-healthy")); err != nil || status != http.StatusOK {
		t.Fatalf("healthy agent renewal = %d body %s err %v; want 200", status, data, err)
	}

	revoked := enrollAgent(t, h, "edge-http-revoked", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, revoked)
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/"+agentRowID(h.tenant, "edge-http-revoked")+"/cert-revocations", token, "rv141x-revoke", map[string]any{
		"agent": "edge-http-revoked", "serial": revoked.CertificateSerial(), "reason": "compromised host",
	})
	if code != http.StatusCreated {
		t.Fatalf("revoke agent certificate = %d body %s", code, body)
	}
	refused("revoked agent certificate", "edge-http-revoked", revoked.Identity())

	offboarded := enrollAgent(t, h, "edge-http-offboarded", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, offboarded)
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/"+agentRowID(h.tenant, "edge-http-offboarded")+"/offboard", token, "rv141x-offboard", map[string]any{
		"reason": "host decommissioned",
	})
	if code != http.StatusOK {
		t.Fatalf("offboard agent = %d body %s", code, body)
	}
	refused("offboarded agent certificate", "edge-http-offboarded", offboarded.Identity())
}
