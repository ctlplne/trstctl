// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Every certificate here is signed by the actual served agent CA. TLS trust
// alone must not admit a missing, ambiguous or different registration binding.
func TestServedAgentCertificateRequiresExactRegistrationBinding(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	registerServedTenant(t, h, "Agent binding tenant")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = grpcListener.Close()
		t.Fatal(err)
	}
	grpcDone, httpDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(grpcDone); h.srv.serveAgentChannel(ctx, grpcListener) }()
	go func() { defer close(httpDone); h.srv.serveAgentHTTPRenewal(ctx, httpListener) }()
	t.Cleanup(func() { cancel(); <-grpcDone; <-httpDone })
	bindings, err := agentCertificateAuthorityURIs(ctx, h.store, h.log, h.tenant, nil)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("resolve registration: %v, %v", bindings, err)
	}
	issuer := agentCAIssuer{caSigner: h.srv.agentCASigner, caCertDER: h.srv.agentCACertDER}
	for _, tc := range []struct {
		name  string
		uris  []string
		valid bool
	}{
		{name: "current", uris: bindings, valid: true},
		{name: "missing"},
		{name: "duplicate", uris: []string{bindings[0], bindings[0]}},
		{name: "different", uris: []string{bindings[0] + "-other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := mtls.GenerateAgentKey("binding-" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Destroy()
			csr, err := identity.CSR()
			if err != nil {
				t.Fatal(err)
			}
			chain, err := issuer.SignClientCSRWithTenant(csr, h.tenant, nil, time.Hour, tc.uris...)
			if err != nil {
				t.Fatal(err)
			}
			if err := identity.UseCertificate(chain); err != nil {
				t.Fatal(err)
			}
			credentials, err := mtls.AgentClientCredentials(identity, h.srv.AgentCACertPEM(), "agent.trstctl.local", nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := transport.Dial(grpcListener.Addr().String(), credentials)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			callCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			_, heartbeatErr := transport.NewAgentClient(conn).Heartbeat(callCtx, &transport.HeartbeatRequest{Status: "active"})
			if tc.valid && heartbeatErr != nil {
				t.Fatalf("current binding heartbeat: %v", heartbeatErr)
			}
			if !tc.valid && status.Code(heartbeatErr) != codes.PermissionDenied {
				t.Fatalf("invalid binding heartbeat = %v, want PermissionDenied", heartbeatErr)
			}
			client := agentHTTPRenewalClient(t, h, identity)
			defer client.CloseIdleConnections()
			body, err := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csr)})
			if err != nil {
				t.Fatal(err)
			}
			code, data, err := postHTTPRenewal(client, "https://"+httpListener.Addr().String(), body)
			if err != nil {
				t.Fatalf("trusted certificate failed before HTTP authorization: %v", err)
			}
			if tc.valid && code != http.StatusOK {
				t.Fatalf("current binding renewal = %d, %s", code, data)
			}
			if !tc.valid && (code != http.StatusUnauthorized || !strings.Contains(string(data), "enroll again")) {
				t.Fatalf("invalid binding renewal = %d, %s; want 401 with re-enrollment guidance", code, data)
			}
		})
	}
}
