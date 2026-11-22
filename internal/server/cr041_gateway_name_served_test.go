// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestCR041GatewayCannotMintControlPlaneServerName(t *testing.T) {
	h := newRoleHarnessNamedWithEventOptions(t, "cr041-"+uuid.NewString(), []string{mtls.AgentRoleGateway}, nil, nil, func(d *Deps) {
		wirePAMPostgresProvider(d, pamPostgresAdminFileRef(t, "postgres://test:test@127.0.0.1:1/postgres"), time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: 30 * time.Second, MaxTTL: time.Minute,
			ExpiryInterval: 50 * time.Millisecond, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "access:read", "access:targets.write")
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", token, "run1", map[string]any{
		"id": "lookalike", "target_type": "postgres", "provider_id": "pam-pg-provider",
		"allowed_roles": []string{"readonly"}, "gateway_agent_id": agentRowID(h.tenant, h.agent),
		"gateway_address": h.serverName + ":19443",
	})
	if code != http.StatusCreated {
		t.Fatalf("register gateway binding = HTTP %d %s", code, body)
	}
	var signErr error
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{h.serverName}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{
			CSRDER: csr, Hosts: []string{h.serverName},
		})
		signErr = err
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, errors.New("gateway certificate is not PEM")
		}
		return block.Bytes, nil
	})
	if cert != nil {
		cert.Close()
	}
	if status.Code(signErr) != codes.PermissionDenied || err == nil {
		t.Fatalf("gateway certificate for control-plane name = cert_present %v, sign err %v, issue err %v; want permission denied", cert != nil, signErr, err)
	}
}
