// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"net"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// gatewayServerCertificateTTL bounds one access gateway serving certificate;
// the gateway's renewal worker asks again well before it ends.
const gatewayServerCertificateTTL = 24 * time.Hour

// SignGatewayServerCertificate signs an access gateway's listener CSR (A254)
// with the agent CA: only for a gateway-role agent, only for host names that a
// target binding naming this agent declares, and naming the agent's SPIFFE ID,
// so a client verifies both the host and which agent it reached.
func (a *agentService) SignGatewayServerCertificate(ctx context.Context, req *transport.SignGatewayServerCertificateRequest) (*transport.SignGatewayServerCertificateResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if a.gatewayBoundHosts == nil || a.signGatewayServerCSR == nil {
		return nil, status.Error(codes.FailedPrecondition, "access gateways are not served by this control plane")
	}
	if !agentHasRole(info.Roles, mtls.AgentRoleGateway) {
		return nil, status.Error(codes.PermissionDenied, "a gateway serving certificate needs the gateway role")
	}
	if req == nil || len(req.CSRDER) == 0 || len(req.Hosts) == 0 || len(req.Hosts) > 16 {
		return nil, status.Error(codes.InvalidArgument, "a CSR and one to sixteen host names are required")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	bound, err := a.gatewayBoundHosts(ctx, info.TenantID, agentID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read gateway bindings: %v", err)
	}
	hosts := make([]string, 0, len(req.Hosts))
	for _, h := range req.Hosts {
		h = strings.TrimSpace(h)
		if h == "" || !slices.Contains(bound, h) {
			return nil, status.Errorf(codes.PermissionDenied, "host %q is not the address of a target bound to this gateway", h)
		}
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	der, err := a.signGatewayServerCSR(req.CSRDER, hosts, []string{mtls.AgentSPIFFEID(info.TenantID, info.CommonName)}, gatewayServerCertificateTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign gateway serving certificate: %v", err)
	}
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.gateway.server_certificate_signed", map[string]any{
		"agent": info.CommonName, "hosts": hosts,
	})
	return &transport.SignGatewayServerCertificateResponse{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		NotAfterUnix:   time.Now().Add(gatewayServerCertificateTTL).Unix(),
	}, nil
}

// SignGatewayServerCertificate on the bulkhead wrapper dispatches into the
// agent-channel pool.
func (b *bulkheadedAgentService) SignGatewayServerCertificate(ctx context.Context, req *transport.SignGatewayServerCertificateRequest) (*transport.SignGatewayServerCertificateResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "sign_gateway_server_certificate", b.metrics, func(ctx context.Context) (*transport.SignGatewayServerCertificateResponse, error) {
		return b.next.SignGatewayServerCertificate(ctx, req)
	})
}

// gatewayBoundHosts lists the hosts of every enabled target bound to one
// gateway agent, from operator configuration and tenant registrations.
func (s *pamService) gatewayBoundHosts(ctx context.Context, tenantID, agentID string) ([]string, error) {
	var hosts []string
	add := func(address string) {
		if host, _, err := net.SplitHostPort(address); err == nil && host != "" && !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	for key, t := range s.postgres {
		if key.tenantID == tenantID && t.cfg.GatewayAgentID == agentID {
			add(t.cfg.GatewayAddress)
		}
	}
	targets, err := s.store.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		if t.Enabled && t.GatewayAgentID == agentID {
			add(t.GatewayAddress)
		}
	}
	return hosts, nil
}

func (s *Server) pamGatewayBoundHosts() func(ctx context.Context, tenantID, agentID string) ([]string, error) {
	if s.pam == nil {
		return nil
	}
	return s.pam.gatewayBoundHosts
}

// signGatewayServerCSR signs a gateway listener's CSR with the agent CA, whose
// key stays in the signer process (AN-4).
func (s *Server) signGatewayServerCSR(csr []byte, hosts, uris []string, ttl time.Duration) ([]byte, error) {
	return crypto.SignServerCertFromCSRWithURIs(s.agentCACertDER, s.agentCASigner, csr, hosts, uris, ttl)
}
