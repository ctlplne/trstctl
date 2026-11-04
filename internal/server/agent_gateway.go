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

	"trstctl.com/trstctl/internal/agent/relay"
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

// SignJobSSHKey certifies an access gateway's per-session SSH key (A254 part
// 2) for a session job the gateway holds now: the lease is this agent's at
// this attempt, the agent holds the gateway role, and the job is that
// gateway's session. The certificate names the session's principal and its
// key ID (pam:<session>) and stops working at the session's deadline;
// revoking the session revokes the key ID, so every certificate signed for it.
func (a *agentService) SignJobSSHKey(ctx context.Context, req *transport.SignJobSSHKeyRequest) (*transport.SignJobSSHKeyResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if a.store == nil || a.signGatewaySSHKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "access gateways are not served by this control plane")
	}
	if !agentHasRole(info.Roles, mtls.AgentRoleGateway) {
		return nil, status.Error(codes.PermissionDenied, "a session SSH key is certified only for a gateway-role agent")
	}
	if req == nil || req.JobID <= 0 || req.Attempt <= 0 || len(req.PublicKey) == 0 || len(req.PublicKey) > 8<<10 {
		return nil, status.Error(codes.InvalidArgument, "job_id, attempt and a public key are required")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	job, held, err := a.store.GetAgentJobForRedemption(ctx, info.TenantID, agentID, req.JobID, time.Now().UTC())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load job: %v", err)
	}
	if !held || job.ClaimAttempts != req.Attempt || job.Destination != relay.KindAccessGatewaySession || job.RequiredAgentID != agentID {
		return nil, status.Error(codes.PermissionDenied, "this agent does not hold that gateway session at that attempt")
	}
	certificate, validBefore, err := a.signGatewaySSHKey(ctx, info.TenantID, agentID, job.Payload, req.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "certify the session key: %v", err)
	}
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.gateway.session_key_certified", map[string]any{
		"agent": info.CommonName, "job_id": req.JobID, "attempt": req.Attempt,
	})
	return &transport.SignJobSSHKeyResponse{Certificate: certificate, ValidBeforeUnix: validBefore.Unix()}, nil
}

// SignJobSSHKey on the bulkhead wrapper dispatches into the agent-channel pool.
func (b *bulkheadedAgentService) SignJobSSHKey(ctx context.Context, req *transport.SignJobSSHKeyRequest) (*transport.SignJobSSHKeyResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "sign_job_ssh_key", b.metrics, func(ctx context.Context) (*transport.SignJobSSHKeyResponse, error) {
		return b.next.SignJobSSHKey(ctx, req)
	})
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
	for key, t := range s.databases {
		if key.tenantID == tenantID && t.cfg.GatewayAgentID == agentID {
			add(t.cfg.GatewayAddress)
		}
	}
	for key, t := range s.sshTargets {
		if key.tenantID == tenantID && t.GatewayAgentID == agentID {
			add(t.GatewayAddress)
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
