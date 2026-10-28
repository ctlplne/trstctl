// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

// A219: a host holding a delegated edge CA sends its issuance journal over the
// agent channel when it reconnects, so issuances made while it was offline
// reconcile without an operator posting the file. The control plane reconciles
// it through the same path as the operator's reconcile route. The host is the
// channel certificate's name: an agent reaches only the delegations minted for
// its own host, and each certificate counts against the delegation that
// issued it.

var (
	errEdgeJournalNotServed    = errors.New("edge delegation is not served by this control plane")
	errEdgeJournalNoDelegation = errors.New("no edge delegation was minted for this host")
)

// ReportEdgeJournal implements transport.AgentEdgeServiceServer.
func (a *agentService) ReportEdgeJournal(ctx context.Context, req *transport.EdgeJournalRequest) (*transport.EdgeJournalResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if !agentHasRole(info.Roles, mtls.AgentRoleHost) {
		return nil, status.Error(codes.PermissionDenied, "edge journals come from host agents")
	}
	if a.reconcileEdgeJournal == nil {
		return nil, status.Error(codes.FailedPrecondition, errEdgeJournalNotServed.Error())
	}
	if _, err := a.store.GetAgent(ctx, info.TenantID, agentRowID(info.TenantID, info.CommonName)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.FailedPrecondition, "send an authenticated heartbeat before an edge journal")
		}
		return nil, status.Error(codes.Unavailable, "agent registration state is unavailable; retry later")
	}
	if req == nil || len(req.CertificatesPEM) == 0 {
		return nil, status.Error(codes.InvalidArgument, "an edge journal needs at least one certificate")
	}
	if len(req.CertificatesPEM) > transport.EdgeJournalMaxCertificates {
		return nil, status.Errorf(codes.InvalidArgument, "an edge journal upload carries at most %d certificates", transport.EdgeJournalMaxCertificates)
	}
	for _, certificatePEM := range req.CertificatesPEM {
		if len(certificatePEM) > transport.EdgeJournalMaxCertificateBytes {
			return nil, status.Errorf(codes.InvalidArgument, "an edge journal certificate is larger than %d bytes", transport.EdgeJournalMaxCertificateBytes)
		}
	}
	out, err := a.reconcileEdgeJournal(ctx, info.TenantID, info.CommonName, req.CertificatesPEM)
	switch {
	case errors.Is(err, errEdgeJournalNoDelegation):
		return nil, status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, errEdgeJournalNotServed):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case err != nil:
		if a.logger != nil {
			a.logger.Warn("edge journal reconcile failed", "tenant_id", info.TenantID, "error", err)
		}
		return nil, status.Error(codes.Unavailable, "the edge journal could not be reconciled; retry later")
	}
	return out, nil
}

// reconcileEdgeJournal routes each certificate to the delegation of host that
// issued it and reconciles each delegation's certificates as the agent. A
// certificate no delegation of this host issued is rejected, never recorded.
func (s *Server) reconcileEdgeJournal(ctx context.Context, tenantID, host string, certificatesPEM []string) (*transport.EdgeJournalResponse, error) {
	if s.edgeDelegations == nil {
		return nil, errEdgeJournalNotServed
	}
	delegations, err := s.store.ListEdgeDelegations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id  string
		der []byte
	}
	var candidates []candidate
	for _, d := range delegations {
		if !strings.EqualFold(strings.TrimSpace(d.Host), strings.TrimSpace(host)) {
			continue
		}
		der, err := firstCertDER(d.CertificatePEM)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{id: d.ID, der: der})
	}
	if len(candidates) == 0 {
		return nil, errEdgeJournalNoDelegation
	}
	out := &transport.EdgeJournalResponse{}
	groups := map[string][]string{}
	var order []string
	for _, certificatePEM := range certificatesPEM {
		block, _ := pem.Decode([]byte(certificatePEM))
		if block == nil || block.Type != "CERTIFICATE" {
			out.Rejected++
			continue
		}
		issuer := ""
		for _, c := range candidates {
			if _, err := crypto.InspectEdgeReportedLeaf(c.der, block.Bytes); err == nil {
				issuer = c.id
				break
			}
		}
		if issuer == "" {
			out.Rejected++
			continue
		}
		if _, seen := groups[issuer]; !seen {
			order = append(order, issuer)
		}
		groups[issuer] = append(groups[issuer], certificatePEM)
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: "agent:" + host, Roles: []string{"agent"}})
	for _, id := range order {
		result, err := s.edgeDelegations.Reconcile(actorCtx, tenantID, id, api.EdgeReconcileRequest{Host: host, CertificatesPEM: groups[id]})
		if err != nil {
			return nil, err
		}
		out.Reconciled += result.Reconciled
		out.Already += result.Already
		out.Violations += result.Violations
		out.Rejected += result.Rejected
		out.Delegations = append(out.Delegations, id)
	}
	return out, nil
}

// RenewEdgeDelegation implements transport.AgentEdgeRenewalServer (A220): a
// host-role agent renews the delegation whose certificate it holds, for its own
// host only.
func (a *agentService) RenewEdgeDelegation(ctx context.Context, req *transport.EdgeRenewalRequest) (*transport.EdgeRenewalResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if !agentHasRole(info.Roles, mtls.AgentRoleHost) {
		return nil, status.Error(codes.PermissionDenied, "edge delegations renew from host agents")
	}
	if a.renewEdgeDelegation == nil {
		return nil, status.Error(codes.FailedPrecondition, errEdgeJournalNotServed.Error())
	}
	if _, err := a.store.GetAgent(ctx, info.TenantID, agentRowID(info.TenantID, info.CommonName)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.FailedPrecondition, "send an authenticated heartbeat before an edge renewal")
		}
		return nil, status.Error(codes.Unavailable, "agent registration state is unavailable; retry later")
	}
	if req == nil || strings.TrimSpace(req.Serial) == "" || len(req.CSRDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "an edge renewal needs the delegation serial and a CSR")
	}
	if len(req.CSRDER) > transport.EdgeJournalMaxCertificateBytes || len(req.AttestationCredentialJSON) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "an edge renewal request is too large")
	}
	out, err := a.renewEdgeDelegation(ctx, info.TenantID, info.CommonName, req)
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, api.ErrEdgeDelegationNotFound):
		return nil, status.Error(codes.NotFound, err.Error())
	case errors.Is(err, api.ErrEdgeDelegationInvalid):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, api.ErrEdgeDelegationRefused):
		return nil, status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, errEdgeRenewalTooEarly):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, errEdgeJournalNotServed):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	default:
		if a.logger != nil {
			a.logger.Warn("edge delegation renewal failed", "tenant_id", info.TenantID, "error", err)
		}
		return nil, status.Error(codes.Unavailable, "the edge delegation could not be renewed; retry later")
	}
}

// renewEdgeDelegation renews through the edge delegation service as the agent.
func (s *Server) renewEdgeDelegation(ctx context.Context, tenantID, host string, req *transport.EdgeRenewalRequest) (*transport.EdgeRenewalResponse, error) {
	if s.edgeDelegations == nil {
		return nil, errEdgeJournalNotServed
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: "agent:" + host, Roles: []string{"agent"}})
	renewed, err := s.edgeDelegations.RenewDelegation(actorCtx, tenantID, edgeRenewal{
		host: host, serial: req.Serial, csrDER: req.CSRDER, credentialJSON: req.AttestationCredentialJSON,
	})
	if err != nil {
		return nil, err
	}
	return &transport.EdgeRenewalResponse{DelegationID: renewed.ID, Serial: renewed.Serial,
		CertificatePEM: renewed.CertificatePEM, NotAfter: renewed.NotAfter}, nil
}
