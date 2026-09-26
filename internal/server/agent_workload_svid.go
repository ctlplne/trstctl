// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/protocols/spiffe"
)

// Issuing SVIDs for workloads a host agent attested (epic B3).
//
// This is the node API. The Workload API itself now runs on the host — that is
// the point of the epic — and this is the one call it makes upward: the agent
// inspected a calling process, reports what it saw, and the control plane
// decides which identities that observation unlocks.
//
// The security question is the same one B2 answered for renewals, in a sharper
// form. Selectors are a CLAIM: an agent says "the process that connected to my
// socket runs as uid 1000 from /usr/bin/api". Nothing the control plane can see
// verifies that, and nothing could — the observation happened on another
// machine. So the control plane does not try to verify the claim; it bounds what
// the claim can unlock. Registration entries carry a ParentID naming the node
// permitted to deliver them, the node is taken from the certificate the agent
// authenticated with, and an agent that lies about selectors reaches only the
// workloads on its own host. Which it could reach anyway, by reading their
// memory. An unscoped entry is reachable by no agent at all.

// FetchWorkloadSVID issues SVIDs for a workload this agent attested locally.
func (a *agentService) FetchWorkloadSVID(ctx context.Context, req *transport.FetchWorkloadSVIDRequest) (*transport.FetchWorkloadSVIDResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if a.issueWorkloadSVID == nil {
		// Fails closed, like the other agent-facing issuance seams: a control
		// plane with no workload-identity surface must say so rather than
		// appear to serve one and strand every workload that dials the socket.
		return nil, status.Error(codes.FailedPrecondition,
			"this control plane does not serve workload identity")
	}
	if req == nil || len(req.PublicKeyDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "public_key_der is required")
	}
	if len(req.Selectors) == 0 {
		// No observation means no claim, and a claim of nothing must not match
		// an entry that requires nothing — entries with no selectors are
		// already unreachable by construction, and this keeps the request side
		// honest about it too.
		return nil, status.Error(codes.InvalidArgument,
			"selectors are required: an agent must say what it observed about the calling workload")
	}

	// The node is the agent's OWN authenticated identity, from the certificate
	// it presented on this channel. Never from the request: a node field an
	// agent could set would let it deliver another host's workloads, which is
	// the entire escalation the ParentID scoping exists to prevent.
	// mtls.AgentSPIFFEID is the same value stamped into the certificate this
	// connection presented, so the node an entry is scoped to and the node the
	// caller can prove it is are literally the same string.
	nodeID := mtls.AgentSPIFFEID(info.TenantID, info.CommonName)

	resp, err := a.issueWorkloadSVID(ctx, info.TenantID, nodeID, req)
	if err != nil {
		return nil, err
	}
	a.recordAgentJobEvent(ctx, info.TenantID, "spiffe.workload.svid_issued_via_agent", map[string]any{
		"agent": info.CommonName, "node": nodeID,
		"selectors": req.Selectors, "x509": len(resp.X509SVIDs), "jwt": len(resp.JWTSVIDs),
	})
	return resp, nil
}

// FetchWorkloadSVID on the bulkhead wrapper dispatches into the agent pool.
//
// AN-7: workload SVID fetches are the highest-frequency agent-facing call this
// channel will ever carry — every workload on every host, re-fetching ahead of
// expiry — so it is exactly the traffic a bulkhead exists to keep from starving
// the rest of the control plane.
func (b *bulkheadedAgentService) FetchWorkloadSVID(ctx context.Context, req *transport.FetchWorkloadSVIDRequest) (*transport.FetchWorkloadSVIDResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "fetch_workload_svid", b.metrics, func(ctx context.Context) (*transport.FetchWorkloadSVIDResponse, error) {
		return b.next.FetchWorkloadSVID(ctx, req)
	})
}

// issueWorkloadSVID is the Server-level seam the agent channel is wired to.
//
// It routes through the SAME spiffe.Server the control plane's own socket uses,
// so a workload receives the identical identity whichever socket it reached —
// the control plane's during the deprecation window, or its own host's after.
// A second issuance path here would be a second place for the trust domain, the
// TTLs and the audit trail to drift, and the drift would be invisible because
// both paths would issue.
func (s *Server) issueWorkloadSVID(
	ctx context.Context,
	tenantID, nodeID string,
	req *transport.FetchWorkloadSVIDRequest,
) (*transport.FetchWorkloadSVIDResponse, error) {
	if s.protocols == nil || s.protocols.spiffe == nil || s.protocols.spiffe.wl == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"this control plane has no SPIFFE trust domain configured")
	}
	wl := s.protocols.spiffe.wl
	out := &transport.FetchWorkloadSVIDResponse{}

	if len(req.Audience) > 0 {
		jwts, err := wl.FetchJWTSVIDsForNode(ctx, nodeID, req.Audience, req.Selectors)
		if err != nil {
			return nil, workloadSVIDError(err)
		}
		for _, svid := range jwts {
			out.JWTSVIDs = append(out.JWTSVIDs, transport.WorkloadJWTSVID{
				SPIFFEID: svid.SPIFFEID, Token: svid.Token,
				ExpiresAtUnix: svid.ExpiresAt.Unix(),
			})
		}
		return out, nil
	}

	svids, err := wl.FetchX509SVIDsForNode(ctx, nodeID, req.PublicKeyDER, req.Selectors)
	if err != nil {
		return nil, workloadSVIDError(err)
	}
	for _, svid := range svids {
		out.X509SVIDs = append(out.X509SVIDs, transport.WorkloadX509SVID{
			SPIFFEID: svid.SPIFFEID, CertChainDER: svid.CertChain,
			ExpiresAtUnix: svid.ExpiresAt.Unix(),
		})
		if len(out.Bundle) == 0 {
			out.Bundle = svid.Bundle
		}
	}
	return out, nil
}

// workloadSVIDError maps an issuance failure to a status an agent can act on.
//
// "No identity" is PermissionDenied rather than NotFound, and the message says
// why in the terms an operator can fix: the usual cause is not a missing entry
// but an entry that exists and has not been scoped to this node, which reads as
// "my registration is right there and the workload still cannot get an SVID".
func workloadSVIDError(err error) error {
	if errors.Is(err, spiffe.ErrNoIdentity) {
		return status.Error(codes.PermissionDenied,
			"no registration entry is both matched by these selectors and scoped to this node; "+
				"an entry reachable from a host agent must name that agent in its ParentID, and "+
				"an entry with no ParentID is served only on the control plane's own socket")
	}
	return status.Errorf(codes.Internal, "issue workload svid: %v", err)
}

// Workload API heartbeat counter keys, mirrored from the agent (epic B3).
const (
	workloadAPIServedKey = "workload_api_served"
	workloadAPIIssuedKey = "workload_api_svids_issued"
)

// workloadAPIPosture reads a heartbeat's Workload API counters.
//
// The third return value is what makes this honest: reported=false means the
// agent said NOTHING about the Workload API, which is what an agent predating
// this epic does. That is a different fact from "this agent reported that it is
// not serving", and the console shows them differently — one is a version gap
// an operator fixes by upgrading, the other is a configuration choice.
func workloadAPIPosture(inv map[string]int64) (served bool, svids int64, reported bool) {
	if len(inv) == 0 {
		return false, 0, false
	}
	raw, ok := inv[workloadAPIServedKey]
	if !ok {
		return false, 0, false
	}
	return raw != 0, inv[workloadAPIIssuedKey], true
}
