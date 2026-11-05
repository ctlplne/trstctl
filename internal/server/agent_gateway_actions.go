// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func (a *agentService) EvaluateGatewayAction(ctx context.Context, req *transport.EvaluateGatewayActionRequest) (*transport.EvaluateGatewayActionResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if a.store == nil || a.evaluatePAMCommand == nil {
		return nil, status.Error(codes.FailedPrecondition, "gateway command rules are not served")
	}
	if !agentHasRole(info.Roles, mtls.AgentRoleGateway) {
		return nil, status.Error(codes.PermissionDenied, "command decisions require a gateway-role agent")
	}
	if req == nil || req.JobID < 1 || req.Attempt < 1 || req.IdempotencyKey == "" {
		return nil, status.Error(codes.InvalidArgument, "a held job, attempt and action idempotency key are required")
	}
	if accessrules.ValidateObservation(req.Observation) != nil {
		return nil, status.Error(codes.InvalidArgument, "the public action metadata is invalid or exceeds its bounds")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	job, held, err := a.store.GetAgentJobForRedemption(ctx, info.TenantID, agentID, req.JobID, time.Now().UTC())
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not load the held session job; retry the same action")
	}
	if !held || job.ClaimAttempts != req.Attempt || job.RequiredAgentID != agentID || !relay.IsCommandRulesSession(job.Destination) {
		return nil, status.Error(codes.PermissionDenied, "this agent does not hold that policy-bearing session at that attempt")
	}
	decision, err := a.evaluatePAMCommand(ctx, info.TenantID, agentID, job.Payload, req.JobID, req.Attempt, req.IdempotencyKey, req.Observation, req.Cancel)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrDatastoreBusy):
			return nil, status.Error(codes.ResourceExhausted, "the command-decision pool is busy; retry the same action")
		case errors.Is(err, orchestrator.ErrIdempotencyConflict):
			return nil, status.Error(codes.AlreadyExists, "the action identity already belongs to different metadata")
		case errors.Is(err, api.ErrPAMRejected):
			return nil, status.Error(codes.PermissionDenied, "the session is no longer active on this gateway")
		case errors.Is(err, api.ErrPAMInvalid):
			return nil, status.Error(codes.InvalidArgument, "the action does not match its frozen session policy")
		default:
			return nil, status.Error(codes.Unavailable, "could not durably record the command decision; the held action must remain refused")
		}
	}
	return &transport.EvaluateGatewayActionResponse{Decision: decision}, nil
}

func (b *bulkheadedAgentService) EvaluateGatewayAction(ctx context.Context, req *transport.EvaluateGatewayActionRequest) (*transport.EvaluateGatewayActionResponse, error) {
	next, ok := b.next.(transport.AgentGatewayCommandServiceServer)
	if !ok || b.commandPool == nil {
		return nil, status.Error(codes.FailedPrecondition, "the gateway command bulkhead is not configured")
	}
	return runAgentBulkhead(ctx, b.commandPool, "evaluate_gateway_action", b.metrics, func(ctx context.Context) (*transport.EvaluateGatewayActionResponse, error) {
		return next.EvaluateGatewayAction(ctx, req)
	})
}
