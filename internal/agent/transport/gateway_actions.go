// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/accessrules"
)

const methodEvaluateGatewayAction = "EvaluateGatewayAction"
const fullMethodEvaluateGatewayAction = "/" + agentServiceName + "/" + methodEvaluateGatewayAction

// EvaluateGatewayActionRequest contains no traffic or sign-in field. Tenant,
// session, target and requester are derived from the authenticated held job.
type EvaluateGatewayActionRequest struct {
	JobID          int64                   `json:"job_id"`
	Attempt        int                     `json:"attempt"`
	IdempotencyKey string                  `json:"idempotency_key"`
	Observation    accessrules.Observation `json:"observation"`
	Cancel         bool                    `json:"cancel,omitempty"`
}
type EvaluateGatewayActionResponse struct {
	Decision accessrules.Decision `json:"decision"`
}

// Kept separate from the old gateway interface so its pre-existing methods
// remain usable for ordinary sessions when this optional service is absent.
type AgentGatewayCommandServiceServer interface {
	EvaluateGatewayAction(context.Context, *EvaluateGatewayActionRequest) (*EvaluateGatewayActionResponse, error)
}

func evaluateGatewayActionHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(EvaluateGatewayActionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	service, ok := srv.(AgentGatewayCommandServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve gateway command rules")
	}
	if interceptor == nil {
		return service.EvaluateGatewayAction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodEvaluateGatewayAction}
	return interceptor(ctx, in, info, func(ctx context.Context, raw any) (any, error) {
		return service.EvaluateGatewayAction(ctx, raw.(*EvaluateGatewayActionRequest))
	})
}

func (c *AgentClient) EvaluateGatewayAction(ctx context.Context, req *EvaluateGatewayActionRequest) (*EvaluateGatewayActionResponse, error) {
	out := new(EvaluateGatewayActionResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodEvaluateGatewayAction, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}
