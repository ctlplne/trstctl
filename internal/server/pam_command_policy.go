// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
)

// This report narrows availability only. Tenant, target authority and the exact
// gateway demand still come from authenticated configuration and the held job.
func (s *pamService) requireCommandRuleGateway(ctx context.Context, tenantID string, req api.PAMSessionRequest) error {
	if err := accessrules.ValidatePolicy(req.ResolvedCommandPolicy, req.TargetType); err != nil {
		return fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
	}
	kind := accessgateway.KindForPolicy(req.ResolvedCommandPolicy)
	if !s.commandRuleJobKinds[kind] {
		return fmt.Errorf("%w: enable %s in agent_channel.claimable_job_kinds before opening a rule-bearing session", api.ErrPAMInvalid, kind)
	}
	target, err := s.getPAMTarget(ctx, tenantID, req.TargetType, req.TargetID)
	if err != nil {
		return err
	}
	if target.GatewayAgentID == "" {
		return fmt.Errorf("%w: command rules require a gateway-bound target", api.ErrPAMInvalid)
	}
	agent, err := s.store.GetAgent(ctx, tenantID, target.GatewayAgentID)
	if err != nil {
		return err
	}
	var report transport.ExecutorReport
	if agent.ExecutorsReportedAt == nil || json.Unmarshal(agent.Executors, &report) != nil || report.PendingReportError != "" {
		return fmt.Errorf("%w: the named gateway has not reported a usable command-rule executor; upgrade it and wait for its heartbeat", api.ErrPAMInvalid)
	}
	requiredKind := kind
	for _, kind := range report.Kinds {
		if kind.Kind == requiredKind && len(kind.MissingFlags) == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: the named gateway cannot enforce command rules; upgrade it and enable its access-gateway listener", api.ErrPAMInvalid)
}
