// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
)

func (s *pamService) requireDesktopGateway(ctx context.Context, tenantID, targetID string) error {
	if s.recordings == nil {
		return fmt.Errorf("%w: desktop sessions need encrypted recording storage and audit signing", api.ErrPAMInvalid)
	}
	if !s.desktopJobEnabled {
		return fmt.Errorf("%w: enable %s in agent_channel.claimable_job_kinds", api.ErrPAMInvalid, accessgateway.KindSessionDesktop)
	}
	target, err := s.getPAMTarget(ctx, tenantID, pamTargetRDP, targetID)
	if err != nil {
		return err
	}
	agent, err := s.store.GetAgent(ctx, tenantID, target.GatewayAgentID)
	if err != nil {
		return err
	}
	var report transport.ExecutorReport
	if agent.ExecutorsReportedAt == nil || json.Unmarshal(agent.Executors, &report) != nil || report.PendingReportError != "" {
		return fmt.Errorf("%w: wait for the named gateway's native desktop executor heartbeat", api.ErrPAMInvalid)
	}
	for _, kind := range report.Kinds {
		if kind.Kind == accessgateway.KindSessionDesktop && len(kind.MissingFlags) == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: the named gateway needs the native desktop helper and access listener", api.ErrPAMInvalid)
}
