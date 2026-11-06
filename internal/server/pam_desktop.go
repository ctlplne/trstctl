// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"trstctl.com/trstctl/internal/accessdesktop"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
)

func (s *pamService) requireDesktopGateway(ctx context.Context, tenantID, targetID string) error {
	if s.recordings == nil {
		return fmt.Errorf("%w: desktop sessions need encrypted recording storage and audit signing", api.ErrPAMInvalid)
	}
	target, err := s.getPAMTarget(ctx, tenantID, pamTargetRDP, targetID)
	if err != nil {
		return err
	}
	jobKind := accessgateway.KindSessionDesktop
	found := false
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != target.ProviderID {
			continue
		}
		source, ok := provider.(interface {
			DynamicSecretGatewayDesktop(string) (accessdesktop.Binding, error)
		})
		if !ok {
			break
		}
		binding, e := source.DynamicSecretGatewayDesktop(target.AccountSecret)
		if e != nil {
			return fmt.Errorf("%w: reviewed desktop identity unavailable", api.ErrPAMInvalid)
		}
		if binding.AccountKind == "active_directory" {
			jobKind = accessgateway.KindSessionADDesktop
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("%w: reviewed desktop provider unavailable", api.ErrPAMInvalid)
	}
	enabled := s.desktopJobEnabled
	if jobKind == accessgateway.KindSessionADDesktop {
		enabled = s.adDesktopJobEnabled
	}
	if !enabled {
		return fmt.Errorf("%w: enable %s in agent_channel.claimable_job_kinds", api.ErrPAMInvalid, jobKind)
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
		if kind.Kind == jobKind && len(kind.MissingFlags) == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: the named gateway needs the native desktop helper and access listener", api.ErrPAMInvalid)
}
