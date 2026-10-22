// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/store"
)

// requireTargetHostProfileUsable applies RequireHostAgentProfileUsable to a
// target routed to a host agent (B7). Targets with no host assignment, and
// assignments the store cannot resolve here, pass: the existing admission
// paths own those answers.
func (a *API) requireTargetHostProfileUsable(ctx context.Context, tenantID string, target store.DeploymentTarget, work string) error {
	agentID, err := connector.TargetHostAgentID(target.Config)
	if err != nil || agentID == "" {
		return nil
	}
	agent, err := a.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil
	}
	return RequireHostAgentProfileUsable(agent, work)
}
