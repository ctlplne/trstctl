// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ErrAgentRolesInvalid is a role grant naming no known role or an unknown one.
var ErrAgentRolesInvalid = errors.New("orchestrator: agent role grant is invalid")

// ErrAgentOffboarded is a change to an agent that was offboarded.
var ErrAgentOffboarded = errors.New("orchestrator: agent is offboarded")

// GrantAgentRoles records the complete role set an agent's next certificate
// carries (A191) as agent.roles.granted. It grants nothing by itself: the
// served renewal signs the roles into the certificate's SANs, so the agent
// gains or loses a capability only through a certificate the agent CA signed.
// A later grant replaces one no renewal has signed yet.
func (o *Orchestrator) GrantAgentRoles(ctx context.Context, tenantID, agentID string, roles []string, reason string) (store.AgentRoleGrant, error) {
	agentID = strings.TrimSpace(agentID)
	reason = strings.TrimSpace(reason)
	for _, role := range roles {
		if !mtls.ValidAgentRole(role) {
			return store.AgentRoleGrant{}, fmt.Errorf("%w: unknown role %q; expected %q or %q",
				ErrAgentRolesInvalid, role, mtls.AgentRoleHost, mtls.AgentRoleNetwork)
		}
	}
	granted := mtls.NormalizeAgentRoles(roles)
	if len(granted) == 0 {
		return store.AgentRoleGrant{}, fmt.Errorf("%w: name at least one role", ErrAgentRolesInvalid)
	}
	existing, err := o.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return store.AgentRoleGrant{}, err
	}
	if existing.Status == "offboarded" {
		return store.AgentRoleGrant{}, fmt.Errorf("%w: %s cannot renew, so it cannot take new roles; enroll a new agent instead", ErrAgentOffboarded, existing.Name)
	}
	grantedBy := ""
	if actor, ok := events.ActorFromContext(ctx); ok {
		grantedBy = actor.Subject
	}
	payload, err := json.Marshal(projections.AgentRolesGranted{
		ID: agentID, Agent: existing.Name, Roles: granted, Reason: reason, GrantedBy: grantedBy,
	})
	if err != nil {
		return store.AgentRoleGrant{}, err
	}
	if _, err := o.emit(ctx, projections.EventAgentRolesGranted, tenantID, payload); err != nil {
		return store.AgentRoleGrant{}, err
	}
	grant, found, err := o.store.AgentRoleGrant(ctx, tenantID, agentID)
	if err == nil && !found {
		err = errors.New("orchestrator: the recorded agent role grant did not project")
	}
	return grant, err
}
