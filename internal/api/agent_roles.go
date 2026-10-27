// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A191: operator-granted agent roles. An agent's roles live in signed SANs on
// its certificate; an operator changes them by recording a grant that the
// agent's next renewal signs, with no re-enrollment.

type agentRoleGrantRequest struct {
	Roles  []string `json:"roles"`
	Reason string   `json:"reason,omitempty"`
}

// agentRoleGrantStatus is an agent's newest operator role grant and whether a
// renewal has signed it into a certificate yet.
type agentRoleGrantStatus struct {
	Roles         []string `json:"roles"`
	State         string   `json:"state"`
	GrantedAt     string   `json:"granted_at"`
	EventID       string   `json:"event_id"`
	AppliedSerial string   `json:"applied_serial,omitempty"`
	AppliedAt     *string  `json:"applied_at,omitempty"`
	Detail        string   `json:"detail"`
}

const (
	agentRoleGrantPending = "pending"
	agentRoleGrantApplied = "applied"
)

func agentRoleGrantStatusFor(g store.AgentRoleGrant) *agentRoleGrantStatus {
	out := &agentRoleGrantStatus{
		Roles: g.Roles, GrantedAt: g.GrantedAt.UTC().Format(time.RFC3339Nano), EventID: g.EventID,
	}
	if g.Pending() {
		out.State = agentRoleGrantPending
		out.Detail = "The agent's next certificate renewal signs these roles. A current agent renews at its next heartbeat and reconnects with the new certificate; an older agent renews on its schedule. Until then the agent keeps the roles its current certificate carries."
		return out
	}
	out.State = agentRoleGrantApplied
	out.AppliedSerial = g.AppliedSerial
	if g.AppliedAt != nil {
		at := g.AppliedAt.UTC().Format(time.RFC3339Nano)
		out.AppliedAt = &at
	}
	out.Detail = "Signed into the agent certificate with serial " + g.AppliedSerial + ". The roles take effect when the agent reconnects with that certificate, which a current agent does right after renewing."
	return out
}

// attachRoleGrants fills each agent's newest operator role grant.
func (a *API) attachRoleGrants(ctx context.Context, tenantID string, items []agentResponse) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	grants, err := a.store.AgentRoleGrants(ctx, tenantID, ids)
	if err != nil {
		return err
	}
	for i := range items {
		if grant, ok := grants[items[i].ID]; ok {
			items[i].RoleGrant = agentRoleGrantStatusFor(grant)
		}
	}
	return nil
}

// grantAgentRoles records the complete role set an agent's next certificate
// carries. The route is gated on agents:relay.grant: an agent's roles decide
// whether it may hold appliance credentials, so changing them is the same
// decision as minting a relay enrollment token.
//
//trstctl:mutation
func (a *API) grantAgentRoles(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimSpace(r.PathValue("id"))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "agent role grants are not configured")
		}
		if _, err := googleuuid.Parse(agentID); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "agent id must be a UUID")
		}
		var req agentRoleGrantRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		grant, err := a.orch.GrantAgentRoles(ctx, tenantID, agentID, req.Roles, req.Reason)
		switch {
		case errors.Is(err, orchestrator.ErrAgentRolesInvalid):
			return 0, nil, errStatus(http.StatusBadRequest, strings.TrimPrefix(err.Error(), "orchestrator: "))
		case errors.Is(err, orchestrator.ErrAgentOffboarded):
			return 0, nil, errStatus(http.StatusConflict, strings.TrimPrefix(err.Error(), "orchestrator: "))
		case err != nil:
			return 0, nil, err
		}
		agent, err := a.store.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			return 0, nil, err
		}
		out := a.agentResponse(agent)
		out.RoleGrant = agentRoleGrantStatusFor(grant)
		return http.StatusOK, out, nil
	})
}
