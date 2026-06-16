package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// agentResponse is an in-network agent in the API's JSON shape.
type agentResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	Version    string  `json:"version,omitempty"`
	LastSeenAt *string `json:"last_seen_at,omitempty"`
}

// agentListResponse is the envelope for GET /api/v1/agents.
type agentListResponse struct {
	Agents []agentResponse `json:"agents"`
}

func toAgentResponse(a store.Agent) agentResponse {
	out := agentResponse{ID: a.ID, Name: a.Name, Status: a.Status, Version: a.Version}
	if a.LastSeenAt != nil {
		s := a.LastSeenAt.UTC().Format(time.RFC3339)
		out.LastSeenAt = &s
	}
	return out
}

// listAgents returns the tenant's in-network agents (F3). The web first-run
// wizard polls it to detect a freshly-installed agent's registration.
func (a *API) listAgents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	agents, err := a.store.ListAgents(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]agentResponse, 0, len(agents))
	for _, ag := range agents {
		items = append(items, toAgentResponse(ag))
	}
	a.writeJSON(w, http.StatusOK, agentListResponse{Agents: items})
}

// enrollmentTokenResponse carries a one-time agent bootstrap token and the path
// an agent presents it to when enrolling.
type enrollmentTokenResponse struct {
	Token     string `json:"token"`
	EnrollURL string `json:"enroll_path"`
}

// createEnrollmentToken mints a one-time agent bootstrap token (S5.1/F15) bound to
// the caller's tenant (WIRE-003/AN-1) so the web wizard can build the agent
// install command. The mint runs under an idempotency key (AN-5): a retried
// request returns the original token rather than minting a second one. The token
// is tenant-attributed, so the certificate the agent later receives carries this
// tenant. When no issuer is wired, the capability is reported unavailable.
//
//trstctl:mutation
func (a *API) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if a.agentTokens == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		token, err := a.agentTokens.IssueBootstrapToken(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, enrollmentTokenResponse{Token: token, EnrollURL: "/enroll/bootstrap"}, nil
	})
}
