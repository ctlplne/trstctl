package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
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
	Agents     []agentResponse `json:"agents"`
	NextCursor string          `json:"next_cursor,omitempty"`
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
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	afterID := store.ZeroUUID
	var afterCreatedAt *time.Time
	if c := r.URL.Query().Get("cursor"); c != "" {
		ts, id, perr := decodeAgentCursor(c)
		if perr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		afterCreatedAt = ts
		afterID = id
	}
	agents, err := a.store.ListAgentsPage(r.Context(), tenantID, afterCreatedAt, afterID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]agentResponse, 0, len(agents))
	for _, ag := range agents {
		items = append(items, toAgentResponse(ag))
	}
	next := ""
	if len(agents) == limit {
		next = encodeAgentCursor(agents[len(agents)-1])
	}
	a.writeJSON(w, http.StatusOK, agentListResponse{Agents: items, NextCursor: next})
}

const agentCursorSep = "|"

func encodeAgentCursor(a store.Agent) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a.CreatedAt.UTC().Format(time.RFC3339Nano) + agentCursorSep + a.ID))
}

func decodeAgentCursor(c string) (*time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, "", err
	}
	tsStr, id, found := strings.Cut(string(b), agentCursorSep)
	if !found || len(id) != 36 {
		return nil, "", errors.New("cursor is not a valid agent cursor")
	}
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return nil, "", errors.New("cursor created_at is not a valid timestamp")
	}
	return &ts, id, nil
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
