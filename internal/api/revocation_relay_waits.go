// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

// RevocationRelayWait is one revocation trstctl handed to an AD CS issuer's
// relay that the relay has not finished (A162-L5). The revocation's delivery
// waits for the relay without spending its retry budget, so a relay that
// never connects would otherwise leave the certificate active with no reason
// shown anywhere.
type RevocationRelayWait struct {
	RevocationID string `json:"revocation_id"`
	// Serial is the certificate serial the relay revokes: lower-case hex, no separators.
	Serial     string `json:"serial"`
	CAConfig   string `json:"ca_config"`
	IssuerID   string `json:"issuer_id,omitempty"`
	IssuerName string `json:"issuer_name,omitempty"`
	// Relay is the relay's enrolled name; RelayAgentID the exact agent the
	// attempt is pinned to.
	Relay        string `json:"relay"`
	RelayAgentID string `json:"relay_agent_id"`
	// RelayPresence is never_seen when no agent has ever reported under that
	// name, else the agent's presence: online, stale, unreported, offboarded
	// or clock_skew.
	RelayPresence   string `json:"relay_presence"`
	RelayLastSeenAt string `json:"relay_last_seen_at,omitempty"`
	// State is waiting_for_relay until the relay takes the attempt, then
	// relay_working while it holds it.
	State string `json:"state"`
	// Attempt counts this attempt: one more than the relay's failed ones.
	Attempt   int    `json:"attempt"`
	LastError string `json:"last_error,omitempty"`
	QueuedAt  string `json:"queued_at"`
	// AttemptQueuedAt is when the current attempt was queued.
	AttemptQueuedAt string `json:"attempt_queued_at"`
}

// RevocationRelayWaits lists revocations waiting on their issuer's relay.
type RevocationRelayWaits struct {
	Items    []RevocationRelayWait `json:"items"`
	Guidance string                `json:"guidance"`
}

const (
	revocationRelayNeverSeen    = "never_seen"
	revocationRelayWaiting      = "waiting_for_relay"
	revocationRelayWorking      = "relay_working"
	revocationRelayWaitsLimit   = 100
	revocationRelayWaitGuidance = "An AD CS issuer revokes through its domain-joined relay: the certificate stays active, " +
		"and the revocation waits without spending its retries, until that exact relay connects, runs certutil and " +
		"reports the CA's answer. A relay that has never connected, or is not online, holds every revocation listed here; " +
		"enroll and start it, or bring it back online, and each one completes on its own."
)

func (a *API) listRevocationRelayWaits(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "revocation relay waits are not configured"))
		return
	}
	ctx := r.Context()
	rows, err := a.store.ListADCSRelayRevocationWaits(ctx, tenantID, revocationRelayWaitsLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	routes, err := a.revocationRelayRoutes(ctx, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	agents := map[string]*store.Agent{}
	out := RevocationRelayWaits{Items: make([]RevocationRelayWait, 0, len(rows)), Guidance: revocationRelayWaitGuidance}
	for _, row := range rows {
		item := RevocationRelayWait{
			RevocationID: row.RevocationID, Serial: row.Serial, CAConfig: row.CAConfig, RelayAgentID: row.AgentID,
			State: revocationRelayWaiting, Attempt: row.Attempt, LastError: row.LastError,
			QueuedAt: row.FirstQueuedAt.UTC().Format(time.RFC3339), AttemptQueuedAt: row.AttemptQueuedAt.UTC().Format(time.RFC3339),
		}
		if row.Held {
			item.State = revocationRelayWorking
		}
		if route, ok := routes[row.AgentID+"\x00"+row.CAConfig]; ok {
			item.Relay, item.IssuerID, item.IssuerName = route.relay, route.issuerID, route.issuerName
		}
		agent, cached := agents[row.AgentID]
		if !cached {
			found, err := a.store.GetAgent(ctx, tenantID, row.AgentID)
			switch {
			case store.IsNotFound(err):
			case err != nil:
				a.writeError(w, err)
				return
			default:
				agent = &found
			}
			agents[row.AgentID] = agent
		}
		if agent == nil {
			item.RelayPresence = revocationRelayNeverSeen
		} else {
			if item.Relay == "" {
				item.Relay = agent.Name
			}
			item.RelayPresence = agentPresenceFor(*agent, now, a.agentHeartbeatInterval).State
			if agent.LastSeenAt != nil {
				item.RelayLastSeenAt = agent.LastSeenAt.UTC().Format(time.RFC3339)
			}
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}

type revocationRelayRoute struct {
	relay, issuerID, issuerName string
}

// revocationRelayRoutes names each configured AD CS revocation relay by the
// exact agent id its attempts are pinned to, so a relay that has never
// connected is still named.
func (a *API) revocationRelayRoutes(ctx context.Context, tenantID string) (map[string]revocationRelayRoute, error) {
	routes := map[string]revocationRelayRoute{}
	if a.externalCAs == nil {
		return routes, nil
	}
	cas, err := a.externalCAs.ListExternalCAs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, authority := range cas {
		if authority.RevocationRelay == "" {
			continue
		}
		agentID := sshtrustrollout.EnrolledAgentID(tenantID, authority.RevocationRelay)
		routes[agentID+"\x00"+authority.RevocationCAConfig] = revocationRelayRoute{
			relay: authority.RevocationRelay, issuerID: authority.ID, issuerName: authority.Name,
		}
	}
	return routes, nil
}
