// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

// The agent job ledger's operations surface (epic A1).
//
// Once work is executed by agents rather than by the control plane, "is the
// fabric moving?" becomes an operational question with no other way to answer it.
// A queue that has stopped draining looks exactly like a quiet estate until
// something expires.
//
// This is shaped like the bulkhead surface it sits beside: process-wide counters
// and one age, never tenant identifiers, payloads or credentials. An operator has
// to be able to see the fabric is healthy without being handed anyone's data to
// see it.

// AgentJobQueue is per-kind claim health.
type AgentJobQueue struct {
	// Kind is the job kind (the outbox destination).
	Kind string `json:"kind"`
	// Enabled reports whether an operator has made this kind claimable. A kind
	// that is served but not enabled shows zero because nothing is handed out,
	// which is a different thing from a queue that has drained.
	Enabled bool `json:"enabled"`
	// Pending is work waiting for an agent to take it.
	Pending int `json:"pending"`
	// Claimed is work an agent holds right now.
	Claimed int `json:"claimed"`
	// OldestUnclaimedSeconds is how long the oldest waiting job has waited. This
	// is the number that says a fabric has stalled: depth alone cannot
	// distinguish a busy queue from a stuck one.
	OldestUnclaimedSeconds int `json:"oldest_unclaimed_seconds,omitempty"`
}

// AgentJobPosture is the served job-ledger health view.
type AgentJobPosture struct {
	// Served reports whether the agent channel is mounted at all. Without it the
	// queues below are meaningless rather than empty.
	Served bool `json:"served"`
	// ClaimableKinds are the kinds an operator has enabled. Empty means the
	// ledger is served and hands nothing out — the honest default until an
	// agent-side executor for a kind exists.
	ClaimableKinds []string        `json:"claimable_kinds"`
	GeneratedAt    time.Time       `json:"generated_at"`
	Queues         []AgentJobQueue `json:"queues"`
	// Redemptions is credential-custody health (epic A3): how many redeemed
	// credentials are held by relays right now, how many have ever been handed
	// out, and how long the oldest live one has been held. Counts and one age,
	// never a tenant, agent, reference name or value.
	Redemptions AgentJobRedemptions `json:"redemptions"`
}

// AgentJobRedemptions is the served credential-custody view.
type AgentJobRedemptions struct {
	// Live credentials are held by some relay right now. Each one is material
	// outside the seal, so this is the number an operator watches.
	Live int `json:"live"`
	// Total is every redemption ever recorded.
	Total int `json:"total"`
	// OldestLiveSeconds is how long the oldest live redemption has been held. A
	// value past the maximum claim lease means a relay is holding material for a
	// claim that should have lapsed — the shape of a stuck attempt.
	OldestLiveSeconds int `json:"oldest_live_seconds,omitempty"`
}

// AgentJobPostureProvider reads live job-ledger health. It is evaluated at request
// time because API construction precedes agent-channel construction, and because
// the counters are only useful fresh.
type AgentJobPostureProvider func(ctx context.Context) (AgentJobPosture, error)

// WithAgentJobPosture wires the assembled job ledger into the always-registered
// operations route.
func WithAgentJobPosture(provider AgentJobPostureProvider) Option {
	return func(c *config) { c.agentJobPosture = provider }
}

func (a *API) getAgentJobPosture(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.agentJobPosture == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent job ledger is not assembled"))
		return
	}
	posture, err := a.agentJobPosture(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	if posture.Queues == nil {
		posture.Queues = []AgentJobQueue{}
	}
	if posture.ClaimableKinds == nil {
		posture.ClaimableKinds = []string{}
	}
	if posture.GeneratedAt.IsZero() {
		posture.GeneratedAt = time.Now().UTC()
	}
	a.writeJSON(w, http.StatusOK, posture)
}
