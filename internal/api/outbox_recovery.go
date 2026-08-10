// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// outboxReconciliationConflictResponse deliberately contains command hashes,
// not command payloads. ELI5: operators can prove two envelopes differ without
// receiving a second copy of the executable instruction through a read API.
type outboxReconciliationConflictResponse struct {
	ID                         string    `json:"id"`
	TenantID                   string    `json:"tenant_id"`
	SourceEventID              string    `json:"source_event_id"`
	SourceEventSequence        uint64    `json:"source_event_sequence"`
	SourceEventType            string    `json:"source_event_type"`
	IdempotencyKey             string    `json:"idempotency_key"`
	ExistingOutboxID           int64     `json:"existing_outbox_id"`
	ExistingDestination        string    `json:"existing_destination"`
	ExistingEffectLane         string    `json:"existing_effect_lane"`
	ExistingPayloadSHA256      string    `json:"existing_payload_sha256"`
	ExistingRequiredAgentRole  string    `json:"existing_required_agent_role,omitempty"`
	ExistingRequiredAgentID    string    `json:"existing_required_agent_id,omitempty"`
	CandidateDestination       string    `json:"candidate_destination"`
	CandidateEffectLane        string    `json:"candidate_effect_lane"`
	CandidatePayloadSHA256     string    `json:"candidate_payload_sha256"`
	CandidateRequiredAgentRole string    `json:"candidate_required_agent_role,omitempty"`
	CandidateRequiredAgentID   string    `json:"candidate_required_agent_id,omitempty"`
	Reason                     string    `json:"reason"`
	Status                     string    `json:"status"`
	DetectedAt                 time.Time `json:"detected_at"`
}

type outboxReconciliationConflictListResponse struct {
	Items    []outboxReconciliationConflictResponse `json:"items"`
	Guidance string                                 `json:"guidance"`
}

func toOutboxReconciliationConflictResponse(c store.OutboxReconciliationConflict) outboxReconciliationConflictResponse {
	return outboxReconciliationConflictResponse{
		ID: c.ID, TenantID: c.TenantID, SourceEventID: c.SourceEventID,
		SourceEventSequence: c.SourceEventSequence, SourceEventType: c.SourceEventType,
		IdempotencyKey: c.IdempotencyKey, ExistingOutboxID: c.ExistingOutboxID,
		ExistingDestination: c.ExistingDestination, ExistingEffectLane: c.ExistingEffectLane,
		ExistingPayloadSHA256:     c.ExistingPayloadSHA256,
		ExistingRequiredAgentRole: c.ExistingRequiredAgentRole,
		ExistingRequiredAgentID:   c.ExistingRequiredAgentID,
		CandidateDestination:      c.CandidateDestination, CandidateEffectLane: c.CandidateEffectLane,
		CandidatePayloadSHA256:     c.CandidatePayloadSHA256,
		CandidateRequiredAgentRole: c.CandidateRequiredAgentRole,
		CandidateRequiredAgentID:   c.CandidateRequiredAgentID,
		Reason:                     c.Reason, Status: c.Status, DetectedAt: c.DetectedAt,
	}
}

func (a *API) listOutboxReconciliationConflicts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, "tenant identity required"))
		return
	}
	conflicts, err := a.store.ListOutboxReconciliationConflicts(r.Context(), tenantID, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]outboxReconciliationConflictResponse, 0, len(conflicts))
	for _, conflict := range conflicts {
		items = append(items, toOutboxReconciliationConflictResponse(conflict))
	}
	a.writeJSON(w, http.StatusOK, outboxReconciliationConflictListResponse{
		Items:    items,
		Guidance: "Keep the historical command bound to its original key. Fix the source identity or seed configuration, then issue the intended command with a new unique idempotency key; never rewrite the outbox row or replay the candidate under the old key.",
	})
}
