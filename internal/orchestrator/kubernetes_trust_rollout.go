// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// KubernetesTrustRolloutEventID is the deterministic event id of one rollout
// operation, so a retried request appends nothing new (AN-5).
func KubernetesTrustRolloutEventID(tenantID, rolloutID, operation, idempotencyKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"kubernetes-trust-rollout\x00"+tenantID+"\x00"+rolloutID+"\x00"+operation+"\x00"+idempotencyKey)).String()
}

// StartKubernetesTrustRollout records a TrustBundle rollout to an ordered list
// of clusters (A138). The canary is dispatched with the event; each cluster is
// verified later by its own controller's posture report.
func (o *Orchestrator) StartKubernetesTrustRollout(ctx context.Context, tenantID string, in projections.KubernetesTrustRolloutStarted) error {
	if err := projections.ValidateKubernetesTrustRolloutStarted(in); err != nil {
		return err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID:   KubernetesTrustRolloutEventID(tenantID, in.RolloutID, "start", ""),
		Type: projections.EventKubernetesTrustRolloutStarted, TenantID: tenantID, Data: payload,
	})
	return err
}

// ControlKubernetesTrustRollout pauses (resume false) or resumes a rollout.
func (o *Orchestrator) ControlKubernetesTrustRollout(ctx context.Context, tenantID, rolloutID string, resume bool, idempotencyKey string) error {
	eventType, operation := projections.EventKubernetesTrustRolloutPaused, "pause"
	if resume {
		eventType, operation = projections.EventKubernetesTrustRolloutResumed, "resume"
	}
	payload, err := json.Marshal(projections.KubernetesTrustRolloutControlled{RolloutID: rolloutID})
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID:   KubernetesTrustRolloutEventID(tenantID, rolloutID, operation, idempotencyKey),
		Type: eventType, TenantID: tenantID, Data: payload,
	})
	return err
}
