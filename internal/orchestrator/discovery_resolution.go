// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Resolution workflows for posture findings (A106). A finding under
// investigation names an assignee and a due date; a remediated finding the
// evidence of its fix; an accepted risk the time its acceptance expires, when
// the leader's sweep reopens it.

// RiskAcceptanceExpiryActor is the actor that reopens an expired acceptance.
const RiskAcceptanceExpiryActor = "system:risk-acceptance-expiry"

var riskAcceptanceExpiryNamespace = uuid.MustParse("4f0c2a8e-6a51-5b4e-9d1c-a106e0b1c0de")

// DiscoveryFindingResolution is one resolution: the triage status a finding
// moves to and the resolution fields that status carries.
type DiscoveryFindingResolution struct {
	Status            discovery.TriageStatus
	Reason            string
	Assignee          string
	DueAt             *time.Time
	EvidenceRef       string
	RiskAcceptedUntil *time.Time
}

// ResolveDiscoveryFinding records a resolution as one triage change. Staying
// under investigation or accepted risk with other resolution fields is an
// update (a reassignment, a new due date, a renewed acceptance); the same
// resolution again changes nothing.
func (o *Orchestrator) ResolveDiscoveryFinding(ctx context.Context, tenantID, findingID string, res DiscoveryFindingResolution) (store.DiscoveryFinding, error) {
	current, err := o.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	from := discovery.TriageStatus(current.TriageStatus)
	if from == "" {
		from = discovery.TriageUnmanaged
	}
	if err := discovery.ValidateTriageTransition(from, res.Status); err != nil {
		return store.DiscoveryFinding{}, err
	}
	if from == res.Status && current.TriageAssignee == res.Assignee && sameInstant(current.TriageDueAt, res.DueAt) &&
		current.TriageEvidenceRef == res.EvidenceRef && sameInstant(current.RiskAcceptedUntil, res.RiskAcceptedUntil) {
		return current, nil
	}
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	payload, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
		ID: findingID, Status: string(res.Status), ManagedIdentityID: current.ManagedIdentityID,
		Actor: actor, Reason: strings.TrimSpace(res.Reason),
		Assignee: res.Assignee, DueAt: utcInstant(res.DueAt), EvidenceRef: res.EvidenceRef, RiskAcceptedUntil: utcInstant(res.RiskAcceptedUntil),
	})
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	if _, err := o.emit(ctx, projections.EventDiscoveryFindingTriageChanged, tenantID, payload); err != nil {
		return store.DiscoveryFinding{}, err
	}
	return o.store.GetDiscoveryFinding(ctx, tenantID, findingID)
}

// ExpireRiskAcceptances reopens a tenant's accepted risks whose acceptance
// expired at or before now, a bounded batch per call. Each reopening is one
// triage change by RiskAcceptanceExpiryActor whose event ID names the finding
// and the acceptance it ends, so two sweeps converge on one event.
func (o *Orchestrator) ExpireRiskAcceptances(ctx context.Context, tenantID string, now time.Time) (int, error) {
	expired, err := o.store.ExpiredRiskAcceptances(ctx, tenantID, now, store.MaxRiskAcceptanceExpiriesPerSweep)
	if err != nil {
		return 0, err
	}
	reopened := 0
	for _, f := range expired {
		until := f.RiskAcceptedUntil.UTC()
		payload, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
			ID: f.ID, Status: string(discovery.TriageUnmanaged), ManagedIdentityID: f.ManagedIdentityID,
			Actor: RiskAcceptanceExpiryActor, Reason: "risk acceptance expired at " + until.Format(time.RFC3339),
		})
		if err != nil {
			return reopened, err
		}
		id := uuid.NewSHA1(riskAcceptanceExpiryNamespace, []byte(tenantID+"\x00"+f.ID+"\x00"+until.Format(time.RFC3339Nano))).String()
		if _, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventDiscoveryFindingTriageChanged, TenantID: tenantID, Data: payload}); err != nil {
			return reopened, err
		}
		reopened++
	}
	return reopened, nil
}

func sameInstant(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func utcInstant(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
