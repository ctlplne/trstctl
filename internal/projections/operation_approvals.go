// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventApprovalRequested        = "approval.requested"
	EventApprovalDecisionRecorded = "approval.decision.recorded"
	EventApprovalStatusChanged    = "approval.request.status_changed"
)

// ApprovalRequested is the complete immutable operation intent. The digest is
// computed over these fields before append; the projection never fills missing
// context from mutable inventory.
type ApprovalRequested struct {
	ID                string    `json:"id"`
	IntentDigest      string    `json:"intent_digest"`
	ResourceKind      string    `json:"resource_kind"`
	ResourceID        string    `json:"resource_id"`
	ResourceName      string    `json:"resource_name,omitempty"`
	Action            string    `json:"action"`
	Requester         string    `json:"requester"`
	FromState         string    `json:"from_state,omitempty"`
	ToState           string    `json:"to_state,omitempty"`
	TargetVersion     uint64    `json:"target_version"`
	Reason            string    `json:"reason,omitempty"`
	EvidenceRefs      []string  `json:"evidence_refs"`
	RequiredApprovals int       `json:"required_approvals"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type ApprovalDecisionRecorded struct {
	RequestID    string    `json:"request_id"`
	IntentDigest string    `json:"intent_digest"`
	Approver     string    `json:"approver"`
	Decision     string    `json:"decision"`
	Reason       string    `json:"reason,omitempty"`
	DecidedAt    time.Time `json:"decided_at"`

	ExpectedResourceKind string `json:"expected_resource_kind,omitempty"`
	ExpectedResourceID   string `json:"expected_resource_id,omitempty"`
	ExpectedAction       string `json:"expected_action,omitempty"`
}

type ApprovalStatusChanged struct {
	RequestID     string    `json:"request_id"`
	IntentDigest  string    `json:"intent_digest"`
	Status        string    `json:"status"`
	ChangedAt     time.Time `json:"changed_at"`
	ReplacementID string    `json:"replacement_id,omitempty"`
}

// OperationApprovalDecisionEventID gives one request/digest/principal exactly
// one immutable decision event, regardless of a retry's wall clock.
func OperationApprovalDecisionEventID(tenantID, requestID, intentDigest, approver string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("approval-decision\x00"+tenantID+"\x00"+
		requestID+"\x00"+intentDigest+"\x00"+approver)).String()
}

// OperationApprovalStatusEventID binds one terminal status fact and optional
// replacement request to its exact authority. ChangedAt is deliberately absent:
// the first retained event owns that timestamp forever.
func OperationApprovalStatusEventID(tenantID, requestID, intentDigest, status, replacementID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("approval-status\x00"+tenantID+"\x00"+
		requestID+"\x00"+intentDigest+"\x00"+status+"\x00"+replacementID)).String()
}

func (p *Projector) applyOperationApprovalTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	switch event.Type {
	case EventApprovalRequested:
		var payload ApprovalRequested
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if err := validateApprovalActor(event, payload.Requester); err != nil {
			return true, err
		}
		return true, p.store.ApplyOperationApprovalRequestedTx(ctx, tx, store.OperationApprovalRequest{
			ID: payload.ID, TenantID: event.TenantID, IntentDigest: payload.IntentDigest,
			ResourceKind: payload.ResourceKind, ResourceID: payload.ResourceID,
			ResourceName: payload.ResourceName, Action: payload.Action, Requester: payload.Requester,
			FromState: payload.FromState, ToState: payload.ToState, TargetVersion: payload.TargetVersion,
			Reason: payload.Reason, EvidenceRefs: payload.EvidenceRefs,
			RequiredApprovals: payload.RequiredApprovals,
			CreatedAt:         payload.CreatedAt, ExpiresAt: payload.ExpiresAt,
		})
	case EventApprovalDecisionRecorded:
		var payload ApprovalDecisionRecorded
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if err := validateApprovalActor(event, payload.Approver); err != nil {
			return true, err
		}
		return true, p.store.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: event.TenantID, RequestID: payload.RequestID,
			IntentDigest: payload.IntentDigest, Approver: payload.Approver,
			Decision: payload.Decision, Reason: payload.Reason, EventID: event.ID,
			DecidedAt: payload.DecidedAt, ExpectedResourceKind: payload.ExpectedResourceKind,
			ExpectedResourceID: payload.ExpectedResourceID, ExpectedAction: payload.ExpectedAction,
		})
	case EventApprovalStatusChanged:
		var payload ApprovalStatusChanged
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplyOperationApprovalStatusTx(ctx, tx, event.TenantID,
			payload.RequestID, payload.IntentDigest, payload.Status, payload.ChangedAt)
	default:
		return false, nil
	}
}

// validateApprovalActor applies the same audit binding during cold replay as
// the command producer applies before committing its warm projection. A system
// event may be unattributed. An attributed request/decision must name the
// requester/approver carried by its immutable payload, or the deterministic
// tenant placeholder created by the authorized privacy rewrite. Status events
// intentionally have no bound principal and bypass this check.
func validateApprovalActor(event events.Event, subject string) error {
	if event.Actor == nil || event.Actor.Subject == subject ||
		event.Actor.Subject == privacyref.Placeholder(privacyref.SubjectRef(event.TenantID, subject)) {
		return nil
	}
	return fmt.Errorf("%w: %s actor does not match its bound principal",
		store.ErrIdempotencyConflict, event.Type)
}
