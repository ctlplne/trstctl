// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Decisions on pending AD CS requests (N1): a decision queued for the issuer's
// relay, consuming the exact operation approval it carries, and the decision
// the relay's checked report says the CA now holds.
const (
	EventADCSDecisionQueued = "adcs.request.decision_queued"
	EventADCSDecided        = "adcs.request.decided"
)

// ADCSDecisionQueued is the payload of adcs.request.decision_queued.
type ADCSDecisionQueued struct {
	ID           string                     `json:"id"`
	IssuerID     string                     `json:"issuer_id"`
	CAConfig     string                     `json:"ca_config"`
	RequestID    int                        `json:"request_id"`
	Decision     string                     `json:"decision"`
	RelayAgentID string                     `json:"relay_agent_id"`
	Approval     store.OperationApprovalUse `json:"approval"`
}

// ADCSDecided is the payload of adcs.request.decided.
type ADCSDecided struct {
	ID          string `json:"id"`
	Disposition string `json:"disposition"`
	Serial      string `json:"serial,omitempty"`
}

// ValidateADCSDecisionQueued checks a queued decision's closed shape.
func ValidateADCSDecisionQueued(q ADCSDecisionQueued) error {
	if q.ID == "" || q.IssuerID == "" || q.CAConfig == "" || q.RequestID <= 0 || q.RelayAgentID == "" ||
		(q.Decision != "approve" && q.Decision != "deny") || q.Approval.RequestID == "" || q.Approval.ResourceKind != "adcs_request" ||
		q.Approval.Action != q.Decision {
		return errors.New("projections: an AD CS decision needs its id, issuer, CA, request, approve or deny, relay and its approval")
	}
	return nil
}

func init() {
	for _, typ := range []string{EventADCSDecisionQueued, EventADCSDecided} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyADCSDecisionTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventADCSDecisionQueued:
		var q ADCSDecisionQueued
		if err := json.Unmarshal(e.Data, &q); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateADCSDecisionQueued(q); err != nil {
			return true, err
		}
		if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, q.Approval, e.ID, e.Time); err != nil {
			return true, err
		}
		return true, p.store.ApplyADCSDecisionQueuedTx(ctx, tx, e.TenantID, store.ADCSDecision{ID: q.ID, IssuerID: q.IssuerID,
			CAConfig: q.CAConfig, RequestID: q.RequestID, Decision: q.Decision, RelayAgentID: q.RelayAgentID, Reason: q.Approval.Reason,
			ApprovalRequestID: q.Approval.RequestID, RequestedBy: q.Approval.Requester, QueuedAt: e.Time}, e.Sequence)
	case EventADCSDecided:
		var d ADCSDecided
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return true, p.store.ApplyADCSDecidedTx(ctx, tx, e.TenantID, d.ID, d.Disposition, d.Serial, e.Time, e.Sequence)
	}
	return false, nil
}

func addADCSDecisionPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		clear  = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventADCSDecisionQueued, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/issuer_id", opaque), privacyRule("/ca_config", opaque),
		privacyRule("/request_id", opaque), privacyRule("/decision", opaque), privacyRule("/relay_agent_id", opaque),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs", opaque),
		privacyRule("/approval/issuance", opaque))
	policies[privacyEventPolicyKey{EventADCSDecided, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/disposition", opaque), privacyRule("/serial", opaque))
}

func addADCSDecisionPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventADCSDecisionQueued, 1}] = privacyPayloadShape[ADCSDecisionQueued]()
	shapes[privacyEventPolicyKey{EventADCSDecided, 1}] = privacyPayloadShape[ADCSDecided]()
}
