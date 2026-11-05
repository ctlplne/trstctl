// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func commandReviewEventID(kind, tenant, id string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(kind+"\x00"+tenant+"\x00"+id)).String()
}

// Every invocation is short. The gateway owns the bounded human wait and polls
// the same immutable occurrence; no SQL transaction or worker waits for a vote.
func (s *pamService) reviewGatewayCommand(ctx context.Context, tenant, agent string, intent accessgateway.SessionIntent, expected accessrules.Decision, quorum, ttl int, canceled bool) (accessrules.Decision, error) {
	var result accessrules.Decision
	err := s.store.WithTenantResourceCreation(ctx, tenant, expected.ID, func(work context.Context) error {
		requestedID := commandReviewEventID(projections.EventPAMCommandReviewRequested, tenant, expected.ID)
		source, found, err := s.log.EventByID(work, requestedID)
		if err != nil {
			return err
		}
		session, err := s.store.GetPAMSession(work, tenant, intent.SessionID)
		if err != nil {
			return err
		}
		live := func() bool {
			digest, err := accessrules.PolicyDigest(session.CommandPolicy)
			return err == nil && session.CommandPolicy != nil && digest == expected.PolicyDigest && session.Status == api.PAMSessionStatusActive && session.Delivery == "gateway" && session.GatewayAgentID == agent && s.clock().Before(session.ExpiresAt) && s.clock().Before(intent.ExpiresAt)
		}
		if !found {
			if !live() {
				return api.ErrPAMRejected
			}
			initial := expected
			initial.Status = accessrules.StatusPending
			initial.Reason = "review_required"
			initial.ObservedAt = s.clock().UTC().Truncate(time.Microsecond)
			initial.DecidedAt = initial.ObservedAt
			deadline := initial.ObservedAt.Add(time.Duration(ttl) * time.Second)
			if session.ExpiresAt.Before(deadline) {
				deadline = session.ExpiresAt
			}
			if intent.ExpiresAt.Before(deadline) {
				deadline = intent.ExpiresAt
			}
			initial.ReviewExpiresAt = &deadline
			data, err := json.Marshal(initial)
			if err != nil {
				return err
			}
			source, err = s.log.Append(work, events.Event{ID: requestedID, Type: projections.EventPAMCommandReviewRequested, TenantID: tenant, Time: initial.ObservedAt, Data: data})
			if err != nil {
				return err
			}
		}
		if source.ID != requestedID || source.Type != projections.EventPAMCommandReviewRequested || source.TenantID != tenant || source.SchemaVersion != 1 || len(source.Data) > 8<<10 {
			return orchestrator.ErrIdempotencyConflict
		}
		var initial accessrules.Decision
		decoder := json.NewDecoder(bytes.NewReader(source.Data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&initial) != nil || accessrules.ValidateDecision(initial) != nil || initial.Status != accessrules.StatusPending || !initial.ObservedAt.Equal(source.Time) {
			return orchestrator.ErrIdempotencyConflict
		}
		bound := expected
		bound.Status = initial.Status
		bound.Reason = initial.Reason
		bound.ObservedAt = initial.ObservedAt
		bound.DecidedAt = initial.DecidedAt
		bound.ReviewExpiresAt = initial.ReviewExpiresAt
		deadline := initial.ObservedAt.Add(time.Duration(ttl) * time.Second)
		if session.ExpiresAt.Before(deadline) {
			deadline = session.ExpiresAt
		}
		if intent.ExpiresAt.Before(deadline) {
			deadline = intent.ExpiresAt
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF || !deadline.Equal(*initial.ReviewExpiresAt) {
			return orchestrator.ErrIdempotencyConflict
		}
		if !reflect.DeepEqual(bound, initial) {
			return orchestrator.ErrIdempotencyConflict
		}
		if err := s.projector.Apply(work, source); err != nil {
			return err
		}
		terminalID := commandReviewEventID(projections.EventPAMCommandReviewDecided, tenant, expected.ID)
		terminal, terminalFound, err := s.log.EventByID(work, terminalID)
		if err != nil {
			return err
		}
		if terminalFound {
			if err := s.replayCommandReview(work, tenant, terminalID, initial, terminal, &result); err != nil {
				return err
			}
			if result.Status == accessrules.StatusAuthorized && !live() {
				return api.ErrPAMRejected
			}
			return nil
		}
		now := s.clock().UTC().Truncate(time.Microsecond)
		final := initial
		final.DecidedAt = now
		var use *store.OperationApprovalUse
		switch {
		case canceled:
			final.Status = accessrules.StatusCanceled
			final.Reason = "client_canceled"
		case !live():
			final.Status = accessrules.StatusCanceled
			final.Reason = "session_ended"
		case !now.Before(*initial.ReviewExpiresAt):
			final.Status = accessrules.StatusExpired
			final.Reason = "review_expired"
		default:
			// The gateway authenticates the stream, but the reviewed operation belongs to
			// its original requester. No agent role can cast that person's approval vote.
			approval, err := s.orch.EnsureOperationApprovalRequest(events.ContextWithoutActor(work), tenant, orchestrator.OperationApprovalIntent{
				ResourceKind: "pam_command", ResourceID: "pam-command:" + initial.ID, ResourceName: intent.TargetType + "/" + intent.TargetID,
				Action: "execute", Requester: session.RequestedBy, FromState: "held", ToState: "authorized",
				Reason:            "Authorize one matched operation class. Statement text, arguments and bound values are not reviewed.",
				EvidenceRefs:      []string{"pam-session:" + initial.SessionID, "pam-action:" + initial.ID, "pam-policy-sha256:" + initial.PolicyDigest, "pam-message-sha256:" + initial.MessageDigest, "pam-rule-ids:" + joinCommandRuleIDs(initial.RuleIDs), "pam-operations:" + joinCommandRuleIDs(initial.Operations)},
				RequiredApprovals: quorum, TTL: time.Duration(ttl) * time.Second, ExpiresAtNotAfter: *initial.ReviewExpiresAt,
			})
			if err != nil {
				return err
			}
			switch approval.Status {
			case store.ApprovalStatusPending:
				result = initial
				return nil
			case store.ApprovalStatusApproved:
				value, err := store.OperationApprovalUseFromRequest(approval)
				if err != nil {
					return err
				}
				use = &value
				final.Status = accessrules.StatusAuthorized
				final.Reason = "review_approved"
			case store.ApprovalStatusDenied:
				final.Status = accessrules.StatusDenied
				final.Reason = "review_denied"
			case store.ApprovalStatusExpired:
				final.Status = accessrules.StatusExpired
				final.Reason = "review_expired"
			default:
				return api.ErrPAMRejected
			}
		}
		payload := projections.PAMCommandReviewDecided{Decision: final, Approval: use}
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return s.store.WithTenant(work, tenant, func(tx pgx.Tx) error {
			if _, err := s.store.GetPAMCommandActionForUpdateTx(work, tx, tenant, initial.ID); err != nil {
				return err
			}
			if use != nil {
				if _, err := s.store.ValidateOperationApprovalUseTx(work, tx, tenant, *use, now); err != nil {
					return err
				}
			}
			terminal, err = s.log.Append(work, events.Event{ID: terminalID, Type: projections.EventPAMCommandReviewDecided, TenantID: tenant, Time: now, Data: data})
			if err != nil {
				return err
			}
			if err := validateCommandReviewTerminal(tenant, terminalID, initial, terminal); err != nil {
				return err
			}
			if err := s.projector.ApplyTx(work, tx, terminal); err != nil {
				return err
			}
			result = final
			return nil
		})
	})
	return result, err
}

func joinCommandRuleIDs(ids []string) string {
	var out string
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func validateCommandReviewTerminal(tenant, id string, initial accessrules.Decision, event events.Event) error {
	if event.ID != id || event.Type != projections.EventPAMCommandReviewDecided || event.TenantID != tenant || event.SchemaVersion != 1 || len(event.Data) > 16<<10 {
		return orchestrator.ErrIdempotencyConflict
	}
	var payload projections.PAMCommandReviewDecided
	dec := json.NewDecoder(bytes.NewReader(event.Data))
	dec.DisallowUnknownFields()
	if dec.Decode(&payload) != nil || accessrules.ValidateDecision(payload.Decision) != nil || payload.Status == accessrules.StatusPending || payload.Status == accessrules.StatusBlocked || !payload.DecidedAt.Equal(event.Time) {
		return errors.New("invalid canonical command review result")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return orchestrator.ErrIdempotencyConflict
	}
	expected := initial
	expected.DecidedAt = payload.DecidedAt
	expected.Status = payload.Status
	expected.Reason = payload.Reason
	if !reflect.DeepEqual(expected, payload.Decision) {
		return orchestrator.ErrIdempotencyConflict
	}
	return nil
}
func (s *pamService) replayCommandReview(ctx context.Context, tenant, id string, initial accessrules.Decision, event events.Event, result *accessrules.Decision) error {
	if err := validateCommandReviewTerminal(tenant, id, initial, event); err != nil {
		return err
	}
	if err := s.projector.Apply(ctx, event); err != nil {
		return err
	}
	var payload projections.PAMCommandReviewDecided
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return err
	}
	*result = payload.Decision
	return nil
}
