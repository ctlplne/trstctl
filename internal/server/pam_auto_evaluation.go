// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// pamEnsureReviewedRequest freezes policy evaluation before requesting the
// review. The existing resource-creation fence carries a dedicated lock-pool
// session through nested event/projection work; it never parks all request
// connections while waiting for another request connection.
func (s *pamService) pamEnsureReviewedRequest(ctx context.Context, tenantID string, intent orchestrator.OperationApprovalIntent, facts pamAutoApprovalRequest, requestID string) (store.OperationApprovalRequest, error) {
	var result store.OperationApprovalRequest
	baseDigest, err := pamAutoApprovalBaseDigest(tenantID, intent)
	if err != nil {
		return result, err
	}
	actor, ok := events.ActorFromContext(ctx)
	if !ok {
		// Internal legacy callers without an authenticated actor retain human
		// review. They cannot obtain automatic authority, including from a rule
		// with no role condition.
		return s.orch.EnsureOperationApprovalRequest(ctx, tenantID, intent)
	}
	if actor.Subject != intent.Requester {
		return result, fmt.Errorf("%w: the access requester differs from the authenticated actor", api.ErrPAMRejected)
	}
	facts.Roles = slices.Clone(actor.Roles)
	identity := strings.Join([]string{"trstctl:pam-auto-evaluation:v1", tenantID, facts.Kind, intent.Requester, requestID}, "\x00")
	evaluationID := crypto.UUIDv5OID([]byte(identity))
	resource := crypto.SHA256Hex([]byte(identity))
	err = s.store.WithTenantResourceCreation(ctx, tenantID, resource, func(work context.Context) error {
		source, found, err := s.log.EventByID(work, evaluationID)
		if err != nil {
			return err
		}
		if !found {
			target, err := s.getPAMTarget(work, tenantID, facts.TargetType, facts.TargetID)
			if err != nil {
				return err
			}
			facts.Folder = target.Folder
			facts.At = s.clock().UTC().Truncate(time.Microsecond)
			evaluated := projections.PAMAutoApprovalEvaluated{RequestID: requestID, Kind: facts.Kind, Requester: intent.Requester, BaseDigest: baseDigest, TargetType: facts.TargetType, TargetID: facts.TargetID, Folder: facts.Folder, At: facts.At, ExpiresAt: facts.At.Add(intent.TTL).Truncate(time.Microsecond)}
			rules, err := s.store.ListPAMAutoApprovalRules(work, tenantID)
			if err != nil {
				return err
			}
			if len(rules) > 256 {
				return fmt.Errorf("%w: at most 256 live automatic review rules can be evaluated; delete unused rules", api.ErrPAMInvalid)
			}
			for _, rule := range rules {
				// The engine's self-review fence still applies to synthetic
				// identities. A colliding requester keeps the human quorum.
				if "auto-approval:"+rule.ID == intent.Requester {
					continue
				}
				matched, ok := pamAutoApprovalMatches(rule, facts)
				if !ok {
					continue
				}
				selected := rule
				evaluated.Rule = &selected
				evaluated.Facts = &projections.PAMAutoApprovalFacts{Target: matched.Target, Folder: matched.Folder, Roles: matched.Roles, Window: matched.Window, Ticket: matched.Ticket}
				break
			}
			raw, err := json.Marshal(evaluated)
			if err != nil {
				return err
			}
			source, err = s.log.Append(work, events.Event{ID: evaluationID, Type: projections.EventPAMAutoApprovalEvaluated, TenantID: tenantID, Time: evaluated.At, Data: raw})
			if err != nil {
				return err
			}
		}
		evaluated, err := pamCanonicalAutoEvaluation(source, tenantID, evaluationID, requestID, facts, intent.Requester, baseDigest, intent.TTL)
		if err != nil {
			return err
		}
		if err := s.projector.Apply(work, source); err != nil {
			return err
		}
		if !s.clock().Before(evaluated.ExpiresAt) {
			return fmt.Errorf("%w: the access review expired; start a new request", api.ErrPAMRejected)
		}
		intent.EvidenceRefs = append(intent.EvidenceRefs, "pam-auto-evaluation:"+evaluationID)
		intent.ExpiresAtNotAfter = evaluated.ExpiresAt
		if evaluated.Rule != nil {
			intent.RequiredApprovals = 1
		}
		approval, err := s.orch.EnsureOperationApprovalRequest(work, tenantID, intent)
		if err != nil {
			return err
		}
		if evaluated.Rule == nil {
			result = approval
			return nil
		}
		approver := "auto-approval:" + evaluated.Rule.ID
		system := events.ContextWithActor(work, events.Actor{Subject: approver, Roles: []string{"policy"}})
		approval, err = s.orch.RecordOperationApprovalDecision(system, tenantID, orchestrator.OperationApprovalDecision{RequestID: approval.ID, IntentDigest: approval.IntentDigest, Approver: approver, Decision: store.ApprovalDecisionApprove, Reason: fmt.Sprintf("rule %s@%d matched", evaluated.Rule.Name, evaluated.Rule.Revision), ExpectedResourceKind: intent.ResourceKind, ExpectedResourceID: intent.ResourceID, ExpectedAction: intent.Action})
		if err != nil {
			return err
		}
		// Fault injection for the durable-decision / applied-evidence crash edge.
		// Production leaves it nil; recovery repeats the same canonical decision.
		if s.afterAutoApprovalDecision != nil {
			if err := s.afterAutoApprovalDecision(); err != nil {
				return err
			}
		}
		applied := projections.PAMAutoApprovalApplied{RuleID: evaluated.Rule.ID, RuleName: evaluated.Rule.Name, RuleRevision: evaluated.Rule.Revision, ApprovalRequestID: approval.ID, IntentDigest: approval.IntentDigest, Kind: evaluated.Kind, TargetType: evaluated.TargetType, TargetID: evaluated.TargetID, Folder: evaluated.Folder, Requester: evaluated.Requester, MatchedRoles: evaluated.Facts.Roles, Window: evaluated.Facts.Window, Ticket: evaluated.Facts.Ticket, At: evaluated.At}
		raw, err := json.Marshal(applied)
		if err != nil {
			return err
		}
		eventID := crypto.UUIDv5OID([]byte("pam-auto-approval-applied\x00" + tenantID + "\x00" + evaluationID))
		event, found, err := s.log.EventByID(system, eventID)
		if err != nil {
			return err
		}
		if !found {
			event, err = s.log.Append(system, events.Event{ID: eventID, Type: projections.EventPAMAutoApprovalApplied, TenantID: tenantID, Time: evaluated.At, Data: raw})
			if err != nil {
				return err
			}
		}
		if event.ID != eventID || event.TenantID != tenantID || event.Type != projections.EventPAMAutoApprovalApplied || !bytes.Equal(event.Data, raw) || event.Actor == nil || event.Actor.Subject != approver {
			return fmt.Errorf("%w: the canonical automatic review evidence differs", store.ErrIdempotencyConflict)
		}
		if err := s.projector.Apply(system, event); err != nil {
			return err
		}
		result = approval
		return nil
	})
	if errors.Is(err, store.ErrResourceAdmissionBusy) {
		return result, fmt.Errorf("%w: this access request is being evaluated; retry", store.ErrDatastoreBusy)
	}
	return result, err
}

func pamCanonicalAutoEvaluation(source events.Event, tenantID, eventID, requestID string, req pamAutoApprovalRequest, requester, digest string, reviewTTL time.Duration) (projections.PAMAutoApprovalEvaluated, error) {
	var out projections.PAMAutoApprovalEvaluated
	if source.ID != eventID || source.TenantID != tenantID || source.Type != projections.EventPAMAutoApprovalEvaluated || source.Actor == nil || source.Actor.Subject != requester {
		return out, fmt.Errorf("%w: automatic review evaluation envelope differs", store.ErrIdempotencyConflict)
	}
	if len(source.Data) > 256<<10 {
		return out, fmt.Errorf("%w: automatic review evaluation is too large", store.ErrIdempotencyConflict)
	}
	dec := json.NewDecoder(bytes.NewReader(source.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return out, fmt.Errorf("%w: automatic review evaluation has trailing data", store.ErrIdempotencyConflict)
	}
	if out.RequestID != requestID || out.Kind != req.Kind || out.Requester != requester || out.BaseDigest != digest || out.TargetType != req.TargetType || out.TargetID != req.TargetID || out.At.IsZero() || !source.Time.Equal(out.At) || !out.ExpiresAt.Equal(out.At.Add(reviewTTL)) || !out.ExpiresAt.After(out.At) || (out.Rule == nil) != (out.Facts == nil) {
		return out, fmt.Errorf("%w: automatic review evaluation command differs", store.ErrIdempotencyConflict)
	}
	if out.Rule != nil && (!validUUID(out.Rule.ID) || out.Rule.Name == "" || out.Rule.Revision < 1 || out.Facts.Target != req.TargetType+"/"+req.TargetID || "auto-approval:"+out.Rule.ID == requester) {
		return out, fmt.Errorf("%w: automatic review rule witness is incomplete", store.ErrIdempotencyConflict)
	}
	if out.Rule != nil {
		frozen := req
		frozen.At, frozen.Folder, frozen.Roles = out.At, out.Folder, slices.Clone(source.Actor.Roles)
		matched, ok := pamAutoApprovalMatches(*out.Rule, frozen)
		if !ok {
			return out, fmt.Errorf("%w: the frozen automatic review rule did not match", store.ErrIdempotencyConflict)
		}
		expected, _ := json.Marshal(matched)
		actual, _ := json.Marshal(out.Facts)
		if !bytes.Equal(expected, actual) {
			return out, fmt.Errorf("%w: the automatic review witness differs", store.ErrIdempotencyConflict)
		}
	}
	return out, nil
}

// pamAutoApprovalBaseDigest describes only the stable operator command. The
// rule selection and clock become a separate canonical source record.
func pamAutoApprovalBaseDigest(tenantID string, in orchestrator.OperationApprovalIntent) (string, error) {
	refs := make([]string, 0, len(in.EvidenceRefs))
	for _, ref := range in.EvidenceRefs {
		ref = strings.TrimSpace(ref)
		if ref != "" && !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	slices.Sort(refs)
	basis := struct {
		Version, TenantID, ResourceKind, ResourceID, ResourceName, Action, Requester, FromState, ToState, Reason string
		TargetVersion                                                                                            uint64
		EvidenceRefs                                                                                             []string
		RequiredApprovals                                                                                        int
		TTLNanoseconds                                                                                           int64
	}{"trstctl.pam.auto-review-base.v1", tenantID, strings.TrimSpace(in.ResourceKind), strings.TrimSpace(in.ResourceID), strings.TrimSpace(in.ResourceName), strings.TrimSpace(in.Action), strings.TrimSpace(in.Requester), strings.TrimSpace(in.FromState), strings.TrimSpace(in.ToState), strings.TrimSpace(in.Reason), in.TargetVersion, refs, in.RequiredApprovals, int64(in.TTL)}
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}
