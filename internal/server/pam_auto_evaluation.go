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
			if evaluated.Rule == nil {
				standing, err := s.pamStandingApproval(work, tenantID, intent.Requester, facts)
				if err != nil {
					return err
				}
				evaluated.Standing = standing
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
		if evaluated.Rule != nil || evaluated.Standing != nil {
			intent.RequiredApprovals = 1
		}
		if evaluated.Standing != nil {
			// Activation checks the approval is still in force (OD-9).
			intent.EvidenceRefs = append(intent.EvidenceRefs, pamStandingApprovalEvidence+evaluated.Standing.ApprovalID)
		}
		approval, err := s.orch.EnsureOperationApprovalRequest(work, tenantID, intent)
		if err != nil {
			return err
		}
		if evaluated.Standing != nil {
			result, err = s.pamApproveUnderStandingApproval(work, tenantID, evaluationID, requestID, evaluated, intent, approval)
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
	if st := out.Standing; st != nil && (out.Rule != nil || req.Kind != "session" || !validUUID(st.ApprovalID) || !validUUID(st.BundleID) ||
		st.RunID == "" || st.RunID != req.RunID || st.Role != req.Role || pamStandingApprover(st.ApprovalID) == requester ||
		out.At.Add(time.Duration(req.TTLSeconds)*time.Second).After(st.ExpiresAt)) {
		return out, fmt.Errorf("%w: the standing approval witness differs", store.ErrIdempotencyConflict)
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

// pamStandingApprovalEvidence marks an approval request a bundle's standing
// approval approved (OD-9); activation checks the approval is still in force.
const pamStandingApprovalEvidence = "pam-standing-approval:"

// pamStandingApprover is the synthetic approver a standing approval records.
func pamStandingApprover(approvalID string) string { return "standing-approval:" + approvalID }

// pamStandingApproval finds the access bundle standing approval (OD-9) that
// approves a run's session request: one for exactly this account and role,
// on a bundle the run's own live grants give and that still delegates them,
// in force for the whole session it asks for. Anything else, and every
// request that is not a run's session, keeps the human review.
func (s *pamService) pamStandingApproval(ctx context.Context, tenantID, requester string, facts pamAutoApprovalRequest) (*projections.PAMStandingApprovalMatch, error) {
	principal, isRun := orchestrator.BundleRunPrincipal(requester)
	if facts.Kind != "session" || facts.RunID == "" || !isRun || facts.Role == "" || facts.TTLSeconds <= 0 {
		return nil, nil
	}
	approval, ok, err := s.store.ActiveRunStandingApproval(ctx, tenantID, facts.RunID, facts.TargetType, facts.TargetID, facts.Role, facts.At)
	if err != nil || !ok {
		return nil, err
	}
	expires := approval.ExpiresAt.UTC().Truncate(time.Microsecond)
	if pamStandingApprover(approval.ID) == requester || facts.At.Add(time.Duration(facts.TTLSeconds)*time.Second).After(expires) {
		return nil, nil
	}
	return &projections.PAMStandingApprovalMatch{ApprovalID: approval.ID, BundleID: approval.BundleID, RunID: facts.RunID,
		Principal: principal, Role: facts.Role, ExpiresAt: expires}, nil
}

// pamApproveUnderStandingApproval records the standing approval's one
// approval of the request and, beside it, the approval's use, both
// canonical so a retry after a crash repeats them exactly.
func (s *pamService) pamApproveUnderStandingApproval(work context.Context, tenantID, evaluationID, requestID string, evaluated projections.PAMAutoApprovalEvaluated, intent orchestrator.OperationApprovalIntent, approval store.OperationApprovalRequest) (store.OperationApprovalRequest, error) {
	st := evaluated.Standing
	approver := pamStandingApprover(st.ApprovalID)
	system := events.ContextWithActor(work, events.Actor{Subject: approver, Roles: []string{"policy"}})
	approval, err := s.orch.RecordOperationApprovalDecision(system, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: approval.ID, IntentDigest: approval.IntentDigest, Approver: approver, Decision: store.ApprovalDecisionApprove,
		Reason:               fmt.Sprintf("standing approval %s of access bundle %s for %s/%s as %s", st.ApprovalID, st.BundleID, evaluated.TargetType, evaluated.TargetID, st.Role),
		ExpectedResourceKind: intent.ResourceKind, ExpectedResourceID: intent.ResourceID, ExpectedAction: intent.Action,
	})
	if err != nil {
		return approval, err
	}
	used := projections.AccessBundleStandingApprovalUsed{ID: st.ApprovalID, BundleID: st.BundleID, RunID: st.RunID,
		Principal: st.Principal, RequestID: requestID, ApprovalRequestID: approval.ID}
	raw, err := json.Marshal(used)
	if err != nil {
		return approval, err
	}
	eventID := crypto.UUIDv5OID([]byte("pam-standing-approval-used\x00" + tenantID + "\x00" + evaluationID))
	event, found, err := s.log.EventByID(system, eventID)
	if err != nil {
		return approval, err
	}
	if !found {
		event, err = s.log.Append(system, events.Event{ID: eventID, Type: projections.EventAccessBundleStandingApprovalUsed, TenantID: tenantID, Time: evaluated.At, Data: raw})
		if err != nil {
			return approval, err
		}
	}
	if event.ID != eventID || event.TenantID != tenantID || event.Type != projections.EventAccessBundleStandingApprovalUsed || !bytes.Equal(event.Data, raw) || event.Actor == nil || event.Actor.Subject != approver {
		return approval, fmt.Errorf("%w: the canonical standing approval use differs", store.ErrIdempotencyConflict)
	}
	return approval, s.projector.Apply(system, event)
}

// pamStandingApprovalInForce refuses to activate a request a standing
// approval approved once that approval was revoked or has expired (OD-9).
func (s *pamService) pamStandingApprovalInForce(ctx context.Context, tenantID string, evidenceRefs []string) error {
	for _, ref := range evidenceRefs {
		id, ok := strings.CutPrefix(ref, pamStandingApprovalEvidence)
		if !ok {
			continue
		}
		approval, err := s.store.GetAccessBundleStandingApproval(ctx, tenantID, id)
		if errors.Is(err, store.ErrAccessBundleStandingApprovalNotFound) {
			return fmt.Errorf("%w: the standing approval that approved this request is gone; start a new request", api.ErrPAMRejected)
		}
		if err != nil {
			return err
		}
		if approval.RevokedAt != nil || !approval.ExpiresAt.After(s.clock().UTC()) {
			return fmt.Errorf("%w: the standing approval that approved this request was revoked or has expired; start a new request", api.ErrPAMRejected)
		}
	}
	return nil
}
