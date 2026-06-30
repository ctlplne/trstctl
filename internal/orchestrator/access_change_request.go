package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AccessChangeRequestCreateRequest records a change-management request for an NHI
// access grant, modification, revoke, rotate, deployment, or break-glass action.
// It is metadata-only: PR/change refs and evidence refs, never credentials.
type AccessChangeRequestCreateRequest struct {
	ID                string   `json:"id,omitempty"`
	RequestedAction   string   `json:"requested_action"`
	RequesterSubject  string   `json:"requester_subject,omitempty"`
	NHIID             string   `json:"nhi_id"`
	NHIKind           string   `json:"nhi_kind"`
	DisplayName       string   `json:"display_name,omitempty"`
	OwnerRef          string   `json:"owner_ref,omitempty"`
	Resource          string   `json:"resource"`
	Entitlement       string   `json:"entitlement"`
	ChangeRef         string   `json:"change_ref"`
	ChangeSystem      string   `json:"change_system,omitempty"`
	ChangeURL         string   `json:"change_url,omitempty"`
	Risk              string   `json:"risk,omitempty"`
	Reason            string   `json:"reason"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
}

// AccessChangeDecisionRequest records one distinct approver decision.
type AccessChangeDecisionRequest struct {
	Decision             string   `json:"decision"`
	ApproverSubject      string   `json:"approver_subject,omitempty"`
	Reason               string   `json:"reason,omitempty"`
	DecisionEvidenceRefs []string `json:"decision_evidence_refs,omitempty"`
}

func (o *Orchestrator) CreateAccessChangeRequest(ctx context.Context, tenantID string, in AccessChangeRequestCreateRequest) (store.AccessChangeRequest, error) {
	payload, err := normalizeAccessChangeRequest(ctx, in)
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	evData, err := json.Marshal(payload)
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventAccessChangeRequestCreated, TenantID: tenantID, Data: evData})
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		return store.AccessChangeRequest{}, err
	}
	return o.store.GetAccessChangeRequest(ctx, tenantID, payload.ID)
}

func (o *Orchestrator) DecideAccessChangeRequest(ctx context.Context, tenantID, requestID string, in AccessChangeDecisionRequest) (store.AccessChangeRequest, error) {
	requestID = strings.TrimSpace(requestID)
	req, err := o.store.GetAccessChangeRequest(ctx, tenantID, requestID)
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	if req.Status != "pending" {
		return store.AccessChangeRequest{}, fmt.Errorf("%w: request %s is %s", store.ErrAccessChangeRequestTerminal, req.ID, req.Status)
	}
	payload, err := normalizeAccessChangeDecision(ctx, req, in)
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	for _, existing := range req.Decisions {
		if existing.ApproverSubject == payload.ApproverSubject {
			return store.AccessChangeRequest{}, fmt.Errorf("%w: %s already decided request %s", store.ErrAccessChangeDecisionDuplicate, payload.ApproverSubject, req.ID)
		}
	}
	evData, err := json.Marshal(payload)
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventAccessChangeRequestDecided, TenantID: tenantID, Data: evData})
	if err != nil {
		return store.AccessChangeRequest{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		return store.AccessChangeRequest{}, err
	}
	return o.store.GetAccessChangeRequest(ctx, tenantID, req.ID)
}

func normalizeAccessChangeRequest(ctx context.Context, in AccessChangeRequestCreateRequest) (projections.AccessChangeRequestCreated, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	} else if _, err := uuid.Parse(id); err != nil {
		return projections.AccessChangeRequestCreated{}, fmt.Errorf("access request id must be a UUID")
	}
	action := strings.ToLower(trimBounded(in.RequestedAction, 40))
	switch action {
	case "grant", "modify", "revoke", "rotate", "deploy", "break_glass":
	default:
		return projections.AccessChangeRequestCreated{}, fmt.Errorf("requested_action must be grant, modify, revoke, rotate, deploy, or break_glass")
	}
	requester := trimBounded(in.RequesterSubject, 180)
	if requester == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			requester = trimBounded(actor.Subject, 180)
		}
	}
	if requester == "" {
		return projections.AccessChangeRequestCreated{}, fmt.Errorf("requester_subject is required")
	}
	nhiID := trimBounded(in.NHIID, 240)
	nhiKind := trimBounded(in.NHIKind, 80)
	resource := trimBounded(in.Resource, 240)
	entitlement := trimBounded(in.Entitlement, 160)
	changeRef := trimBounded(in.ChangeRef, 260)
	reason := trimBounded(in.Reason, 500)
	if nhiID == "" || nhiKind == "" || resource == "" || entitlement == "" || changeRef == "" || reason == "" {
		return projections.AccessChangeRequestCreated{}, fmt.Errorf("nhi_id, nhi_kind, resource, entitlement, change_ref, and reason are required")
	}
	displayName := trimBounded(in.DisplayName, 200)
	if displayName == "" {
		displayName = nhiID
	}
	changeSystem := strings.ToLower(trimBounded(in.ChangeSystem, 60))
	if changeSystem == "" {
		changeSystem = inferChangeSystem(changeRef, in.ChangeURL)
	}
	changeURL := trimBounded(in.ChangeURL, 500)
	if changeURL != "" {
		if _, err := url.ParseRequestURI(changeURL); err != nil {
			return projections.AccessChangeRequestCreated{}, fmt.Errorf("change_url must be an absolute or path URL")
		}
	}
	risk := strings.ToLower(trimBounded(in.Risk, 40))
	if risk == "" {
		risk = "medium"
	}
	required := in.RequiredApprovals
	if required == 0 {
		required = 1
	}
	if required < 1 || required > 5 {
		return projections.AccessChangeRequestCreated{}, fmt.Errorf("required_approvals must be between 1 and 5")
	}
	refs, err := normalizeEvidenceRefs(in.EvidenceRefs)
	if err != nil {
		return projections.AccessChangeRequestCreated{}, err
	}
	return projections.AccessChangeRequestCreated{
		ID: id, RequestedAction: action, RequesterSubject: requester,
		NHIID: nhiID, NHIKind: nhiKind, DisplayName: displayName, OwnerRef: trimBounded(in.OwnerRef, 180),
		Resource: resource, Entitlement: entitlement, ChangeRef: changeRef, ChangeSystem: changeSystem,
		ChangeURL: changeURL, Risk: risk, Reason: reason, EvidenceRefs: refs, RequiredApprovals: required,
	}, nil
}

func normalizeAccessChangeDecision(ctx context.Context, req store.AccessChangeRequest, in AccessChangeDecisionRequest) (projections.AccessChangeRequestDecided, error) {
	decision := strings.ToLower(strings.TrimSpace(in.Decision))
	switch decision {
	case "approved", "denied":
	default:
		return projections.AccessChangeRequestDecided{}, fmt.Errorf("decision must be approved or denied")
	}
	approver := trimBounded(in.ApproverSubject, 180)
	if approver == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			approver = trimBounded(actor.Subject, 180)
		}
	}
	if approver == "" {
		return projections.AccessChangeRequestDecided{}, fmt.Errorf("approver_subject is required")
	}
	if approver == req.RequesterSubject {
		return projections.AccessChangeRequestDecided{}, fmt.Errorf("approver_subject must differ from requester_subject")
	}
	reason := trimBounded(in.Reason, 500)
	if decision == "denied" && reason == "" {
		return projections.AccessChangeRequestDecided{}, fmt.Errorf("reason is required for denied decisions")
	}
	refs, err := normalizeEvidenceRefs(in.DecisionEvidenceRefs)
	if err != nil {
		return projections.AccessChangeRequestDecided{}, err
	}
	return projections.AccessChangeRequestDecided{
		RequestID: req.ID, Decision: decision, ApproverSubject: approver,
		Reason: reason, DecisionEvidenceRefs: refs, DecidedAt: time.Now().UTC(),
	}, nil
}

func inferChangeSystem(changeRef, changeURL string) string {
	lower := strings.ToLower(strings.TrimSpace(changeRef + " " + changeURL))
	switch {
	case strings.Contains(lower, "github"):
		return "github"
	case strings.Contains(lower, "gitlab"):
		return "gitlab"
	case strings.Contains(lower, "bitbucket"):
		return "bitbucket"
	case strings.Contains(lower, "servicenow") || strings.HasPrefix(lower, "chg"):
		return "servicenow"
	case strings.Contains(lower, "jira"):
		return "jira"
	default:
		return "external"
	}
}
