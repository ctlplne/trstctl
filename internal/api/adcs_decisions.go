// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Decisions on pending AD CS requests (N1). A request an AD CS template holds
// for a CA manager's approval is approved or denied at the CA by the issuer's
// domain-joined relay — never by the control plane — and only after trstctl's
// own operation approval: the requester asks for an exact decision, other
// reviewers approve it, and the requester then executes exactly what they
// approved, which queues one relay job. The relay acts only while the CA still
// holds the request as pending, and the decision is recorded from its checked
// readback of the CA database.

// ADCSDecisionService runs the approval and execution against the issuer's
// relay route, which lives in the server's external CA configuration.
type ADCSDecisionService interface {
	RequestADCSDecisionApproval(ctx context.Context, tenantID, requester, issuerID string, requestID int,
		input ADCSDecisionRequest) (ADCSDecisionApproval, error)
	QueueADCSDecision(ctx context.Context, tenantID, requester, issuerID string, requestID int,
		input ADCSDecisionStart) (store.ADCSDecision, error)
}

// WithADCSDecisions serves N1's routes.
func WithADCSDecisions(service ADCSDecisionService) Option {
	return func(c *config) { c.adcsDecisions = service }
}

// ErrADCSDecisionUnavailable is an issuer with no AD CS relay route.
var ErrADCSDecisionUnavailable = errors.New("this issuer has no AD CS relay: set revocation_relay on its adcs configuration")

// ADCSDecisionRequest asks for approval of one decision.
type ADCSDecisionRequest struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// ADCSDecisionApproval is the approval request a decision waits on.
type ADCSDecisionApproval struct {
	IssuerID             string    `json:"issuer_id"`
	CAConfig             string    `json:"ca_config"`
	RequestID            int       `json:"request_id"`
	Decision             string    `json:"decision"`
	Reason               string    `json:"reason"`
	ApprovalRequestID    string    `json:"approval_request_id"`
	ApprovalIntentDigest string    `json:"approval_intent_digest"`
	Status               string    `json:"status"`
	RequiredApprovals    int       `json:"required_approvals"`
	ApprovalCount        int       `json:"approval_count"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// ADCSDecisionStart executes an approved decision.
type ADCSDecisionStart struct {
	ApprovalRequestID    string `json:"approval_request_id"`
	ApprovalIntentDigest string `json:"approval_intent_digest"`
}

func (a *API) adcsDecisionRoutes() []route {
	issuerRequest := []param{pathString("id", "configured external CA registry id"), pathInteger("request_id", "the AD CS request id")}
	return []route{
		{method: "POST", path: "/api/v1/external-cas/{id}/adcs-requests/{request_id}/approval-requests", opID: "requestADCSDecisionApproval", summary: "Ask for approval to approve or deny one request an AD CS template holds for a CA manager; other reviewers decide it before anything reaches the CA", handler: a.requestADCSDecisionApproval, pathParams: issuerRequest, reqSchema: "ADCSDecisionRequest", resSchema: "ADCSDecisionApproval", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "POST", path: "/api/v1/external-cas/{id}/adcs-requests/{request_id}/decisions", opID: "executeADCSDecision", summary: "Execute an approved decision: the issuer's relay approves (certutil -resubmit) or denies the request at the CA only while the CA still holds it as pending, and reads its disposition back", handler: a.executeADCSDecision, pathParams: issuerRequest, reqSchema: "ADCSDecisionStart", resSchema: "ADCSDecision", successCode: "201", mutation: true, perm: authz.CertsIssue},
		{method: "GET", path: "/api/v1/external-cas/{id}/adcs-decisions", opID: "listADCSDecisions", summary: "List an AD CS issuer's decisions, newest first: queued, decided with the CA's disposition, or failed with the relay's reason", handler: a.listADCSDecisions, pathParams: []param{pathString("id", "configured external CA registry id")}, resSchema: "ADCSDecisionList", successCode: "200", perm: authz.CertsRead},
	}
}

func adcsRequestFromPath(r *http.Request) (string, int, error) {
	issuerID := strings.TrimSpace(r.PathValue("id"))
	requestID, err := strconv.Atoi(r.PathValue("request_id"))
	if issuerID == "" || err != nil || requestID <= 0 {
		return "", 0, errStatus(http.StatusBadRequest, "name an external CA and a positive AD CS request id")
	}
	return issuerID, requestID, nil
}

func adcsDecisionAPIError(err error) error {
	switch {
	case errors.Is(err, ErrADCSDecisionUnavailable):
		return errStatusFrom(http.StatusConflict, err)
	case errors.Is(err, store.ErrApprovalRequestNotFound):
		return errStatus(http.StatusNotFound, "approval request not found")
	case errors.Is(err, store.ErrApprovalDigestMismatch):
		return errStatus(http.StatusConflict, "the approval request names a different decision, request, issuer or requester")
	}
	return approvalAPIError(err)
}

//trstctl:mutation
func (a *API) requestADCSDecisionApproval(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	issuerID, requestID, err := adcsRequestFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input ADCSDecisionRequest
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	input.Decision, input.Reason = strings.TrimSpace(input.Decision), strings.TrimSpace(input.Reason)
	if input.Decision != "approve" && input.Decision != "deny" {
		a.writeError(w, errStatus(http.StatusBadRequest, "decision is approve or deny"))
		return
	}
	if input.Reason == "" || len(input.Reason) > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "reason is required (at most 200 characters)"))
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("adcs-decision-approval\x00" + subject + "\x00" + issuerID + "\x00" +
		strconv.Itoa(requestID) + "\x00" + input.Decision + "\x00" + input.Reason))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.adcsDecisions == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "AD CS decisions are not configured")
		}
		approval, err := a.adcsDecisions.RequestADCSDecisionApproval(ctx, tenantID, subject, issuerID, requestID, input)
		return http.StatusCreated, approval, adcsDecisionAPIError(err)
	})
}

//trstctl:mutation
func (a *API) executeADCSDecision(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	issuerID, requestID, err := adcsRequestFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var input ADCSDecisionStart
	if err := decodeJSON(r, &input); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("adcs-decision-execute\x00" + subject + "\x00" + issuerID + "\x00" + strconv.Itoa(requestID) +
		"\x00" + input.ApprovalRequestID + "\x00" + input.ApprovalIntentDigest))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.adcsDecisions == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "AD CS decisions are not configured")
		}
		decision, err := a.adcsDecisions.QueueADCSDecision(ctx, tenantID, subject, issuerID, requestID, input)
		if err != nil {
			return 0, nil, adcsDecisionAPIError(err)
		}
		return http.StatusCreated, adcsDecisionResponse(decision), nil
	})
}

type adcsDecisionView struct {
	ID                string     `json:"id"`
	IssuerID          string     `json:"issuer_id"`
	CAConfig          string     `json:"ca_config"`
	RequestID         int        `json:"request_id"`
	Decision          string     `json:"decision"`
	Reason            string     `json:"reason"`
	ApprovalRequestID string     `json:"approval_request_id"`
	RequestedBy       string     `json:"requested_by"`
	Status            string     `json:"status"`
	Disposition       string     `json:"disposition,omitempty"`
	Serial            string     `json:"serial,omitempty"`
	Failure           string     `json:"failure,omitempty"`
	QueuedAt          time.Time  `json:"queued_at"`
	DecidedAt         *time.Time `json:"decided_at,omitempty"`
}

// adcsDecisionResponse reads a decision's status: decided from the relay's
// checked report, failed when its relay job ended without one, queued until
// then.
func adcsDecisionResponse(d store.ADCSDecision) adcsDecisionView {
	view := adcsDecisionView{ID: d.ID, IssuerID: d.IssuerID, CAConfig: d.CAConfig, RequestID: d.RequestID, Decision: d.Decision,
		Reason: d.Reason, ApprovalRequestID: d.ApprovalRequestID, RequestedBy: d.RequestedBy, Status: "queued",
		Disposition: d.Disposition, Serial: d.Serial, QueuedAt: d.QueuedAt, DecidedAt: d.DecidedAt}
	switch {
	case d.Decided:
		view.Status = "decided"
	case d.JobStatus == "failed" || d.JobStatus == "dead_letter" || d.JobStatus == "cancelled":
		view.Status, view.Failure = "failed", d.JobError
	}
	return view
}

func (a *API) listADCSDecisions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	decisions, err := a.store.ListADCSDecisions(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")), 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]adcsDecisionView, 0, len(decisions))
	for _, d := range decisions {
		items = append(items, adcsDecisionResponse(d))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func adcsDecisionSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	decisionEnum := &Schema{Type: "string", Enum: []string{"approve", "deny"}}
	decision := object(map[string]*Schema{"id": str(), "issuer_id": str(), "ca_config": str(), "request_id": integer(),
		"decision": decisionEnum, "reason": str(), "approval_request_id": str(), "requested_by": str(),
		"status": {Type: "string", Enum: []string{"queued", "decided", "failed"}}, "disposition": str(), "serial": str(),
		"failure": str(), "queued_at": ts(), "decided_at": ts()},
		"id", "issuer_id", "ca_config", "request_id", "decision", "reason", "approval_request_id", "requested_by", "status", "queued_at")
	return map[string]*Schema{
		"ADCSDecisionRequest": object(map[string]*Schema{"decision": decisionEnum, "reason": str()}, "decision", "reason"),
		"ADCSDecisionApproval": object(map[string]*Schema{"issuer_id": str(), "ca_config": str(), "request_id": integer(),
			"decision": decisionEnum, "reason": str(), "approval_request_id": str(), "approval_intent_digest": str(), "status": str(),
			"required_approvals": integer(), "approval_count": integer(), "expires_at": ts()},
			"issuer_id", "ca_config", "request_id", "decision", "reason", "approval_request_id", "approval_intent_digest", "status",
			"required_approvals", "approval_count", "expires_at"),
		"ADCSDecisionStart": object(map[string]*Schema{"approval_request_id": str(), "approval_intent_digest": str()},
			"approval_request_id", "approval_intent_digest"),
		"ADCSDecision":     decision,
		"ADCSDecisionList": object(map[string]*Schema{"items": {Type: "array", Items: decision}}, "items"),
	}
}
