// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// ApprovalRequestRecord is the served, non-secret view of an immutable operation
// approval request. Inventory state never becomes a row implicitly: every item
// came from approval.requested and is keyed by ID + IntentDigest.
type ApprovalRequestRecord struct {
	ID                string   `json:"id"`
	IntentDigest      string   `json:"intent_digest"`
	ResourceID        string   `json:"resource_id"`
	ResourceName      string   `json:"resource_name"`
	ResourceKind      string   `json:"resource_kind"`
	Action            string   `json:"action"`
	Requester         string   `json:"requester"`
	FromState         string   `json:"from_state,omitempty"`
	ToState           string   `json:"to_state,omitempty"`
	TargetVersion     string   `json:"target_version"`
	Reason            string   `json:"reason,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs"`
	ApprovalCount     int      `json:"approval_count"`
	RequiredApprovals int      `json:"required_approvals"`
	Status            string   `json:"status"`
	CreatedAt         string   `json:"created_at"`
	ExpiresAt         string   `json:"expires_at"`
}

type ApprovalDecisionCommand struct {
	RequestID            string
	IntentDigest         string
	Approver             string
	Decision             string
	Reason               string
	ExpectedResourceKind string
	ExpectedResourceID   string
	ExpectedAction       string
}

// ApprovalRecorder is the shared event-sourced approval service. Recording a
// decision always names the exact request ID and digest; implementations must
// refuse an unknown, expired, superseded, drifted, consumed, or self-owned
// request and must never create a parent request from this method.
type ApprovalRecorder interface {
	// ValidateApprovalRequest is a read-only tenant-scoped preflight. HTTP routes
	// call it before reserving an idempotency key; RecordApproval repeats every
	// check under projection locks and remains the authorization boundary.
	ValidateApprovalRequest(ctx context.Context, tenantID string, decision ApprovalDecisionCommand) (ApprovalRequestRecord, error)
	RecordApproval(ctx context.Context, tenantID string, decision ApprovalDecisionCommand) (ApprovalRequestRecord, error)
}

// ApprovalRequestListOptions is the served queue's stable newest-first keyset
// cursor plus the exact domains the authenticated principal may review. The store
// applies these booleans in SQL; the API independently rechecks every returned row.
type ApprovalRequestListOptions struct {
	Status                string
	AfterCreatedAt        *time.Time
	AfterID               string
	Limit                 int
	CertificateOperations bool
	SecretOperations      bool
	ManagedKeyOperations  bool
}

type ApprovalRequestLister interface {
	ListApprovalRequests(ctx context.Context, tenantID string, options ApprovalRequestListOptions) ([]ApprovalRequestRecord, error)
}

func WithApprovals(r ApprovalRecorder) Option { return func(c *config) { c.approvals = r } }

type approvalRequest struct {
	Action       string `json:"action,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	IntentDigest string `json:"intent_digest"`
}

type approvalDecisionInput struct {
	IntentDigest string `json:"intent_digest"`
}

type approvalDenialInput struct {
	IntentDigest string `json:"intent_digest"`
	Reason       string `json:"reason"`
}

type approvalResponse struct {
	ID                string `json:"id"`
	IntentDigest      string `json:"intent_digest"`
	Resource          string `json:"resource"`
	Action            string `json:"action"`
	Approver          string `json:"approver"`
	Approvals         int    `json:"approvals"`
	ApprovalCount     int    `json:"approval_count"`
	RequiredApprovals int    `json:"required_approvals"`
	Status            string `json:"status"`
}

type approvalRequestList struct {
	Items      []ApprovalRequestRecord `json:"items"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

func (a *API) listApprovalRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment"))
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !validApprovalStatus(status) {
		a.writeError(w, errStatus(http.StatusBadRequest, "unknown approval request status"))
		return
	}
	lister, ok := a.approvals.(ApprovalRequestLister)
	if !ok {
		a.writeError(w, errStatus(http.StatusNotImplemented, "the genuine approval request queue is not available on this deployment"))
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	var afterCreatedAt *time.Time
	afterID := ""
	if cursor := strings.TrimSpace(r.URL.Query().Get("cursor")); cursor != "" {
		decodedTime, decodedID, decodeErr := decodeApprovalRequestCursor(cursor)
		if decodeErr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		afterCreatedAt, afterID = &decodedTime, decodedID
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	visibility := a.approvalListVisibility(r, principal, tenantID)
	if !visibility.CertificateOperations && !visibility.SecretOperations && !visibility.ManagedKeyOperations {
		a.writeError(w, errStatus(http.StatusForbidden, "forbidden: no approval-review domain is authorized"))
		return
	}
	rows, err := lister.ListApprovalRequests(r.Context(), tenantID, ApprovalRequestListOptions{
		Status: status, AfterCreatedAt: afterCreatedAt, AfterID: afterID, Limit: limit,
		CertificateOperations: visibility.CertificateOperations,
		SecretOperations:      visibility.SecretOperations,
		ManagedKeyOperations:  visibility.ManagedKeyOperations,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]ApprovalRequestRecord, 0, len(rows))
	for _, row := range rows {
		if !a.approvalRecordAuthorized(r, principal, tenantID, row) {
			continue
		}
		items = append(items, row)
		if len(items) == limit {
			break
		}
	}
	next := ""
	if len(rows) == limit && len(rows) > 0 {
		next = encodeApprovalRequestCursor(rows[len(rows)-1])
	}
	a.writeJSON(w, http.StatusOK, approvalRequestList{Items: items, NextCursor: next})
}

// approveApprovalRequest is the canonical reviewer command. The request digest
// is in the body and in the idempotency binding, so reusing the same header for
// a different digest returns a conflict before any decision is appended.
//
//trstctl:mutation
func (a *API) approveApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment"))
		return
	}
	var body approvalDecisionInput
	if err := decodeJSON(r, &body); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated approver is required"))
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: strings.TrimSpace(r.PathValue("id")), IntentDigest: strings.TrimSpace(body.IntentDigest),
		Approver: principal.Subject, Decision: store.ApprovalDecisionApprove,
	}
	record, err := a.preflightApprovalDecision(r, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.authorizeGenericApprovalDecision(r, record, &command); err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := approvalDecisionBinding(command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding,
		func(ctx context.Context, tenantID string) (int, any, error) {
			record, err := a.approvals.RecordApproval(ctx, tenantID, command)
			if err != nil {
				return 0, nil, approvalAPIError(err)
			}
			return http.StatusOK, approvalResponseFor(record, principal.Subject), nil
		})
}

// denyApprovalRequest records one immutable deny decision. It never transitions,
// retires, or otherwise mutates the target resource; the approval projection alone
// becomes denied and can no longer grant execution.
//
//trstctl:mutation
func (a *API) denyApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment"))
		return
	}
	var body approvalDenialInput
	if err := decodeJSON(r, &body); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Reason == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "reason is required for an approval denial"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated reviewer is required"))
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: strings.TrimSpace(r.PathValue("id")), IntentDigest: strings.TrimSpace(body.IntentDigest),
		Approver: principal.Subject, Decision: store.ApprovalDecisionDeny, Reason: body.Reason,
	}
	record, err := a.preflightApprovalDecision(r, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.authorizeGenericApprovalDecision(r, record, &command); err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := approvalDecisionBinding(command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding,
		func(ctx context.Context, tenantID string) (int, any, error) {
			denied, err := a.approvals.RecordApproval(ctx, tenantID, command)
			if err != nil {
				return 0, nil, approvalAPIError(err)
			}
			return http.StatusOK, approvalResponseFor(denied, principal.Subject), nil
		})
}

// approveIdentityAction is the compatibility route. Unlike its pre-AUD-77
// shape it cannot infer authority from identity/action: the caller must carry
// the exact request ID and digest it reviewed, and the recorder verifies that
// request really targets this path and action. A missing exact binding is the
// same tenant-safe 404 as an unknown request and changes no state.
//
//trstctl:mutation
func (a *API) approveIdentityAction(w http.ResponseWriter, r *http.Request) {
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment"))
		return
	}
	var body approvalRequest
	if err := decodeJSON(r, &body); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if !isIdentityApprovalAction(body.Action) {
		a.writeError(w, errStatus(http.StatusBadRequest, `action must be "issue", "rotate", "revoke", or "sign"`))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated approver is required"))
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: strings.TrimSpace(body.RequestID), IntentDigest: strings.TrimSpace(body.IntentDigest),
		Approver: principal.Subject, Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "identity", ExpectedResourceID: r.PathValue("id"),
		ExpectedAction: body.Action,
	}
	if _, err := a.preflightApprovalDecision(r, command); err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := approvalDecisionBinding(command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding,
		func(ctx context.Context, tenantID string) (int, any, error) {
			record, err := a.approvals.RecordApproval(ctx, tenantID, command)
			if err != nil {
				return 0, nil, approvalAPIError(err)
			}
			return http.StatusOK, approvalResponseFor(record, principal.Subject), nil
		})
}

func (a *API) preflightApprovalDecision(r *http.Request, command ApprovalDecisionCommand) (ApprovalRequestRecord, error) {
	if command.RequestID == "" || command.IntentDigest == "" {
		return ApprovalRequestRecord{}, approvalAPIError(store.ErrApprovalRequestNotFound)
	}
	if _, err := googleuuid.Parse(command.RequestID); err != nil {
		return ApprovalRequestRecord{}, approvalAPIError(store.ErrApprovalRequestNotFound)
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		return ApprovalRequestRecord{}, errStatus(http.StatusUnauthorized, "missing or invalid tenant")
	}
	record, err := a.approvals.ValidateApprovalRequest(r.Context(), tenantID, command)
	if err != nil {
		return ApprovalRequestRecord{}, approvalAPIError(err)
	}
	return record, nil
}

type approvalDomainVisibility struct {
	CertificateOperations bool
	SecretOperations      bool
	ManagedKeyOperations  bool
}

func (a *API) approvalListVisibility(r *http.Request, principal authz.Principal, tenantID string) approvalDomainVisibility {
	return approvalDomainVisibility{
		CertificateOperations: a.approvalPermissionAuthorized(r, principal, tenantID, authz.CertsIssue),
		SecretOperations:      a.approvalPermissionAuthorized(r, principal, tenantID, authz.SecretsWrite),
		ManagedKeyOperations:  a.approvalPermissionAuthorized(r, principal, tenantID, authz.KeysApprove),
	}
}

func (a *API) approvalRecordAuthorized(r *http.Request, principal authz.Principal, tenantID string, record ApprovalRequestRecord) bool {
	permission, ok := approvalRecordPermission(record.ResourceKind, record.Action)
	return ok && a.approvalPermissionAuthorized(r, principal, tenantID, permission)
}

func (a *API) approvalPermissionAuthorized(r *http.Request, principal authz.Principal, tenantID string, permission authz.Permission) bool {
	target := authz.Scope{TenantID: tenantID}
	return principal.Can(permission, target) && a.checkABAC(r.Context(), r, principal, permission, target) == nil
}

func (a *API) authorizeGenericApprovalDecision(r *http.Request, record ApprovalRequestRecord, command *ApprovalDecisionCommand) error {
	tenantID, ok := a.tenant(r)
	if !ok {
		return errStatus(http.StatusUnauthorized, "missing or invalid tenant")
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	permission, mapped := approvalRecordPermission(record.ResourceKind, record.Action)
	if !mapped || !a.approvalPermissionAuthorized(r, principal, tenantID, permission) {
		return errStatus(http.StatusForbidden, "forbidden: approval request belongs to another review domain")
	}
	// The preflight supplies the immutable target shown to the reviewer. Copy it
	// into the command so RecordApproval rechecks the exact kind/resource/action
	// under its request-row lock before appending the decision.
	command.ExpectedResourceKind = record.ResourceKind
	command.ExpectedResourceID = record.ResourceID
	command.ExpectedAction = record.Action
	return nil
}

func approvalRecordPermission(resourceKind, action string) (authz.Permission, bool) {
	switch resourceKind {
	case "identity":
		return authz.CertsIssue, action == "issue" || action == "rotate" || action == "revoke" || action == "sign"
	case "ephemeral":
		return authz.CertsIssue, action == "issue"
	case "code_signing":
		return authz.CertsIssue, action == "sign"
	case "secret":
		return authz.SecretsWrite, action == "create" || action == "rotate" || action == "recover" || action == "delete"
	case "managed_key":
		return authz.KeysApprove, action == ManagedKeyActionRotate || action == ManagedKeyActionRevoke || action == ManagedKeyActionZeroize
	default:
		return "", false
	}
}

func encodeApprovalRequestCursor(record ApprovalRequestRecord) string {
	return base64.RawURLEncoding.EncodeToString([]byte(record.CreatedAt + "\x00" + record.ID))
}

func decodeApprovalRequestCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", err
	}
	createdAt, id, ok := strings.Cut(string(raw), "\x00")
	if !ok {
		return time.Time{}, "", errors.New("approval cursor is incomplete")
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return time.Time{}, "", err
	}
	if _, err := googleuuid.Parse(id); err != nil {
		return time.Time{}, "", err
	}
	return parsed.UTC(), id, nil
}

func approvalResponseFor(record ApprovalRequestRecord, approver string) approvalResponse {
	return approvalResponse{
		ID: record.ID, IntentDigest: record.IntentDigest, Resource: record.ResourceID,
		Action: record.Action, Approver: approver, Approvals: record.ApprovalCount,
		ApprovalCount: record.ApprovalCount, RequiredApprovals: record.RequiredApprovals,
		Status: record.Status,
	}
}

func approvalDecisionBinding(command ApprovalDecisionCommand) (string, error) {
	raw, err := json.Marshal(struct {
		Domain  string                  `json:"domain"`
		Command ApprovalDecisionCommand `json:"command"`
	}{Domain: "trstctl.api.operation-approval-decision.v1", Command: command})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}

func approvalAPIError(err error) error {
	switch {
	case errors.Is(err, store.ErrApprovalRequestNotFound), errors.Is(err, store.ErrApprovalDigestMismatch):
		return errStatus(http.StatusNotFound, "resource not found")
	case errors.Is(err, store.ErrApprovalSelfDecision), errors.Is(err, store.ErrSelfIssuanceApproval):
		return errStatus(http.StatusForbidden, "approval requester cannot approve their own request")
	case errors.Is(err, store.ErrApprovalExpired):
		return errStatus(http.StatusConflict, "approval request expired")
	case errors.Is(err, store.ErrApprovalSuperseded):
		return errStatus(http.StatusConflict, "approval request superseded")
	case errors.Is(err, store.ErrApprovalConsumed):
		return errStatus(http.StatusConflict, "approval authority already consumed")
	case errors.Is(err, store.ErrApprovalDrifted):
		return errStatus(http.StatusConflict, "approval target version or state drifted")
	case errors.Is(err, store.ErrApprovalNotReady):
		return errStatus(http.StatusConflict, "approval request has not reached quorum")
	default:
		return err
	}
}

func validApprovalStatus(status string) bool {
	switch status {
	case store.ApprovalStatusPending, store.ApprovalStatusApproved,
		store.ApprovalStatusDenied, store.ApprovalStatusExpired,
		store.ApprovalStatusSuperseded, store.ApprovalStatusConsumed:
		return true
	default:
		return false
	}
}

var identityApprovalActions = []string{"issue", "rotate", "revoke", "sign"}

func isIdentityApprovalAction(action string) bool {
	for _, allowed := range identityApprovalActions {
		if action == allowed {
			return true
		}
	}
	return false
}
