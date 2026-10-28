// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

type SSHTrustFleetPreviewInput struct {
	Name        string   `json:"name"`
	Reason      string   `json:"reason"`
	PublicCAKey string   `json:"public_ca_key"`
	AgentIDs    []string `json:"agent_ids"`
}

type SSHTrustFleetPlanInput struct {
	Plan       sshtrustrollout.Plan `json:"plan"`
	PlanDigest string               `json:"plan_digest"`
}

type SSHTrustFleetPreview struct {
	SSHTrustFleetPlanInput
	ReadyHosts     int  `json:"ready_hosts"`
	SkippedHosts   int  `json:"skipped_hosts"`
	EffectFree     bool `json:"effect_free"`
	JobKindEnabled bool `json:"job_kind_enabled"`
}

type SSHTrustFleetApproval struct {
	SSHTrustFleetPlanInput
	ApprovalRequestID    string    `json:"approval_request_id"`
	ApprovalIntentDigest string    `json:"approval_intent_digest"`
	Status               string    `json:"status"`
	RequiredApprovals    int       `json:"required_approvals"`
	ApprovalCount        int       `json:"approval_count"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type SSHTrustFleetStartInput struct {
	SSHTrustFleetPlanInput
	ApprovalRequestID    string `json:"approval_request_id"`
	ApprovalIntentDigest string `json:"approval_intent_digest"`
}

type SSHTrustFleetList struct {
	Items      []store.SSHTrustFleetRollout `json:"items"`
	NextCursor string                       `json:"next_cursor,omitempty"`
}

type SSHTrustFleetService interface {
	PreviewSSHTrustFleet(context.Context, string, SSHTrustFleetPreviewInput) (SSHTrustFleetPreview, error)
	RequestSSHTrustFleetApproval(context.Context, string, string, SSHTrustFleetPlanInput) (SSHTrustFleetApproval, error)
	StartSSHTrustFleet(context.Context, string, string, SSHTrustFleetStartInput) (store.SSHTrustFleetRollout, error)
	GetSSHTrustFleetRollout(context.Context, string, string) (store.SSHTrustFleetRollout, error)
	ListSSHTrustFleetRollouts(context.Context, string, *time.Time, string, int) ([]store.SSHTrustFleetRollout, error)
}

func WithSSHTrustFleet(service SSHTrustFleetService) Option {
	return func(c *config) { c.sshTrustFleet = service }
}

func (a *API) previewSSHTrustFleet(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.sshTrustFleet == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "SSH trust fleet execution is not configured"))
		return
	}
	var input SSHTrustFleetPreviewInput
	if err := decodeJSONWithLimitOptions(r, &input, 128<<10, true); err != nil {
		a.writeError(w, err)
		return
	}
	result, err := a.sshTrustFleet.PreviewSSHTrustFleet(r.Context(), tenantID, input)
	if err != nil {
		a.writeSSHTrustFleetError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

//trstctl:mutation
func (a *API) requestSSHTrustFleetApproval(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	var input SSHTrustFleetPlanInput
	if err := decodeJSONWithLimit(r, &input, 128<<10); err != nil {
		a.writeError(w, err)
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	raw, err := json.Marshal(input)
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex(append([]byte("ssh-trust-fleet-approval\x00"+subject+"\x00"), raw...))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshTrustFleet == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "SSH trust fleet execution is not configured")
		}
		result, err := a.sshTrustFleet.RequestSSHTrustFleetApproval(ctx, tenantID, subject, input)
		return http.StatusCreated, result, sshTrustFleetAPIError(err)
	})
}

//trstctl:mutation
func (a *API) startSSHTrustFleet(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	var input SSHTrustFleetStartInput
	if err := decodeJSONWithLimit(r, &input, 128<<10); err != nil {
		a.writeError(w, err)
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	raw, err := json.Marshal(input)
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex(append([]byte("ssh-trust-fleet-start\x00"+subject+"\x00"), raw...))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshTrustFleet == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "SSH trust fleet execution is not configured")
		}
		result, err := a.sshTrustFleet.StartSSHTrustFleet(ctx, tenantID, subject, input)
		return http.StatusAccepted, result, sshTrustFleetAPIError(err)
	})
}

func (a *API) getSSHTrustFleetRollout(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.sshTrustFleet == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "SSH trust fleet execution is not configured"))
		return
	}
	id, err := googleuuid.Parse(r.PathValue("id"))
	if err != nil || id == googleuuid.Nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "rollout id must be a UUID"))
		return
	}
	result, err := a.sshTrustFleet.GetSSHTrustFleetRollout(r.Context(), tenantID, id.String())
	if err != nil {
		a.writeSSHTrustFleetError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func (a *API) listSSHTrustFleetRollouts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.sshTrustFleet == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "SSH trust fleet execution is not configured"))
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	var after *time.Time
	afterID := ""
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		at, id, err := decodeApprovalRequestCursor(cursor)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid SSH trust rollout cursor"))
			return
		}
		after = &at
		afterID = id
	}
	rows, err := a.sshTrustFleet.ListSSHTrustFleetRollouts(r.Context(), tenantID, after, afterID, limit)
	if err != nil {
		a.writeSSHTrustFleetError(w, err)
		return
	}
	out := SSHTrustFleetList{Items: rows}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		out.NextCursor = encodeApprovalRequestCursor(ApprovalRequestRecord{ID: last.ID, CreatedAt: last.CreatedAt.UTC().Format(time.RFC3339Nano)})
	}
	a.writeJSON(w, http.StatusOK, out)
}

func sshTrustFleetAPIError(err error) error {
	if errors.Is(err, ErrSSHWorkflowUnavailable) {
		return errStatus(http.StatusServiceUnavailable, strings.TrimPrefix(err.Error(), ErrSSHWorkflowUnavailable.Error()+": "))
	}
	if errors.Is(err, store.ErrSSHTrustFleetNotFound) {
		return errStatus(http.StatusNotFound, "no such SSH trust fleet rollout")
	}
	if errors.Is(err, ErrSSHWorkflowInvalid) {
		return errStatus(http.StatusUnprocessableEntity, err.Error())
	}
	return approvalAPIError(err)
}
func (a *API) writeSSHTrustFleetError(w http.ResponseWriter, err error) {
	a.writeError(w, sshTrustFleetAPIError(err))
}
