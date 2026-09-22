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
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type issuanceRequestBody struct {
	Subject       string `json:"subject"`
	OwnerID       string `json:"owner_id"`
	Profile       string `json:"profile"`
	CSRPEM        string `json:"csr_pem"`
	Justification string `json:"justification"`
	// Origin and TicketRef let a ticket-driven intake say where it came from.
	// An unrecorded origin stays empty rather than defaulting to "api": as with
	// owner provenance, absence must not be dressed up as an answer.
	Origin    string `json:"origin"`
	TicketRef string `json:"ticket_ref"`
}

type issuanceDecisionBody struct {
	Reason     string `json:"reason"`
	IdentityID string `json:"identity_id"`
}

type issuanceRequestResponse struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	Subject        string `json:"subject"`
	OwnerID        string `json:"owner_id,omitempty"`
	Profile        string `json:"profile,omitempty"`
	Requester      string `json:"requester"`
	Justification  string `json:"justification,omitempty"`
	Origin         string `json:"origin,omitempty"`
	TicketRef      string `json:"ticket_ref,omitempty"`
	Status         string `json:"status"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecisionReason string `json:"decision_reason,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	IdentityID     string `json:"identity_id,omitempty"`
	IssuedBy       string `json:"issued_by,omitempty"`
	IssuedAt       string `json:"issued_at,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
}

type issuanceRequestPreparationResponse struct {
	Request             issuanceRequestResponse `json:"request"`
	Identity            identityResponse        `json:"identity"`
	CSRPEM              string                  `json:"csr_pem,omitempty"`
	IssueIdempotencyKey string                  `json:"issue_idempotency_key"`
}

// issuanceRequestPreviewResponse is the effect-free answer to "can this exact
// request be opened safely?" It deliberately exposes only public/operational
// metadata. A CSR is public, but echoing it would add no decision value and would
// expand browser/evidence exposure, so only its presence and custody mode appear.
type issuanceRequestPreviewResponse struct {
	Ready                  bool     `json:"ready"`
	Subject                string   `json:"subject"`
	OwnerID                string   `json:"owner_id"`
	OwnerName              string   `json:"owner_name,omitempty"`
	OwnerKind              string   `json:"owner_kind,omitempty"`
	Profile                string   `json:"profile,omitempty"`
	ProfileName            string   `json:"profile_name,omitempty"`
	ProfileVersion         int      `json:"profile_version,omitempty"`
	Requester              string   `json:"requester"`
	CSRSupplied            bool     `json:"csr_supplied"`
	KeyOrigin              string   `json:"key_origin"`
	ApprovalRequired       bool     `json:"approval_required"`
	ApprovalPermission     string   `json:"approval_permission"`
	IssuancePermissions    []string `json:"issuance_permissions"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	SubmissionEffects      []string `json:"submission_effects"`
	Steps                  []string `json:"steps"`
	Warnings               []string `json:"warnings"`
	Blockers               []string `json:"blockers"`
	Guidance               string   `json:"guidance"`
}

type issuanceRequestList struct {
	Items []issuanceRequestResponse `json:"items"`
	// Open is counted separately from the total. A single number cannot tell an
	// operator whether the queue needs attention or is just long with history.
	Open     int    `json:"open"`
	Guidance string `json:"guidance"`
}

const issuanceRequestGuidance = "A request has a real lifecycle: requested, then approved, denied, " +
	"expired, or canceled — and approved is not the end, because issuance can still fail. Denial " +
	"and expiry are deliberately different: a denial is somebody's decision with a reason, an expiry " +
	"is nobody's. A requester can withdraw their own request and can never decide it; self-approval " +
	"would leave an approval record that looks legitimate while nobody independent ever looked."

// The CSR is public material. This response deliberately does NOT echo it back:
// it is large, it is already in the request the caller sent, and a list endpoint
// that returns every CSR makes an inventory of pending key material's public
// halves available to anyone who can list.
func toIssuanceRequestResponse(r store.IssuanceRequest) issuanceRequestResponse {
	out := issuanceRequestResponse{
		ID: r.ID, TenantID: r.TenantID, Subject: r.Subject, OwnerID: r.OwnerID, Profile: r.Profile,
		Requester: r.Requester, Justification: r.Justification, Origin: r.Origin,
		TicketRef: r.TicketRef, Status: r.Status, DecidedBy: r.DecidedBy,
		DecisionReason: r.DecisionReason, IdentityID: r.IdentityID,
		IssuedBy:  r.IssuedBy,
		ExpiresAt: r.ExpiresAt.UTC().Format(time.RFC3339),
		CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.DecidedAt != nil {
		out.DecidedAt = r.DecidedAt.UTC().Format(time.RFC3339)
	}
	if r.IssuedAt != nil {
		out.IssuedAt = r.IssuedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// principalSubject reads the authenticated caller. Empty means unauthenticated,
// and every caller here treats that as fatal rather than as an anonymous
// requester: a request with no requester makes the self-approval check compare
// an empty string to an empty string and pass.
func principalSubject(ctx context.Context) string {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok {
		return ""
	}
	return principal.Subject
}

func (a *API) issuanceRequestPreview(ctx context.Context, tenantID string, body issuanceRequestBody) (issuanceRequestPreviewResponse, error) {
	subject := strings.TrimSpace(body.Subject)
	if subject == "" {
		return issuanceRequestPreviewResponse{}, errStatus(http.StatusBadRequest, "subject is required")
	}
	ownerID, err := validateOwnerID(body.OwnerID)
	if err != nil {
		return issuanceRequestPreviewResponse{}, err
	}
	requester := principalSubject(ctx)
	if requester == "" {
		return issuanceRequestPreviewResponse{}, errStatus(http.StatusUnauthorized,
			"an issuance request must name its requester; without one the self-approval check has nothing to compare")
	}
	csrPEM := strings.TrimSpace(body.CSRPEM)
	if csrPEM != "" {
		if err := a.validateSubjectCSRPEM(csrPEM); err != nil {
			return issuanceRequestPreviewResponse{}, errStatus(http.StatusBadRequest, err.Error())
		}
	}

	preview := issuanceRequestPreviewResponse{
		Subject: subject, OwnerID: ownerID, Requester: requester, CSRSupplied: csrPEM != "",
		KeyOrigin: "requester_csr", ApprovalRequired: true,
		ApprovalPermission:  string(authz.CertsIssue),
		IssuancePermissions: []string{string(authz.IdentitiesWrite), string(authz.CertsIssue)},
		PreviewWrites:       []string{}, PreviewExternalEffects: []string{},
		SubmissionEffects: []string{
			"Append one tenant-scoped issuance.request.opened event.",
			"Project one request in requested state for an independent approver.",
			"Mint no certificate; approval and signer-backed issuance remain later, separate steps.",
		},
		Steps: []string{
			"Submit this exact request.",
			"A different principal with certs:issue approves or denies it.",
			"An issuer prepares one deterministic identity and reuses one stable issuance key.",
			"The request becomes issued only after matching signer-backed certificate evidence exists.",
		},
		Warnings: []string{}, Blockers: []string{},
		Guidance: "This preview performed no write and contacted no certificate authority. Submitting opens a request only; it does not approve or mint a certificate.",
	}
	if csrPEM == "" {
		preview.KeyOrigin = "deprecated_control_plane_generation"
		preview.Warnings = append(preview.Warnings,
			"No CSR was supplied. A later compatibility path may generate a private key inside the control plane; use a requester-generated CSR to keep the private key on the machine.")
	}

	owner, err := a.store.GetOwner(ctx, tenantID, ownerID)
	if err != nil {
		if store.IsNotFound(err) {
			preview.Blockers = append(preview.Blockers,
				"owner_id does not reference an existing owner")
		} else {
			return issuanceRequestPreviewResponse{}, err
		}
	} else {
		preview.OwnerName = owner.Name
		preview.OwnerKind = string(owner.Kind)
	}

	binding := strings.TrimSpace(body.Profile)
	if binding != "" {
		profileName, profileVersion, resolveErr := a.orch.ResolveIssuanceRequestProfileBinding(ctx, tenantID, binding)
		if resolveErr != nil {
			if errors.Is(resolveErr, orchestrator.ErrIssuanceRequestNotReady) || store.IsNotFound(resolveErr) {
				preview.Blockers = append(preview.Blockers, issuanceRequestBlocker(resolveErr))
			} else {
				return issuanceRequestPreviewResponse{}, resolveErr
			}
		} else {
			preview.ProfileName, preview.ProfileVersion = profileName, profileVersion
			preview.Profile = profileName + ":" + strconv.Itoa(profileVersion)
		}
	} else {
		preview.Warnings = append(preview.Warnings,
			"No certificate profile was pinned. This compatibility request has no versioned certificate rule; normal console requests should select one.")
	}
	preview.Ready = len(preview.Blockers) == 0
	return preview, nil
}

func issuanceRequestBlocker(err error) string {
	const prefix = "orchestrator: issuance request is not ready: "
	message := strings.TrimSpace(err.Error())
	message = strings.TrimPrefix(message, prefix)
	return message
}

func (a *API) previewIssuanceRequest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var body issuanceRequestBody
	if err := decodeJSON(r, &body); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	preview, err := a.issuanceRequestPreview(r.Context(), tenantID, body)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

func (a *API) createIssuanceRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body issuanceRequestBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		preview, err := a.issuanceRequestPreview(ctx, tenantID, body)
		if err != nil {
			return 0, nil, err
		}
		if !preview.Ready {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, strings.Join(preview.Blockers, "; "))
		}
		out, err := a.orch.OpenIssuanceRequest(ctx, tenantID, projections.IssuanceRequestOpened{
			Subject: preview.Subject, OwnerID: preview.OwnerID, Profile: preview.Profile,
			CSRPEM: strings.TrimSpace(body.CSRPEM), Requester: preview.Requester,
			Justification: strings.TrimSpace(body.Justification),
			Origin:        strings.TrimSpace(body.Origin), TicketRef: strings.TrimSpace(body.TicketRef),
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toIssuanceRequestResponse(out), nil
	})
}

func (a *API) listIssuanceRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !validIssuanceState(status) {
		a.writeError(w, errStatus(http.StatusBadRequest,
			"status must be one of: "+strings.Join(issuancerequest.States, ", ")))
		return
	}
	rows, err := a.store.ListIssuanceRequests(r.Context(), tenantID, status, 200)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := issuanceRequestList{Items: []issuanceRequestResponse{}, Guidance: issuanceRequestGuidance}
	for _, row := range rows {
		if row.Status == issuancerequest.StateRequested {
			out.Open++
		}
		out.Items = append(out.Items, toIssuanceRequestResponse(row))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func validIssuanceState(s string) bool {
	for _, v := range issuancerequest.States {
		if v == s {
			return true
		}
	}
	return false
}

// decideIssuanceRequest handles approve / deny / cancel through one path, so the
// transition rules cannot be enforced in one handler and forgotten in another.
func (a *API) decideIssuanceRequest(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
			var body issuanceDecisionBody
			if r.ContentLength > 0 {
				if err := decodeJSON(r, &body); err != nil {
					return 0, nil, errWithStatus(http.StatusBadRequest, err)
				}
			}
			if to == issuancerequest.StateDenied && strings.TrimSpace(body.Reason) == "" {
				// A denial with no reason is the thing that makes people stop
				// using a request queue: the requester learns only that somebody
				// said no, and re-asks.
				return 0, nil, errStatus(http.StatusBadRequest,
					"a denial needs a reason; without one the requester learns only that somebody said no and will simply ask again")
			}
			out, err := a.orch.DecideIssuanceRequest(ctx, tenantID, r.PathValue("id"), to,
				principalSubject(ctx), strings.TrimSpace(body.Reason), strings.TrimSpace(body.IdentityID))
			if err != nil {
				return 0, nil, err
			}
			return http.StatusOK, toIssuanceRequestResponse(out), nil
		})
	}
}

func (a *API) prepareIssuanceRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		request, identity, err := a.orch.PrepareIssuanceRequest(ctx, tenantID, r.PathValue("id"), principalSubject(ctx))
		if err != nil {
			if errors.Is(err, orchestrator.ErrIssuanceRequestNotReady) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			return 0, nil, err
		}
		return http.StatusOK, issuanceRequestPreparationResponse{
			Request: toIssuanceRequestResponse(request), Identity: toIdentityResponse(identity),
			CSRPEM:              request.CSRPEM,
			IssueIdempotencyKey: orchestrator.IssuanceRequestIssueIdempotencyKey(request.ID),
		}, nil
	})
}

func (a *API) completeIssuanceRequest(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		request, err := a.orch.CompleteIssuanceRequest(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			if errors.Is(err, orchestrator.ErrIssuanceRequestNotReady) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			return 0, nil, err
		}
		return http.StatusOK, toIssuanceRequestResponse(request), nil
	})
}
