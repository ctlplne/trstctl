// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/accessweb"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// A258: reusable access templates and audited emergency access.

// PAMAccessTemplate is a reusable access template: the reason a session
// request records, the approvals it needs (never fewer than the
// deployment's) and the longest session it allows.
type PAMAccessTemplate struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Reason            string `json:"reason"`
	RequiredApprovals int    `json:"required_approvals"`
	MaxTTLSeconds     int    `json:"max_ttl_seconds"`
	// RequireRecording (A261 part 3) refuses a session through the template
	// that would not be recorded, and every check-out.
	RequireRecording bool `json:"require_recording"`
	// DesktopClipboard (A269) is the remote desktop clipboard policy a reviewed
	// session through the template gets: deny (the default), to_target,
	// from_target or both.
	DesktopClipboard string             `json:"desktop_clipboard,omitempty"`
	CommandRules     []accessrules.Rule `json:"command_rules,omitempty"`
	// WebSignIn (A273) is how the gateway signs in to a web console for a
	// session through the template.
	WebSignIn *accessweb.SignIn `json:"web_sign_in,omitempty"`
	Revision  int64             `json:"revision"`
	SavedBy   string            `json:"saved_by,omitempty"`
	SavedAt   time.Time         `json:"saved_at"`
}

// PAMEmergencyGrant is a session a named responder opened without waiting
// for approval, with the post-incident review it requires.
type PAMEmergencyGrant struct {
	SessionID  string             `json:"session_id"`
	Responder  string             `json:"responder"`
	Reason     string             `json:"reason"`
	TargetType string             `json:"target_type"`
	TargetID   string             `json:"target_id"`
	Role       string             `json:"role"`
	OpenedAt   time.Time          `json:"opened_at"`
	ExpiresAt  time.Time          `json:"expires_at"`
	Review     PAMEmergencyReview `json:"review"`
}

// PAMEmergencyReview is an emergency grant's post-incident review.
type PAMEmergencyReview struct {
	Status     string     `json:"status"`
	Reviewer   string     `json:"reviewer,omitempty"`
	Outcome    string     `json:"outcome,omitempty"`
	Notes      string     `json:"notes,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
}

// PAMTemplateService keeps access templates; the served broker implements it.
type PAMTemplateService interface {
	SavePAMTemplate(ctx context.Context, tenantID, actor string, t PAMAccessTemplate) (PAMAccessTemplate, error)
	ListPAMTemplates(ctx context.Context, tenantID string) ([]PAMAccessTemplate, error)
	GetPAMTemplate(ctx context.Context, tenantID, id string) (PAMAccessTemplate, error)
	DeletePAMTemplate(ctx context.Context, tenantID, id, actor string) error
}

// PAMEmergencyService is emergency access; the served broker implements it.
type PAMEmergencyService interface {
	SetPAMEmergencyResponders(ctx context.Context, tenantID, actor string, subjects []string) ([]string, error)
	ListPAMEmergencyResponders(ctx context.Context, tenantID string) ([]string, error)
	OpenPAMEmergencySession(ctx context.Context, tenantID, idempotencyKey, responder string, req PAMSessionRequest) (PAMSession, error)
	ListPAMEmergencyGrants(ctx context.Context, tenantID string) ([]PAMEmergencyGrant, error)
	ReviewPAMEmergencyGrant(ctx context.Context, tenantID, sessionID, reviewer, outcome, notes string) (PAMEmergencyGrant, error)
}

func (a *API) pamTemplateRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "GET", path: "/api/v1/access/templates", opID: "listPAMTemplates", summary: "List access templates: the reason, approvals and maximum length a session request can take from one", handler: a.listPAMTemplates, resSchema: "PAMAccessTemplateList", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/templates", opID: "createPAMTemplate", summary: "Create an access template", handler: a.savePAMTemplate, reqSchema: "PAMAccessTemplateRequest", resSchema: "PAMAccessTemplate", successCode: "201", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/templates/{id}", opID: "getPAMTemplate", summary: "Get an access template", handler: a.getPAMTemplate, pathParams: idPath, resSchema: "PAMAccessTemplate", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/templates/{id}", opID: "updatePAMTemplate", summary: "Replace an access template at the revision you read; requests already under review keep what they were reviewed with", handler: a.savePAMTemplate, pathParams: idPath, reqSchema: "PAMAccessTemplateRequest", resSchema: "PAMAccessTemplate", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "DELETE", path: "/api/v1/access/templates/{id}", opID: "deletePAMTemplate", summary: "Delete an access template; requests naming it are refused from then on", handler: a.deletePAMTemplate, pathParams: idPath, resSchema: "PAMAccessTemplateDeleted", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/emergency/responders", opID: "listPAMEmergencyResponders", summary: "List the named responders who may open emergency access", handler: a.listPAMEmergencyResponders, resSchema: "PAMEmergencyResponders", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/emergency/responders", opID: "setPAMEmergencyResponders", summary: "Replace the named responders who may open emergency access", handler: a.setPAMEmergencyResponders, reqSchema: "PAMEmergencyResponders", resSchema: "PAMEmergencyResponders", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/access/emergency-sessions", opID: "openPAMEmergencySession", summary: "Open a privileged session at once as a named responder: every approver is notified, it ends at its short deadline and requires a post-incident review", handler: a.openPAMEmergencySession, reqSchema: "PAMEmergencySessionRequest", resSchema: "PAMSession", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessSessionsOpen},
		{method: "GET", path: "/api/v1/access/emergency-sessions", opID: "listPAMEmergencyGrants", summary: "List emergency access grants, newest first, with their post-incident reviews", handler: a.listPAMEmergencyGrants, resSchema: "PAMEmergencyGrantList", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/emergency-sessions/{id}/review", opID: "reviewPAMEmergencyGrant", summary: "Record an emergency grant's post-incident review; its responder cannot review it", handler: a.reviewPAMEmergencyGrant, pathParams: idPath, reqSchema: "PAMEmergencyReviewRequest", resSchema: "PAMEmergencyGrant", successCode: "200", mutation: true, perm: authz.AccessApprove},
	}
}

func (a *API) templates() (PAMTemplateService, error) {
	svc, ok := a.pam.(PAMTemplateService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func (a *API) emergency() (PAMEmergencyService, error) {
	svc, ok := a.pam.(PAMEmergencyService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func pamTemplateNotFound(err error) error {
	if errors.Is(err, store.ErrPAMTemplateNotFound) {
		return errStatus(http.StatusNotFound, "access template not found")
	}
	return err
}

func (a *API) listPAMTemplates(w http.ResponseWriter, r *http.Request) {
	svc, err := a.templates()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMTemplates(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getPAMTemplate(w http.ResponseWriter, r *http.Request) {
	svc, err := a.templates()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	item, err := svc.GetPAMTemplate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, pamTemplateNotFound(err))
		return
	}
	a.writeJSON(w, http.StatusOK, item)
}

//trstctl:mutation
func (a *API) savePAMTemplate(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.templates()
		if err != nil {
			return 0, nil, err
		}
		var body PAMAccessTemplate
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		status := http.StatusCreated
		body.ID = ""
		if id := r.PathValue("id"); id != "" {
			body.ID, status = id, http.StatusOK
		}
		item, err := svc.SavePAMTemplate(ctx, tenantID, principal.Subject, body)
		if err != nil {
			return 0, nil, pamTemplateNotFound(err)
		}
		return status, item, nil
	})
}

//trstctl:mutation
func (a *API) deletePAMTemplate(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.templates()
		if err != nil {
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if err := svc.DeletePAMTemplate(ctx, tenantID, r.PathValue("id"), principal.Subject); err != nil {
			return 0, nil, pamTemplateNotFound(err)
		}
		return http.StatusOK, map[string]any{"id": r.PathValue("id"), "deleted": true}, nil
	})
}

func (a *API) listPAMEmergencyResponders(w http.ResponseWriter, r *http.Request) {
	svc, err := a.emergency()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	subjects, err := svc.ListPAMEmergencyResponders(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"subjects": subjects})
}

//trstctl:mutation
func (a *API) setPAMEmergencyResponders(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.emergency()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Subjects []string `json:"subjects"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		subjects, err := svc.SetPAMEmergencyResponders(ctx, tenantID, principal.Subject, body.Subjects)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"subjects": subjects}, nil
	})
}

//trstctl:mutation
func (a *API) openPAMEmergencySession(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.emergency()
		if err != nil {
			return 0, nil, err
		}
		req, err := decodePAMSessionRequest(r)
		if err != nil {
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		switch {
		case principal.Subject == "":
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated responder is required")
		case principal.RunID != "":
			// A run acts for its principal under bundles; emergency access
			// belongs to a named person, never to something acting for one.
			return 0, nil, errStatus(http.StatusForbidden, "an access bundle run cannot open emergency access")
		case principal.Delegated:
			return 0, nil, errStatus(http.StatusForbidden, "a token minted for another principal cannot open emergency access")
		}
		session, err := svc.OpenPAMEmergencySession(ctx, tenantID, r.Header.Get("Idempotency-Key"), principal.Subject, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, session, nil
	})
}

func (a *API) listPAMEmergencyGrants(w http.ResponseWriter, r *http.Request) {
	svc, err := a.emergency()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMEmergencyGrants(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) reviewPAMEmergencyGrant(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.emergency()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Outcome string `json:"outcome"`
			Notes   string `json:"notes"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Delegated {
			return 0, nil, errStatus(http.StatusForbidden, "a token minted for another principal cannot review emergency access")
		}
		grant, err := svc.ReviewPAMEmergencyGrant(ctx, tenantID, r.PathValue("id"), principal.Subject, strings.TrimSpace(body.Outcome), body.Notes)
		if errors.Is(err, store.ErrPAMEmergencyGrantNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "emergency grant not found")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, grant, nil
	})
}
