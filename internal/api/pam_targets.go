// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

type pamTargetRequest struct {
	ID           string   `json:"id"`
	TargetType   string   `json:"target_type"`
	ProviderID   string   `json:"provider_id,omitempty"`
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	Host         string   `json:"host,omitempty"`
	Port         int      `json:"port,omitempty"`
	Principals   []string `json:"principals,omitempty"`
}

//trstctl:mutation
func (a *API) registerPAMTarget(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pam == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var body pamTargetRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated registrar required")
		}
		created, err := a.pam.RegisterPAMTarget(ctx, tenantID, principal.Subject, PAMTarget{
			ID: strings.TrimSpace(body.ID), TargetType: strings.TrimSpace(body.TargetType),
			ProviderID: strings.TrimSpace(body.ProviderID), AllowedRoles: body.AllowedRoles,
			Host: strings.TrimSpace(body.Host), Port: body.Port, Principals: body.Principals,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, created, nil
	})
}

func (a *API) listPAMTargets(w http.ResponseWriter, r *http.Request) {
	if a.pam == nil {
		a.writeError(w, ErrPAMUnavailable)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := a.pam.ListPAMTargets(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		Items []PAMTarget `json:"items"`
	}{Items: items})
}

func (a *API) getPAMTarget(w http.ResponseWriter, r *http.Request) {
	if a.pam == nil {
		a.writeError(w, ErrPAMUnavailable)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	item, err := a.pam.GetPAMTarget(r.Context(), tenantID, r.PathValue("target_type"), r.PathValue("id"))
	if errors.Is(err, store.ErrPAMTargetNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "PAM target not found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, item)
}

//trstctl:mutation
func (a *API) disablePAMTarget(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pam == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated registrar required")
		}
		item, err := a.pam.DisablePAMTarget(ctx, tenantID, r.PathValue("target_type"), r.PathValue("id"), principal.Subject, body.Reason)
		if errors.Is(err, store.ErrPAMTargetNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "PAM target not found")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, item, nil
	})
}
