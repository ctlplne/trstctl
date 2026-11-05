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
	// GatewayAgentID and GatewayAddress bind the target to a gateway (A254).
	GatewayAgentID string `json:"gateway_agent_id,omitempty"`
	GatewayAddress string `json:"gateway_address,omitempty"`
	// HostKeyFingerprints pin a gateway-bound SSH target's host keys.
	HostKeyFingerprints []string `json:"host_key_fingerprints,omitempty"`
	// AccountSecret makes a database target vaulted (A261).
	AccountSecret string `json:"account_secret,omitempty"`
	// Folder places the target in a folder (A261 part 3).
	Folder string `json:"folder,omitempty"`
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
			GatewayAgentID: strings.TrimSpace(body.GatewayAgentID), GatewayAddress: strings.TrimSpace(body.GatewayAddress),
			HostKeyFingerprints: body.HostKeyFingerprints, AccountSecret: strings.TrimSpace(body.AccountSecret),
			Folder: strings.TrimSpace(body.Folder),
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

// checkPAMTargetHealth signs in once now with the credential a target's
// provider holds (A258): after an operator repairs an account, a credential
// the server refused before is tried again.
//
//trstctl:mutation
func (a *API) checkPAMTargetHealth(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		checker, ok := a.pam.(PAMAccountHealthChecker)
		if a.pam == nil || !ok {
			return 0, nil, ErrPAMUnavailable
		}
		item, err := checker.CheckPAMAccountHealth(ctx, tenantID, r.PathValue("target_type"), r.PathValue("id"))
		if errors.Is(err, store.ErrPAMTargetNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "PAM target not found")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, item, nil
	})
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
