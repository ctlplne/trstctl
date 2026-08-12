// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

type ownershipExceptionRequest struct {
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ownershipExceptionRevokeRequest struct {
	Reason string `json:"reason"`
}

type ownershipExceptionResponse struct {
	ID               string     `json:"id"`
	IdentityID       string     `json:"identity_id"`
	Reason           string     `json:"reason"`
	GrantedBy        string     `json:"granted_by"`
	GrantedAt        time.Time  `json:"granted_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	Active           bool       `json:"active"`
}

func toOwnershipExceptionResponse(exception store.OwnershipException) ownershipExceptionResponse {
	return ownershipExceptionResponse{
		ID: exception.ID, IdentityID: exception.IdentityID, Reason: exception.Reason,
		GrantedBy: exception.GrantedBy, GrantedAt: exception.GrantedAt, ExpiresAt: exception.ExpiresAt,
		RevokedBy: exception.RevokedBy, RevokedAt: exception.RevokedAt,
		RevocationReason: exception.RevocationReason, Active: exception.Active(time.Now().UTC()),
	}
}

//trstctl:mutation
func (a *API) attestOwner(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		attestor := principalSubject(ctx)
		if strings.TrimSpace(attestor) == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated ownership attestor is required")
		}
		owner, err := a.orch.AttestOwnership(ctx, tenantID, r.PathValue("id"), attestor)
		if err != nil {
			if store.IsNotFound(err) {
				return 0, nil, err
			}
			return 0, nil, errWithStatus(http.StatusConflict, err)
		}
		return http.StatusOK, a.toOwnerResponse(owner), nil
	})
}

//trstctl:mutation
func (a *API) grantOwnershipException(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var body ownershipExceptionRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		exception, err := a.orch.GrantOwnershipException(ctx, tenantID, r.PathValue("id"), body.Reason,
			principalSubject(ctx), body.ExpiresAt)
		if err != nil {
			if store.IsNotFound(err) {
				return 0, nil, err
			}
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusCreated, toOwnershipExceptionResponse(exception), nil
	})
}

func (a *API) listOwnershipExceptions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	exceptions, err := a.store.ListOwnershipExceptions(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]ownershipExceptionResponse, 0, len(exceptions))
	for _, exception := range exceptions {
		items = append(items, toOwnershipExceptionResponse(exception))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) revokeOwnershipException(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var body ownershipExceptionRevokeRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		exception, err := a.orch.RevokeOwnershipException(ctx, tenantID, r.PathValue("id"),
			r.PathValue("exception_id"), body.Reason, principalSubject(ctx))
		if err != nil {
			if store.IsNotFound(err) {
				return 0, nil, err
			}
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusOK, toOwnershipExceptionResponse(exception), nil
	})
}
