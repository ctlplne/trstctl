// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type bulkRevokeRequest struct {
	IDs            []string `json:"ids,omitempty"`
	IdentityIDs    []string `json:"identity_ids,omitempty"`
	CertificateIDs []string `json:"certificate_ids,omitempty"`
	OwnerID        string   `json:"owner_id,omitempty"`
	IssuerID       string   `json:"issuer_id,omitempty"`
	Kind           string   `json:"kind,omitempty"`
	Status         string   `json:"status,omitempty"`
	Reason         string   `json:"reason"`
}

func (a *API) bulkRevoke(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "bulk revoke is not configured")
		}
		var req bulkRevokeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "revocation reason is required")
		}
		if !crypto.IsValidRevocationReason(reason) {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid revocation reason: use an RFC 5280 reason such as keyCompromise or unspecified")
		}
		principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
		if req.CertificateIDs != nil {
			req.Reason = reason
			return a.revokeSelectedCertificates(ctx, tenantID, idempotencyKey, r.URL.EscapedPath(), principal, req)
		}
		result, err := a.orch.BulkRevokeAuthorized(ctx, tenantID, orchestrator.BulkRevokeRequest{
			IDs:      bulkRevokeIDs(req),
			OwnerID:  strings.TrimSpace(req.OwnerID),
			IssuerID: strings.TrimSpace(req.IssuerID),
			Kind:     strings.TrimSpace(req.Kind),
			Status:   strings.TrimSpace(req.Status),
			Reason:   reason,
		}, func(ctx context.Context, identity store.Identity) error {
			var resourceAttrs map[string]string
			if a.gate.ABAC != nil {
				var err error
				resourceAttrs, err = a.identityABACResourceAttrs(ctx, tenantID, identity.ID)
				if err != nil {
					return err
				}
				resourceAttrs["transition.to"] = string(orchestrator.StateRevoked)
			}
			// Bulk input carries no exact per-target approval authority. The gate
			// must therefore refuse when dual control is required; it must never
			// turn a standing approval boolean into reusable revocation authority.
			return a.gate.check(ctx, principal, tenantID, identity.ID, orchestrator.StateRevoked, resourceAttrs)
		})
		var gateErr *gateError
		if errors.As(err, &gateErr) {
			return 0, nil, errStatus(gateErr.status, gateErr.detail)
		}
		if errors.Is(err, orchestrator.ErrBulkRevokeEmptyCriteria) {
			return 0, nil, errStatus(http.StatusBadRequest, "at least one identity id or criterion is required")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, result, nil
	})
}

func bulkRevokeIDs(req bulkRevokeRequest) []string {
	ids := make([]string, 0, len(req.IDs)+len(req.IdentityIDs)+len(req.CertificateIDs))
	ids = append(ids, req.IDs...)
	ids = append(ids, req.IdentityIDs...)
	ids = append(ids, req.CertificateIDs...)
	return ids
}
