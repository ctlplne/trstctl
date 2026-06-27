package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
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
		result, err := a.orch.BulkRevoke(ctx, tenantID, orchestrator.BulkRevokeRequest{
			IDs:      bulkRevokeIDs(req),
			OwnerID:  strings.TrimSpace(req.OwnerID),
			IssuerID: strings.TrimSpace(req.IssuerID),
			Kind:     strings.TrimSpace(req.Kind),
			Status:   strings.TrimSpace(req.Status),
			Reason:   reason,
		})
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
