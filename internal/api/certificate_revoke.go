// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CertificateRevocationAuthorityResolver is read-only. The assembled server
// verifies the actual public certificate against an issuer whose revocation
// ledger and publisher it serves. It must not guess from serials or names.
type CertificateRevocationAuthorityResolver func(context.Context, store.Certificate) (string, error)

func WithCertificateRevocationAuthority(resolver CertificateRevocationAuthorityResolver) Option {
	return func(c *config) { c.certRevocationAuthority = resolver }
}

func (a *API) revokeSelectedCertificates(ctx context.Context, tenantID, commandKey, route string, principal authz.Principal, request bulkRevokeRequest) (int, any, error) {
	// Require mutation authority even if every supplied ID is absent. Per-object
	// policy and approval checks below still narrow this coarse permission.
	if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
		return 0, nil, errStatus(http.StatusForbidden, "certificate revocation requires certs:issue authority")
	}
	if len(request.IDs) != 0 || len(request.IdentityIDs) != 0 || request.OwnerID != "" || request.IssuerID != "" || request.Kind != "" || request.Status != "" {
		return 0, nil, errStatus(http.StatusBadRequest, "certificate_ids selects exact certificates; do not mix it with identity ids or identity criteria")
	}
	if a.certRevocationAuthority == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "certificate revocation authority is not configured")
	}
	material, err := json.Marshal(struct {
		Domain    string            `json:"domain"`
		Route     string            `json:"route"`
		Principal string            `json:"principal"`
		Request   bulkRevokeRequest `json:"request"`
	}{"trstctl.api.certificate-revocation.v1", route, principal.Subject, request})
	if err != nil {
		return 0, nil, err
	}
	result, err := a.orch.BulkRevokeCertificates(ctx, tenantID, commandKey, crypto.SHA256Hex(material),
		request.CertificateIDs, request.Reason, orchestrator.CertificateRevocationChecks{
			Authority: a.certRevocationAuthority,
			Authorize: func(ctx context.Context, certificate store.Certificate) error {
				ownerID := ""
				if certificate.OwnerID != nil {
					ownerID = *certificate.OwnerID
				}
				attrs := map[string]string{
					"certificate.id": certificate.ID, "certificate.subject": certificate.Subject,
					"certificate.status": certificate.Status, "certificate.fingerprint": certificate.Fingerprint,
					"owner_id": ownerID, "transition.to": "revoked", "resource.kind": "certificate",
				}
				return a.gate.check(ctx, principal, tenantID, certificate.ID, orchestrator.StateRevoked, attrs)
			},
		})
	var denial *gateError
	if errors.As(err, &denial) {
		return 0, nil, errStatus(denial.status, denial.detail)
	}
	if errors.Is(err, orchestrator.ErrCertificateRevocationInvalid) {
		return 0, nil, errStatus(http.StatusBadRequest, fmt.Sprintf("supply 1 to %d valid certificate_ids and an RFC 5280 reason", projections.MaxCertificateRevocationBatch))
	}
	if errors.Is(err, store.ErrIdempotencyConflict) {
		return 0, nil, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different certificate revocation request")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, result, nil
}
