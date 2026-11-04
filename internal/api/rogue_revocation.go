// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Provider-native revocation of rogue certificates (A163).
//
// A Certificate Transparency finding names a certificate trstctl never asked
// for — someone issued it in the tenant's own vendor account outside trstctl,
// say. An operator who names the external authority that issued it can have
// trstctl revoke it there by serial, through that authority's revocation API;
// the finding reads revoked at the issuer only once the authority confirms. An
// ACME authority takes the certificate's bytes instead of a serial (N10). A
// rogue certificate already in inventory goes through the exact revocation
// (POST /api/v1/certificates/bulk-revoke), which reaches its recorded issuer.

type rogueCertificateRevokeRequest struct {
	DiscoveryID string `json:"discovery_id"`
	AuthorityID string `json:"authority_id"`
	Reason      string `json:"reason"`
}

type rogueIssuerRevocationResponse struct {
	DiscoveryID string `json:"discovery_id"`
	AuthorityID string `json:"authority_id"`
	Serial      string `json:"serial"`
	Reason      string `json:"reason"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at,omitempty"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	Attempts    int    `json:"attempts"`
	LastError   string `json:"last_error,omitempty"`
}

func (a *API) revokeRogueCertificateAtIssuer(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "certificate revocation requires certs:issue authority")
		}
		var request rogueCertificateRevokeRequest
		if err := decodeJSON(r, &request); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		request.DiscoveryID = strings.TrimSpace(request.DiscoveryID)
		request.AuthorityID = strings.TrimSpace(request.AuthorityID)
		request.Reason = strings.TrimSpace(request.Reason)
		if parsed, err := googleuuid.Parse(request.DiscoveryID); err != nil || parsed.String() != request.DiscoveryID {
			return 0, nil, errStatus(http.StatusBadRequest, "discovery_id must name a Certificate Transparency finding by its id")
		}
		if request.AuthorityID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "authority_id must name the external CA that issued the certificate")
		}
		if !crypto.IsValidRevocationReason(request.Reason) || request.Reason == "removeFromCRL" {
			return 0, nil, errStatus(http.StatusBadRequest, "reason must be an RFC 5280 revocation reason such as keyCompromise or superseded")
		}
		if a.externalCAs == nil || a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "external certificate authorities are not configured")
		}
		authorities, err := a.externalCAs.ListExternalCAs(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		kind := ""
		for _, authority := range authorities {
			if authority.ID == request.AuthorityID {
				kind = strings.ToLower(authority.Type)
			}
		}
		if kind == "" {
			return 0, nil, errStatus(http.StatusNotFound, "this tenant has no external CA with that id")
		}
		// An ACME authority revokes from the certificate's bytes once trstctl's
		// account is authorized for every name in it (N10): the delivery reads
		// the bytes back from the CT log that recorded the finding.
		if !ca.RevokesBySerial(kind) && !ca.RevokesByCertificate(kind) {
			return 0, nil, errStatus(http.StatusConflict, "this authority ("+kind+") revokes a certificate by its thumbprint or through a relay, "+
				"which a Certificate Transparency finding does not give trstctl; revoke it at the CA")
		}
		requested, _, err := a.orch.RequestRogueCertificateRevocation(ctx, tenantID, orchestrator.RogueCertificateRevocationRequest{
			DiscoveryID: request.DiscoveryID, AuthorityID: request.AuthorityID, Reason: request.Reason, IdempotencyKey: idempotencyKey,
		})
		switch {
		case errors.Is(err, orchestrator.ErrRogueRevocationExists):
			return 0, nil, errStatus(http.StatusConflict, "this finding's revocation at that authority is already queued or confirmed")
		case errors.Is(err, orchestrator.ErrRogueFindingNotRevocable):
			return 0, nil, errStatus(http.StatusConflict, "only a Certificate Transparency finding with a certificate serial can be revoked at its issuer; "+
				"revoke an inventory certificate through the exact revocation")
		case store.IsNotFound(err):
			return 0, nil, errStatus(http.StatusNotFound, "no finding with that id in this tenant")
		case err != nil:
			return 0, nil, err
		}
		return http.StatusAccepted, rogueIssuerRevocationResponse{
			DiscoveryID: requested.DiscoveryID, AuthorityID: requested.AuthorityID, Serial: requested.Serial,
			Reason: requested.Reason, Status: "queued",
		}, nil
	})
}

// attachRogueIssuerRevocations sets each CT finding's newest revocation at an
// issuer.
func (a *API) attachRogueIssuerRevocations(ctx context.Context, tenantID string, findings []rogueCertificateFinding) error {
	revocations, err := a.store.ListRogueCertificateRevocations(ctx, tenantID)
	if err != nil {
		return err
	}
	newest := map[string]store.RogueCertificateRevocation{}
	for _, r := range revocations {
		if _, seen := newest[r.DiscoveryID]; !seen {
			newest[r.DiscoveryID] = r
		}
	}
	for i := range findings {
		r, ok := newest[findings[i].DiscoveryID]
		if !ok || findings[i].DiscoveryID == "" {
			continue
		}
		resp := rogueIssuerRevocationResponse{
			DiscoveryID: r.DiscoveryID, AuthorityID: r.AuthorityID, Serial: r.Serial, Reason: r.Reason, Status: r.State,
			RequestedAt: r.RequestedAt.UTC().Format(time.RFC3339), Attempts: r.Attempts, LastError: r.LastError,
		}
		if r.RevokedAt != nil {
			resp.RevokedAt = r.RevokedAt.UTC().Format(time.RFC3339)
		}
		findings[i].IssuerRevocation = &resp
	}
	return nil
}
