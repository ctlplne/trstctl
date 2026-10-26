// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Revoking a signer-backed CA authority's key (A128). Two custodians approve a
// revoke_ca ceremony bound to the exact authority, its certificate, its signer
// handle and the reason. Executing it revokes the key in the isolated signer,
// which then signs nothing with it in any signer process sharing its keystore;
// records ca.authority.revoked; stops the authority issuing; and, under a
// managed parent in this tenant, revokes the authority's certificate on the
// parent's CRL so relying parties stop trusting what it issued.

// caRevocationReasons maps the accepted reason codes to RFC 5280 CRL reasons.
var caRevocationReasons = map[string]int{
	"key_compromise":         1,
	"ca_compromise":          2,
	"affiliation_changed":    3,
	"superseded":             4,
	"cessation_of_operation": 5,
	"privilege_withdrawn":    9,
}

func caRevocationReasonCode(reason string) (int, error) {
	code, ok := caRevocationReasons[reason]
	if !ok {
		return 0, fmt.Errorf("%w: reason must be key_compromise, ca_compromise, affiliation_changed, superseded, cessation_of_operation or privilege_withdrawn", api.ErrCAHierarchyInvalid)
	}
	return code, nil
}

// revokeCAPurpose binds a revoke_ca ceremony to the exact authority, certificate,
// signer handle and reason, so approvals cover only that revocation.
func revokeCAPurpose(authority store.CAAuthority, reason string) (string, error) {
	if _, err := caRevocationReasonCode(reason); err != nil {
		return "", err
	}
	certDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return "", err
	}
	binding := strings.Join([]string{authority.ID, authority.SignerHandle, crypto.SHA256Hex(certDER), reason}, "\x00")
	return "revoke-ca:" + crypto.SHA256Hex([]byte(binding)), nil
}

func validateAuthorityRevocation(authority store.CAAuthority) error {
	if authority.SignerHandle == "" {
		return fmt.Errorf("%w: this authority's key is held offline, outside trstctl; revoke its certificate where its issuer lives", api.ErrCAHierarchyInvalid)
	}
	switch authority.Status {
	case "active", "superseded":
		return nil
	case "revoked":
		return fmt.Errorf("%w: this authority's key is already revoked", api.ErrCAHierarchyConflict)
	default:
		return fmt.Errorf("%w: authority status %q cannot be revoked", api.ErrCAHierarchyConflict, authority.Status)
	}
}

// RevokeAuthority executes a revoke_ca ceremony that reached quorum.
func (h *caHierarchyService) RevokeAuthority(ctx context.Context, tenantID, caID string, req api.CAAuthorityRevokeRequest) (api.CAAuthorityRevocation, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	reason := strings.TrimSpace(req.Reason)
	if caID == "" || ceremonyID == "" {
		return api.CAAuthorityRevocation{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	reasonCode, err := caRevocationReasonCode(reason)
	if err != nil {
		return api.CAAuthorityRevocation{}, err
	}
	client := h.signer.Client()
	if client == nil {
		return api.CAAuthorityRevocation{}, api.ErrCAHierarchyUnavailable
	}
	var result api.CAAuthorityRevocation
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		authority, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		if err := validateAuthorityRevocation(authority); err != nil {
			return err
		}
		purpose, err := revokeCAPurpose(authority, reason)
		if err != nil {
			return err
		}
		_, approvals, err := h.store.ValidateKeyCeremonyWithApprovalEvidenceTx(ctx, tx, tenantID, ceremonyID, purpose)
		if err != nil {
			if errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
				return fmt.Errorf("%w: this ceremony approved a different revocation; start a revoke_ca ceremony for this authority and reason", api.ErrCAHierarchyConflict)
			}
			return err
		}
		record, _, err := client.RevokeKey(ctx, authority.SignerHandle, ceremonyID, reason)
		if err != nil {
			return err
		}
		// The signer's own readback, not the call's success, is the effect.
		if revoked, err := client.KeyRevoked(ctx, authority.SignerHandle); err != nil || !revoked {
			return fmt.Errorf("signer did not report the authority's key revoked: %v", err)
		}
		var parent *store.CAAuthority
		if authority.ParentID != nil && *authority.ParentID != "" {
			p, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, *authority.ParentID)
			switch {
			case err == nil && p.SignerHandle != "" && p.Status != "revoked":
				parent = &p
			case err != nil && !store.IsNotFound(err):
				return err
			}
		}
		payload := projections.CAAuthorityRevoked{
			ID: authority.ID, SignerHandle: authority.SignerHandle, Serial: authority.Serial,
			Reason: reason, ReasonCode: reasonCode, CeremonyID: ceremonyID,
			SignerOperationID: record.OperationID, RevokedAt: time.Unix(record.RevokedAt, 0).UTC(),
		}
		for _, approval := range approvals {
			payload.ApprovalEventIDs = append(payload.ApprovalEventIDs, approval.EventID)
		}
		if parent != nil {
			payload.ParentID = parent.ID
			payload.RevokedOnParentCRL = true
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		event, err := h.log.Append(ctx, events.Event{ID: "ca-authority-revoked-" + ceremonyID, Type: projections.EventCAAuthorityRevoked, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		var canonical projections.CAAuthorityRevoked
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.ID != caID || canonical.CeremonyID != ceremonyID || canonical.Reason != reason {
			return fmt.Errorf("%w: the recorded revocation for this ceremony does not match this request", api.ErrCAHierarchyConflict)
		}
		if err := projections.New(h.store).ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		if canonical.RevokedOnParentCRL {
			if err := h.store.EnsureCertificateCRLPublicationTx(ctx, tx, tenantID, event.ID, canonical.ParentID); err != nil {
				return err
			}
		}
		revoked, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		result = api.CAAuthorityRevocation{
			Authority: authorityResponse(revoked), Reason: canonical.Reason, RevokedAt: canonical.RevokedAt,
			SignerRevoked: true, CeremonyID: ceremonyID, RevokedOnParentCRL: canonical.RevokedOnParentCRL,
			FollowUp: caRevocationFollowUp(revoked, canonical.RevokedOnParentCRL),
		}
		if canonical.ParentID != "" {
			parentID := canonical.ParentID
			result.ParentID = &parentID
		}
		return nil
	})
	if err != nil {
		return api.CAAuthorityRevocation{}, caHierarchyConflict(err)
	}
	h.forgetSigner(caID)
	return result, nil
}

// caRevocationFollowUp says what trstctl cannot do for the operator after a
// revocation: the key signs nothing more, so its own CRL is frozen.
func caRevocationFollowUp(authority store.CAAuthority, onParentCRL bool) []string {
	steps := []string{
		"This authority's key signs nothing more: no certificate, CRL or OCSP response. Its last published CRL stays until its next-update time.",
		"Reissue the certificates this authority issued from another active authority.",
	}
	switch {
	case onParentCRL:
		steps = append(steps, "Its certificate is revoked on its parent's CRL; relying parties that check revocation stop trusting what it issued.")
	case authority.Kind == "root":
		steps = append(steps, "A root has no issuer to revoke it: remove its certificate from every trust store that holds it.")
	default:
		steps = append(steps, "Its issuer is not a managed authority in this tenant: revoke its certificate where that issuer lives.")
	}
	return steps
}

// forgetSigner drops the cached remote signer of an authority whose key the
// signer no longer signs with.
func (h *caHierarchyService) forgetSigner(caID string) {
	h.mu.Lock()
	delete(h.signers, caID)
	h.mu.Unlock()
}
