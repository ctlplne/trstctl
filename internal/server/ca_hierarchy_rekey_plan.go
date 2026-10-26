// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/release"
	"trstctl.com/trstctl/internal/store"
)

func rekeyAuthoritySpec(ca store.CAAuthority, ttlSeconds int64) api.CASpec {
	return api.CASpec{
		CommonName: ca.CommonName, PermittedDNSDomains: append([]string(nil), ca.PermittedDNSNames...),
		MaxPathLen: ca.MaxPathLen, ExtendedKeyUsages: append([]string(nil), ca.EKUs...),
		TTLSeconds: ttlSeconds, SignatureAlgorithm: "ecdsa-p256",
	}
}

// ceremonyPurposeAndSpec binds a re-key approval to the authority's current
// profile, the requested lifetime, and the operator's reason. Preview and
// start share this validation so the displayed plan is the executed plan.
func (h *caHierarchyService) ceremonyPurposeAndSpec(ctx context.Context, tenantID string, req api.CACeremonyStartRequest) (string, api.CASpec, error) {
	if req.Operation == "revoke_ca" {
		if strings.TrimSpace(req.AuthorityID) == "" {
			return "", api.CASpec{}, fmt.Errorf("%w: authority_id is required for revoke_ca", api.ErrCAHierarchyInvalid)
		}
		if _, err := caRevocationReasonCode(strings.TrimSpace(req.Reason)); err != nil {
			return "", api.CASpec{}, err
		}
		authority, err := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.AuthorityID))
		if err != nil {
			return "", api.CASpec{}, err
		}
		if err := validateAuthorityRevocation(authority); err != nil {
			return "", api.CASpec{}, err
		}
		purpose, err := revokeCAPurpose(authority, strings.TrimSpace(req.Reason))
		return purpose, api.CASpec{}, err
	}
	if req.Operation == "release_managed_ca_leaf" {
		if req.Threshold < 2 {
			return "", api.CASpec{}, fmt.Errorf("%w: release requires at least two distinct custodians", api.ErrCAHierarchyInvalid)
		}
		review, err := release.NewReviewer(h.store, h.log).Preview(ctx, tenantID, req.AuthorityID,
			release.Request{CertificateID: req.DependentID,
				ExpectedCertificateSHA256: req.ExpectedCertificateSHA256,
				Reason:                    req.Reason, RiskAccepted: req.RiskAccepted}, time.Now().UTC())
		if err != nil {
			if errors.Is(err, release.ErrInvalid) {
				return "", api.CASpec{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
			}
			return "", api.CASpec{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyConflict, err)
		}
		return review.Purpose(), api.CASpec{}, nil
	}
	if req.Operation != "rekey_ca" {
		if (req.Operation == "import_existing_ca" || req.Operation == "prepare_existing_ca" || req.Operation == "import_ca_key") && req.ParentID != "" {
			chainDER, _, err := certificateChainPEM(req.CertificatePEM)
			if err != nil {
				return "", api.CASpec{}, err
			}
			parent, err := h.store.GetCAAuthority(ctx, tenantID, req.ParentID)
			if err != nil {
				return "", api.CASpec{}, err
			}
			if req.Operation == "import_existing_ca" || req.Operation == "import_ca_key" {
				if err := validateImportedCAParent(parent, chainDER); err != nil {
					return "", api.CASpec{}, err
				}
			} else if err := validatePreparedCAIssuerParent(parent, chainDER); err != nil {
				return "", api.CASpec{}, err
			}
		}
		purpose, err := hierarchyPurposeFromStartRequest(req)
		if err != nil {
			return "", api.CASpec{}, err
		}
		switch req.Operation {
		case "create_intermediate", "issue_intermediate_csr":
			issuer, err := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.ParentID))
			if err != nil {
				return "", api.CASpec{}, err
			}
			if err := validateOnlineCeremonyIssuer(issuer); err != nil {
				return "", api.CASpec{}, err
			}
		case "cross_sign_ca":
			issuer, err := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.AuthorityID))
			if err != nil {
				return "", api.CASpec{}, err
			}
			if err := validateOnlineCeremonyIssuer(issuer); err != nil {
				return "", api.CASpec{}, err
			}
		}
		return purpose, req.Spec, nil
	}
	if strings.TrimSpace(req.AuthorityID) == "" {
		return "", api.CASpec{}, fmt.Errorf("%w: authority_id is required for rekey_ca", api.ErrCAHierarchyInvalid)
	}
	if req.Spec.TTLSeconds <= 0 || req.Spec.TTLSeconds > math.MaxInt64/int64(time.Second) {
		return "", api.CASpec{}, fmt.Errorf("%w: re-key ttl_seconds must be positive and within the supported duration range", api.ErrCAHierarchyInvalid)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return "", api.CASpec{}, fmt.Errorf("%w: reason is required for rekey_ca", api.ErrCAHierarchyInvalid)
	}
	authority, err := h.store.GetCAAuthority(ctx, tenantID, strings.TrimSpace(req.AuthorityID))
	if err != nil {
		return "", api.CASpec{}, err
	}
	if err := validateAuthorityRekey(authority); err != nil {
		return "", api.CASpec{}, err
	}
	if authority.Kind == "intermediate" {
		if authority.ParentID == nil || *authority.ParentID == "" {
			return "", api.CASpec{}, fmt.Errorf("%w: intermediate CA has no parent authority", api.ErrCAHierarchyInvalid)
		}
		parent, err := h.store.GetCAAuthority(ctx, tenantID, *authority.ParentID)
		if err != nil {
			return "", api.CASpec{}, err
		}
		if err := validateOnlineRekeyParent(parent); err != nil {
			return "", api.CASpec{}, err
		}
	}
	spec := rekeyAuthoritySpec(authority, req.Spec.TTLSeconds)
	if req.Spec.CommonName != spec.CommonName || req.Spec.MaxPathLen != spec.MaxPathLen ||
		!sameStringSet(req.Spec.PermittedDNSDomains, spec.PermittedDNSDomains) ||
		!sameStringSet(req.Spec.ExtendedKeyUsages, spec.ExtendedKeyUsages) ||
		!strings.EqualFold(req.Spec.SignatureAlgorithm, spec.SignatureAlgorithm) {
		return "", api.CASpec{}, fmt.Errorf("%w: re-key spec must exactly match the authority profile and ecdsa-p256 signer algorithm", api.ErrCAHierarchyInvalid)
	}
	purpose, err := rekeyCAPurpose(authority.ID, spec, req.Reason)
	return purpose, spec, err
}

func validateOnlineCeremonyIssuer(issuer store.CAAuthority) error {
	if issuer.SignerHandle == "" {
		return fmt.Errorf("%w: offline issuer cannot perform online signing; use the offline certificate or CSR import ceremony", api.ErrCAHierarchyInvalid)
	}
	if issuer.Status != "active" {
		return fmt.Errorf("%w: online signing issuer must be active", api.ErrCAHierarchyConflict)
	}
	return nil
}

func validateOnlineRekeyParent(parent store.CAAuthority) error {
	if parent.SignerHandle == "" {
		return fmt.Errorf("%w: offline parent cannot sign an online CA re-key; use prepare_existing_ca and have the external issuer sign its public CSR", api.ErrCAHierarchyInvalid)
	}
	if parent.Status != "active" {
		return fmt.Errorf("%w: re-key parent CA must be active", api.ErrCAHierarchyConflict)
	}
	return nil
}

func rekeyCAPurpose(authorityID string, spec api.CASpec, reason string) (string, error) {
	authorityID = strings.TrimSpace(authorityID)
	if authorityID == "" {
		return "", fmt.Errorf("%w: authority_id is required for rekey_ca", api.ErrCAHierarchyInvalid)
	}
	payload, err := json.Marshal(struct {
		AuthorityID string     `json:"authority_id"`
		Spec        api.CASpec `json:"spec"`
		Reason      string     `json:"reason"`
	}{authorityID, spec, strings.TrimSpace(reason)})
	if err != nil {
		return "", err
	}
	return "ca-rekey-v2:" + crypto.SHA256Hex(payload), nil
}
