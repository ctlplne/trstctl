// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
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
	if req.Operation != "rekey_ca" {
		purpose, err := hierarchyPurposeFromStartRequest(req)
		return purpose, req.Spec, err
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
