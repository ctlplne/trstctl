// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/reprotect"
	"trstctl.com/trstctl/internal/crypto"
)

type SanitizationClaim struct {
	TenantID       string   `json:"tenant_id"`
	KeyID          string   `json:"key_id"`
	DataSetID      string   `json:"data_set_id"`
	Scope          string   `json:"scope,omitempty"`
	StorageRefs    []string `json:"storage_refs,omitempty"`
	StorageDigest  []byte   `json:"storage_digest,omitempty"`
	DesignationRef string   `json:"designation_ref"`
	ClaimDigest    []byte   `json:"claim_digest,omitempty"`
}

func PlanReprotectionWithErasure(state depstate.KeyState, claims []SanitizationClaim) ([]reprotect.Job, error) {
	if err := VerifySanitizationClaims(state, claims); err != nil {
		return nil, err
	}
	return reprotect.PlanFromState(state)
}

func VerifySanitizationClaims(state depstate.KeyState, claims []SanitizationClaim) error {
	if len(claims) == 0 {
		return nil
	}
	erased := map[string]depstate.Dependent{}
	for _, dep := range state.ErasureDesignated {
		erased[dependentKey(dep)] = dep
	}
	for _, claim := range normalizeClaims(claims) {
		if claim.TenantID != state.TenantID || claim.KeyID != state.KeyID {
			return fmt.Errorf("%w: sanitization claim outside dependency state", ErrInvalidRecord)
		}
		dep := depstate.Dependent{Class: depstate.DependentDataSet, ID: claim.DataSetID}
		if _, ok := erased[dependentKey(dep)]; !ok {
			return fmt.Errorf("%w: sanitization claim lacks erasure designation", ErrInvalidRecord)
		}
	}
	return nil
}

func SanitizationClaimDigest(claim SanitizationClaim) ([]byte, error) {
	claim = normalizeClaimNoDigest(claim)
	if claim.TenantID == "" || claim.KeyID == "" || claim.DataSetID == "" || claim.DesignationRef == "" {
		return nil, fmt.Errorf("%w: sanitization claim requires tenant, key, data set, and designation ref", ErrInvalidRecord)
	}
	body := struct {
		Domain string            `json:"domain"`
		Claim  SanitizationClaim `json:"claim"`
	}{Domain: "trstctl/vdec/aggregate/sanitization-claim/v1", Claim: claim}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: encode sanitization claim: %w", err)
	}
	return crypto.SHA256Sum(raw), nil
}

func normalizeClaims(in []SanitizationClaim) []SanitizationClaim {
	out := make([]SanitizationClaim, 0, len(in))
	for _, claim := range in {
		claim = normalizeClaimNoDigest(claim)
		digest, _ := SanitizationClaimDigest(claim)
		claim.ClaimDigest = digest
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].KeyID != out[j].KeyID {
			return out[i].KeyID < out[j].KeyID
		}
		if out[i].DataSetID != out[j].DataSetID {
			return out[i].DataSetID < out[j].DataSetID
		}
		return bytes.Compare(out[i].ClaimDigest, out[j].ClaimDigest) < 0
	})
	return out
}

func normalizeClaimNoDigest(in SanitizationClaim) SanitizationClaim {
	return SanitizationClaim{
		TenantID:       strings.TrimSpace(in.TenantID),
		KeyID:          strings.TrimSpace(in.KeyID),
		DataSetID:      strings.TrimSpace(in.DataSetID),
		Scope:          strings.TrimSpace(in.Scope),
		StorageRefs:    sortedStrings(in.StorageRefs),
		StorageDigest:  cloneBytes(in.StorageDigest),
		DesignationRef: strings.TrimSpace(in.DesignationRef),
	}
}

func dependentKey(dep depstate.Dependent) string {
	return string(dep.Class) + "\x00" + dep.ID
}
