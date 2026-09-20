// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// Renewals use the identity's selected policy when admitted work carries no
// explicit issuance binding. Resolve its current revision before host handoff, so delayed CSR signing
// uses that exact revision and validity instead of requesting an unrelated 30
// days. This does not reuse the predecessor's approval or change admission rules.
// Both requester-held and legacy control-plane renewals use the same binding.
func (d *issuanceDispatcher) renewalIssuanceBinding(ctx context.Context, tenantID, identityID string, trigger transitionTrigger) (*store.OperationApprovalIssuanceBinding, error) {
	binding, err := issuanceBindingForTrigger(trigger)
	if err != nil || binding != nil {
		return binding, err
	}
	requirement, err := d.orch.ProfileApprovalRequirement(ctx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	if requirement.ProfileName == "" && d.defaultProfile != "" {
		requirement, err = d.orch.ProfileApprovalRequirementByName(ctx, tenantID, d.defaultProfile)
		if err != nil {
			return nil, err
		}
	}
	return requirement.IssuanceBinding(), nil
}

func intendedProfileEKUs(requested, allowed []string) []string {
	if len(requested) > 0 {
		return cloneStrings(requested)
	}
	if len(allowed) > 0 {
		return cloneStrings(allowed)
	}
	return nil
}

func leafProfileForCertificateProfile(base crypto.LeafProfile, prof profile.CertificateProfile, intendedEKUs []string) crypto.LeafProfile {
	out := base
	if prof.MaxValidity > 0 {
		max := time.Duration(prof.MaxValidity)
		if out.MaxValidity == 0 || max < out.MaxValidity {
			out.MaxValidity = max
		}
	}
	if len(intendedEKUs) > 0 {
		out.AllowedExtKeyUsage = cloneStrings(intendedEKUs)
	}
	if len(prof.AllowedDNSSuffixes) > 0 && len(out.PermittedDNSSuffixes) == 0 {
		out.PermittedDNSSuffixes = cloneStrings(prof.AllowedDNSSuffixes)
	}
	if len(prof.AllowedIPCIDRs) > 0 && len(out.PermittedIPCIDRs) == 0 {
		out.PermittedIPCIDRs = cloneStrings(prof.AllowedIPCIDRs)
	}
	if len(prof.AllowedEmailDomains) > 0 && len(out.PermittedEmailDomains) == 0 {
		out.PermittedEmailDomains = cloneStrings(prof.AllowedEmailDomains)
	}
	if len(prof.AllowedURIPrefixes) > 0 && len(out.PermittedURIPrefixes) == 0 {
		out.PermittedURIPrefixes = cloneStrings(prof.AllowedURIPrefixes)
	}
	return out
}

func profileDNSNames(info crypto.CSRInfo, fallback []string) []string {
	if len(info.DNSNames) > 0 {
		return cloneStrings(info.DNSNames)
	}
	return cloneStrings(fallback)
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
