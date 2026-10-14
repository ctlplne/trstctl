// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func validateProfileSigningLifetime(name string, maximum time.Duration, issuerSource string) error {
	// An external CA owns its validity rules; selecting it must not silently
	// apply the local signer's backdate.
	if issuerSource != endpointIssuerPlatform && issuerSource != endpointIssuerPrivate {
		return nil
	}
	skew := crypto.IssuanceBackdateSkew()
	if maximum > 0 && maximum <= skew {
		refusal := errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
			"certificate profile %q maximum validity %s leaves no usable lifetime after the %s NotBefore backdate; choose a profile whose full signed validity includes this clock-skew allowance plus time for deployment and automatic renewal; preview again before authorizing issuance; nothing was queued", name, maximum, skew))
		refusal.ext = map[string]any{"retryable": false, "recovery_required": "new_issuance_request"}
		return refusal
	}
	return nil
}

// validateIdentityProfileLifetime checks the parts of the eventual signing
// request that are already known before a lifecycle event is appended. The
// worker still validates the final CSR, but an ACME-only or name-constrained
// profile must not leave an identity claiming to be issued with no certificate.
func (a *API) validateIdentityProfileLifetime(ctx context.Context, tenantID string, identity store.Identity, requirement orchestrator.ProfileApprovalRequirement, transitionCSR string) error {
	if identity.Kind != store.KindX509Certificate || requirement.ProfileName == "" {
		return nil
	}
	var attrs map[string]json.RawMessage
	if len(identity.Attributes) > 0 {
		if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
			return err
		}
	}
	source := endpointIssuerPlatform
	if raw, ok := attrs["issuing_authority_source"]; ok {
		if err := json.Unmarshal(raw, &source); err != nil {
			return errStatus(http.StatusUnprocessableEntity, "identity issuing authority source is invalid; no CA was substituted and nothing was queued")
		}
		source = strings.TrimSpace(source)
	}
	record, err := a.store.GetProfileVersion(ctx, tenantID, requirement.ProfileName, requirement.ProfileVersion)
	if err != nil {
		return err
	}
	if record.ID != requirement.ProfileID || store.ProfileSpecDigest(record.Spec) != requirement.ProfileSpecDigest {
		return errStatus(http.StatusConflict, "certificate profile changed during review; preview again")
	}
	var policy profile.CertificateProfile
	if err := json.Unmarshal(record.Spec, &policy); err != nil {
		return err
	}
	policy.Name, policy.Version = record.Name, record.Version
	if err := validateProfileSigningLifetime(record.Name, time.Duration(policy.MaxValidity), source); err != nil {
		return err
	}
	request := profile.Request{Protocol: "api", TTL: time.Duration(requirement.EffectiveTTLSeconds) * time.Second}
	csr := strings.TrimSpace(transitionCSR)
	if csr == "" {
		if raw, ok := attrs["subject_csr_pem"]; ok {
			if err := json.Unmarshal(raw, &csr); err != nil {
				return errStatus(http.StatusUnprocessableEntity, "identity subject CSR is invalid; nothing was queued")
			}
			csr = strings.TrimSpace(csr)
		}
	}
	if csr != "" {
		_, info, err := crypto.ParsePublicCSRPEMWithInspector([]byte(csr), crypto.InspectCSR)
		if err != nil {
			return errWithStatus(http.StatusBadRequest, err)
		}
		request.DNSNames = info.DNSNames
		if len(request.DNSNames) == 0 && strings.TrimSpace(info.CommonName) != "" {
			request.DNSNames = []string{info.CommonName}
		}
		request.IPAddresses = info.IPAddresses
		request.EmailAddresses = info.EmailAddresses
		request.URIs = info.URIs
	}
	if len(request.DNSNames) == 0 {
		request.DNSNames = []string{identity.Name}
	}
	if err := policy.ValidateRequestMetadata(request); err != nil {
		return errStatus(http.StatusUnprocessableEntity, err.Error()+"; no identity transition or CA issuance was queued")
	}
	return nil
}
