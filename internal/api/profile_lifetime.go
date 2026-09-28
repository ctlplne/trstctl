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
		return errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
			"certificate profile %q maximum validity %s leaves no usable lifetime after the %s NotBefore backdate; choose a profile whose full signed validity includes this clock-skew allowance plus time for deployment and automatic renewal; preview again before authorizing issuance; nothing was queued", name, maximum, skew))
	}
	return nil
}

func (a *API) validateIdentityProfileLifetime(ctx context.Context, tenantID string, identity store.Identity, requirement orchestrator.ProfileApprovalRequirement) error {
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
	return validateProfileSigningLifetime(record.Name, time.Duration(policy.MaxValidity), source)
}
