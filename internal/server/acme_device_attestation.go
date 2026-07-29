// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

// acmeDeviceAttestationProfiles adapts the existing active-profile read model
// into ACME's narrow policy seam. GetActiveProfile runs under Store.WithTenant,
// so the trust roots and identifier allowlist cannot cross an RLS boundary.
type acmeDeviceAttestationProfiles struct {
	store       *store.Store
	profileName string
}

func (p acmeDeviceAttestationProfiles) DeviceAttestationPolicy(
	ctx context.Context,
	tenantID, identifier string,
) (acme.DeviceAttestationPolicy, bool, error) {
	if p.store == nil || p.profileName == "" {
		return acme.DeviceAttestationPolicy{}, false, nil
	}
	record, err := p.store.GetActiveProfile(ctx, tenantID, p.profileName)
	if err != nil {
		if store.IsNotFound(err) {
			return acme.DeviceAttestationPolicy{}, false, nil
		}
		return acme.DeviceAttestationPolicy{}, false, fmt.Errorf("load active profile %q: %w", p.profileName, err)
	}
	var certificateProfile profile.CertificateProfile
	if err := json.Unmarshal(record.Spec, &certificateProfile); err != nil {
		return acme.DeviceAttestationPolicy{}, false, fmt.Errorf("decode active profile %q: %w", p.profileName, err)
	}
	if err := certificateProfile.ValidateDefinition(); err != nil {
		return acme.DeviceAttestationPolicy{}, false, fmt.Errorf("validate active profile %q: %w", p.profileName, err)
	}
	policy := certificateProfile.ACMEDeviceAttestation
	if !policy.Enabled || policy.Format != "tpm" || !policy.AllowsIdentifier(identifier) {
		return acme.DeviceAttestationPolicy{}, false, nil
	}
	roots := make([][]byte, 0, len(policy.AttestationRootsPEM))
	for _, root := range policy.AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	return acme.DeviceAttestationPolicy{
		TrustedRootsPEM:   roots,
		AllowedAlgorithms: append([]int64(nil), policy.AllowedAlgorithms...),
		MaxAge:            time.Duration(policy.MaxAge),
	}, true, nil
}
