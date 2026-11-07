// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import "errors"

const RotationManifestPlanVersion = 2

// NewRotationIntentFromManifest retains one complete account and one vault
// generation. Native entries stay in their bounded immutable source pages.
func NewRotationIntentFromManifest(header RotationManifestHeader, seal RotationManifestSeal) (RotationIntent, error) {
	if err := header.Validate(); err != nil {
		return RotationIntent{}, err
	}
	if err := seal.Validate(header); err != nil {
		return RotationIntent{}, err
	}
	plan := RotationPlan{Version: RotationManifestPlanVersion, ID: header.ID, Account: header.Account, SecretName: header.SecretName, CreatedAt: header.CreatedAt, ExpiresAt: seal.ExpiresAt, Manifest: &seal}
	var err error
	plan.Digest, err = plan.contentDigest()
	if err != nil {
		return RotationIntent{}, err
	}
	intent := RotationIntent{Mode: header.Mode, Plan: plan, ExpectedVersion: header.ExpectedVersion, ProviderBinding: header.ProviderBinding}
	if header.Reconcile != nil {
		copy := *header.Reconcile
		intent.Reconcile = &copy
	}
	if _, err := intent.Digest(); err != nil {
		return RotationIntent{}, err
	}
	return intent, nil
}
func (p RotationPlan) validateManifestPlan() error {
	if !canonicalID(p.ID) || p.Account.Validate() != nil || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.After(p.CreatedAt.Add(RotationInventoryMaxAge)) || p.Manifest == nil || len(p.Hosts) != 0 || len(p.Order) != 0 || p.Manifest.ValidateShape() != nil || p.Manifest.ID != p.ID || !p.Manifest.ExpiresAt.Equal(p.ExpiresAt) {
		return errors.New("service dependents: exact sealed account manifest without inline authority required")
	}
	if err := validateRotationSecretName(p.SecretName); err != nil {
		return err
	}
	digest, err := p.contentDigest()
	if err != nil {
		return err
	}
	if digest != p.Digest {
		return errors.New("service dependents: sealed manifest plan digest differs")
	}
	return nil
}
