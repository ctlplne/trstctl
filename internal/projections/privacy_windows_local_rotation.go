// SPDX-License-Identifier: BUSL-1.1
package projections

import "time"

type privacySecretStaticRotationAdvancedV1 struct {
	SealedPreparation []byte `json:"sealed_preparation,omitempty"`
	ID                string `json:"id"`
	TenantEpoch       string `json:"tenant_epoch"`
	FromPhase         string `json:"from_phase"`
	Phase             string `json:"phase"`
	ProviderType      string `json:"provider_type,omitempty"`
	NewRef            string `json:"new_ref,omitempty"`
	SealedNew         []byte `json:"sealed_new,omitempty"`
	SealedOld         []byte `json:"sealed_old,omitempty"`
	ResultVersion     int    `json:"result_version,omitempty"`
	RestoredVersion   int    `json:"restored_version,omitempty"`
	VerifyMode        string `json:"verify_mode,omitempty"`
	Error             string `json:"error,omitempty"`
	// NewExpiresAt is when a dynamic-lease rotation's new lease expires.
	NewExpiresAt *time.Time `json:"new_expires_at,omitempty"`
	// RetireNotBefore is the approved retirement deadline, fixed when the
	// successor verifies (A240).
	RetireNotBefore *time.Time `json:"retire_not_before,omitempty"`
}
