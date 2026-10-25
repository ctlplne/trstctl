// SPDX-License-Identifier: BUSL-1.1

package projections

import "time"

// ManagedTenantRegistered is the existing managed-offering variant of
// tenant.registered v1. Share the wire type with the producer so its closed
// privacy policy includes exactly the metadata that provisioning records.
// The ordinary registration variant contains only name.
type ManagedTenantRegistered struct {
	Name            string                  `json:"name"`
	ManagedOffering ManagedOfferingMetadata `json:"managed_offering"`
	// ControlPlaneKeygen is the hosted tenant's control-plane key generation
	// default, decided with its registration (owner decision 2026-10-24: a new
	// tenant starts with it off). It rides on the registration because the
	// Provider's provisioning request holds the Provider tenant's service
	// fence, so a separate decision command for the new tenant cannot run
	// inside it; projected with the tenant row, it is atomic and a rebuild
	// reproduces it. Registrations recorded before the switch carry none.
	ControlPlaneKeygen *ControlPlaneKeygenSet `json:"control_plane_keygen,omitempty"`
}

// ManagedOfferingMetadata records the provider relationship without changing
// the hosted tenant's own storage and event isolation boundary.
type ManagedOfferingMetadata struct {
	Enabled          bool      `json:"enabled"`
	DeploymentModel  string    `json:"deployment_model"`
	ProviderTenantID string    `json:"provider_tenant_id"`
	Region           string    `json:"region,omitempty"`
	DataResidency    string    `json:"data_residency,omitempty"`
	Plan             string    `json:"plan,omitempty"`
	SupportTier      string    `json:"support_tier,omitempty"`
	SLOTier          string    `json:"slo_tier,omitempty"`
	ProvisionedBy    string    `json:"provisioned_by,omitempty"`
	ProvisionedAt    time.Time `json:"provisioned_at"`
}
