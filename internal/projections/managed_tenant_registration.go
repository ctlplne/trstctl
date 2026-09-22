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
