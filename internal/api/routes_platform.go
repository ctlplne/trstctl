// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// platformRoutes are the deployment-posture surfaces: what this build is, how
// its tenant cryptography is protected, how it is distributed, and — since J2 —
// whether its backups have ever been proven restorable.
//
// Split out of api.go for the served-surface file budget rather than taking the
// reviewed allowlist waiver. The budget is doing its job: api.go is the file
// every new endpoint gets appended to, so without a forcing function it grows
// until the route table is unreadable and duplicated paths stop being obvious.
func (a *API) platformRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/platform/system", opID: "getPlatformSystem", summary: "Running build, uptime, signer topology, and spine reachability", handler: a.getPlatformSystem, resSchema: "SystemReadout", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/platform/tenant-key-domain", opID: "getTenantKeyDomain", summary: "Get this tenant's cryptographic protection and lifecycle status", handler: a.getTenantKeyDomain, resSchema: "TenantKeyDomainStatus", successCode: "200", perm: authz.KeysRead},
		{method: "POST", path: "/api/v1/platform/tenant-key-domain/migrate", opID: "migrateTenantKeyDomain", summary: "Migrate this tenant into an independently wrapped cryptographic domain", handler: a.migrateTenantKeyDomain, reqSchema: "TenantKeyDomainMigrateRequest", resSchema: "TenantKeyDomainStatus", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/platform/tenant-key-domain/seal", opID: "sealTenantKeyDomain", summary: "Queue an independently replayable seal for this tenant's cryptographic domain", handler: a.sealTenantKeyDomain, resSchema: "TenantKeyDomainSealReceipt", successCode: "202", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/platform/tenant-key-domain/unseal", opID: "unsealTenantKeyDomain", summary: "Unseal this tenant through its configured operator wrapper", handler: a.unsealTenantKeyDomain, resSchema: "TenantKeyDomainStatus", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "GET", path: "/api/v1/platform/distribution", opID: "getPlatformDistribution", summary: "Self-hostable run-anywhere distribution posture", handler: a.getPlatformDistribution, resSchema: "PlatformDistributionStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/support/enterprise", opID: "getEnterpriseSupportStatus", summary: "Enterprise support, SLA, and services posture", handler: a.getEnterpriseSupportStatus, resSchema: "EnterpriseSupportStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/managed-offering/status", opID: "getManagedOfferingStatus", summary: "Managed offering/provider-plane posture", handler: a.getManagedOfferingStatus, resSchema: "ManagedOfferingStatus", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/scale/orchestration", opID: "getScaleOrchestration", summary: "High-volume orchestration posture for 100k-1M+ credentials", handler: a.getScaleOrchestration, resSchema: "ScaleOrchestrationPlan", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/scale/ha-issuance", opID: "getActiveActiveIssuance", summary: "Multi-region HA issuance posture", handler: a.getActiveActiveIssuance, resSchema: "ActiveActiveIssuancePlan", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/platform/dr-posture", opID: "getDRPosture", summary: "Report when this deployment's backup was last verified by re-hashing its artifacts", handler: a.listDRPosture, resSchema: "DRPosture", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/posture/adcs", opID: "getADCSPosture", summary: "AD CS certificate template posture observed by an in-domain relay", handler: a.getADCSPosture, resSchema: "ADCSPosture", successCode: "200", perm: authz.DiscoveryRead},
		{method: "POST", path: "/api/v1/adcs/ca-database/ingest", opID: "ingestADCSDatabase", summary: "Ingest certutil rows a domain-joined relay collected from a CA database; summarize by disposition", handler: a.ingestADCSDatabase, reqSchema: "ADCSDatabaseIngest", resSchema: "ADCSDatabaseSummary", successCode: "200", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/adcs/ca-database", opID: "listADCSDatabases", summary: "Per-CA certificate-database lifecycle visibility: issued, pending approval, revoked, denied, failed", handler: a.listADCSDatabases, resSchema: "ADCSDatabaseList", successCode: "200", perm: authz.DiscoveryRead},
		{method: "GET", path: "/api/v1/editions", opID: "getEditions", summary: "Edition and license posture", handler: a.getEditions, resSchema: "EditionsInfo", successCode: "200"},
		// B-5: what is running and is the spine reachable — the readout an
		// operator wants on /admin/system, which only /healthz answered.
		// Platform posture routes live in routes_platform.go (served-surface file budget).
		// Provider-plane tenant creation is a tenant-scoped system operation: the
		// provider tenant is authorized by the bearer principal, while the command
		// emits tenant.registered for the hosted tenant so PostgreSQL RLS creates a
		// separate boundary from the first projected row.
		{method: "POST", path: "/api/v1/managed-offering/tenants", opID: "provisionManagedTenant", summary: "Provision a hosted tenant in the managed offering", handler: a.provisionManagedTenant, reqSchema: "ManagedTenantProvisionRequest", resSchema: "ManagedTenant", successCode: "201", mutation: true, perm: authz.AccessWrite},
	}
}
