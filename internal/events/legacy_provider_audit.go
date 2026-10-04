// SPDX-License-Identifier: BUSL-1.1

package events

// LegacyProviderGlobalAuditScope is the single pre-UUID Provider audit partition.
// It is retained verbatim for historical evidence, never assigned to a customer.
const LegacyProviderGlobalAuditScope = "provider-control-plane"

// These are the Provider audit types emitted before the authority partition
// received a UUID. Keep the list explicit: a future provider.* command under
// the textual partition must not silently bypass core replay or outbox work.
var legacyProviderAuditTypes = map[string]struct{}{
	"provider.tenant_provision":               {},
	"provider.tenant_suspend":                 {},
	"provider.tenant_resume":                  {},
	"provider.tenant_offboard":                {},
	"provider.tenant_erasure.requested":       {},
	"provider.unregistered_tenant.offboarded": {},
	"provider.tenant_erasure.failed":          {},
	"provider.tenant_erasure.completed":       {},
	"provider.breakglass_request":             {},
	"provider.breakglass_consent":             {},
	"provider.breakglass_deny":                {},
	"provider.breakglass_access":              {},
	"provider.isolation.drill":                {},
	"provider.delegation.granted":             {},
	"provider.delegation.revoked":             {},
	"provider.operator.upserted":              {},
	"provider.operator.offboarded":            {},
	"provider.tenant.quota.set":               {},
	"provider.tenant.brand.set":               {},
}

// IsLegacyProviderGlobalAudit identifies only the historical Provider audit
// partition that predates UUID tenant identifiers on deployment-wide events.
// Its envelope stays immutable. Core consumers with no Provider side effect may
// advance past it, while the licensed projection still replays the original.
// Retention emits audit.archived into the same historical partition, and that
// checkpoint also has no core outbox effect. Do not admit unrelated events under
// this textual scope: they still fail the UUID tenant-service fence.
// New Provider events use the reserved UUID partition instead.
func IsLegacyProviderGlobalAudit(event Event) bool {
	return IsLegacyProviderCoreProjectionNoop(event) ||
		(event.TenantID == LegacyProviderGlobalAuditScope && event.Type == "audit.archived")
}

// IsLegacyProviderCoreProjectionNoop is narrower than the outbox predicate.
// Historical allowlisted Provider audit records have no core read-model receiver, while
// audit.archived must still project the retention checkpoint in its mapped UUID
// RLS partition. Unknown event types in this textual scope remain fail-closed.
func IsLegacyProviderCoreProjectionNoop(event Event) bool {
	if event.TenantID != LegacyProviderGlobalAuditScope {
		return false
	}
	_, known := legacyProviderAuditTypes[event.Type]
	return known
}
