// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

// These exact field classes describe subject erasure. They do not make other
// opaque fields public: only SourceAdmission's closed controls bypass sealing.
func addEventProtectionPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	for version, policy := range eventprivacy.AuthorizationPrivacyPolicies() {
		policies[privacyEventPolicyKey{eventprivacy.EventAuthorizationDecision, version}] = policy
	}
	opaque := events.PrivacyFieldOpaqueExact
	request := []events.PrivacyFieldRule{
		privacyRule("/registration_identity", opaque), privacyRule("/operation_id", opaque),
		privacyRule("/key_id", opaque), privacyRule("/retention_ns", opaque),
	}
	policies[privacyEventPolicyKey{EventTenantEventProtectionRequested, 1}] = privacyRules(request...)
	activation := append([]events.PrivacyFieldRule(nil), request...)
	activation = append(activation,
		privacyRule("/requested_event_id", opaque), privacyRule("/requested_sequence", opaque),
		privacyRule("/requested_at", opaque), privacyRule("/creation/version", opaque),
		privacyRule("/creation/ref/tenant_id", opaque), privacyRule("/creation/ref/key_id", opaque),
		privacyRule("/creation/created_at", opaque), privacyRule("/creation/probe", opaque),
	)
	policies[privacyEventPolicyKey{EventTenantEventProtectionActivated, 1}] = privacyRules(activation...)
	policies[privacyEventPolicyKey{EventTenantEventProtectionHoldsCleared, 1}] = privacyRules(
		privacyRule("/request/ref/tenant_id", opaque), privacyRule("/request/ref/key_id", opaque), privacyRule("/request/operation_id", opaque), privacyRule("/request/registration_identity", opaque),
		privacyRule("/request/activation_event_id", opaque), privacyRule("/request/activation_sequence", opaque), privacyRule("/request/creation_digest", opaque),
		privacyRule("/request/offboard_event_id", opaque), privacyRule("/request/offboard_sequence", opaque), privacyRule("/request/offboarded_at", opaque), privacyRule("/request/not_before", opaque),
	)
	policies[privacyEventPolicyKey{EventTenantEventProtectionDestroyed, 1}] = privacyRules(privacyRule("/jws", opaque))
}

func addEventProtectionPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	for version, policy := range eventprivacy.AuthorizationPrivacyPolicies() {
		shapes[privacyEventPolicyKey{eventprivacy.EventAuthorizationDecision, version}] = policy.PayloadShape
	}
	shapes[privacyEventPolicyKey{EventTenantEventProtectionRequested, 1}] = privacyPayloadShape[TenantEventProtectionRequested]()
	shapes[privacyEventPolicyKey{EventTenantEventProtectionActivated, 1}] = privacyPayloadShape[TenantEventProtectionActivated]()
	shapes[privacyEventPolicyKey{EventTenantEventProtectionHoldsCleared, 1}] = privacyPayloadShape[TenantEventProtectionHoldsCleared]()
	shapes[privacyEventPolicyKey{EventTenantEventProtectionDestroyed, 1}] = privacyPayloadShape[TenantEventProtectionDestroyed]()
}
