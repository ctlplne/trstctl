// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// CA ceremony events carry authenticated custodian subjects. These exact
// shapes allow subject erasure to rewrite those fields while keeping purpose,
// threshold, ceremony identity, and terminal command binding unchanged.
func addCACeremonyPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		clear  = events.PrivacyFieldFreeTextClear
		opaque = events.PrivacyFieldOpaqueExact
	)
	policies[privacyEventPolicyKey{EventType: EventCACeremonyStarted, Version: 1}] = privacyRules(
		privacyRule("/ceremony_id", opaque), privacyRule("/purpose", opaque),
		privacyRule("/threshold", opaque), privacyRule("/opener", exact),
	)
	policies[privacyEventPolicyKey{EventType: EventCACeremonyApproved, Version: 1}] = privacyRules(
		privacyRule("/ceremony_id", opaque), privacyRule("/custodian", exact),
		privacyRule("/approvals", opaque),
	)
	policies[privacyEventPolicyKey{EventType: EventCACeremonyCancelled, Version: 1}] = privacyRules(
		privacyRule("/ceremony_id", opaque), privacyRule("/actor", exact),
		privacyRule("/reason", clear),
	)
}

func addCACeremonyPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventType: EventCACeremonyStarted, Version: 1}] = privacyPayloadShape[CACeremonyStarted]()
	shapes[privacyEventPolicyKey{EventType: EventCACeremonyApproved, Version: 1}] = privacyPayloadShape[CACeremonyApproved]()
	shapes[privacyEventPolicyKey{EventType: EventCACeremonyCancelled, Version: 1}] = privacyPayloadShape[CACeremonyCancelled]()
}
