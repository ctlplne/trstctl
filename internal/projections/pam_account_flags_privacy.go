// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// pamAccountFlagActionedPrivacy (A276): the approved action applied to a
// brokered account's flag and the approval it consumed.
func pamAccountFlagActionedPrivacy() events.PrivacyEventPolicy {
	opaque, exact, clear := events.PrivacyFieldOpaqueExact, events.PrivacyFieldIdentityExact, events.PrivacyFieldFreeTextClear
	return privacyRules(
		privacyRule("/target_type", opaque), privacyRule("/target_id", opaque), privacyRule("/action", opaque),
		privacyRule("/owner_id", opaque), privacyRule("/rotation_id", opaque), privacyRule("/reason", clear),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs/*", clear),
		privacyRule("/approval/issuance", opaque),
		privacyRule("/actor", exact), privacyRule("/at", opaque),
	)
}
