// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// Reviewer text and identity can be erased without changing the approved
// effect. The public CA, roster, digests and signed receipt stay byte-exact.
func addSSHTrustFleetPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	opaque := events.PrivacyFieldOpaqueExact
	clear := events.PrivacyFieldFreeTextClear
	exact := events.PrivacyFieldIdentityExact
	policies[privacyEventPolicyKey{EventSSHTrustFleetStarted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/plan_digest", opaque),
		privacyRule("/plan/name", clear), privacyRule("/plan/reason", clear),
		privacyRule("/plan/public_ca_key", opaque), privacyRule("/plan/ca_fingerprint", opaque),
		privacyRule("/plan/expires_at", opaque), privacyRule("/plan/hosts", opaque),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs", opaque),
		privacyRule("/approval/issuance", opaque),
	)
	policies[privacyEventPolicyKey{EventSSHTrustFleetObserved, 1}] = privacyRules(
		privacyRule("/job_id", opaque), privacyRule("/attempt", opaque),
		privacyRule("/report", opaque), privacyRule("/evidence_digest", opaque),
		privacyRule("/receipt_statement", opaque), privacyRule("/receipt_signature_base64", opaque),
		privacyRule("/signer_fingerprint", opaque),
	)
}

func addSSHTrustFleetPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSSHTrustFleetStarted, 1}] = privacyPayloadShape[SSHTrustFleetStarted]()
	shapes[privacyEventPolicyKey{EventSSHTrustFleetObserved, 1}] = privacyPayloadShape[SSHTrustFleetObserved]()
}
