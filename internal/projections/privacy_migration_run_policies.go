// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// migrationRunPrivacyPolicy is the exact payload-field policy for the
// migration.run.recorded projection. It lives beside the migration workflow
// so the central schema registry stays within its served-source size guard;
// new run or member fields are classified here.
func migrationRunPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		token  = events.PrivacyFieldSubjectToken
		clear  = events.PrivacyFieldFreeTextClear
		jsonID = events.PrivacyFieldJSONIdentityValues
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/run/id", opaque), privacyRule("/run/plan_id", token),
		privacyRule("/run/incident/mode", opaque),
		privacyRule("/run/incident/compromised_issuer_id", opaque),
		privacyRule("/run/incident/replacement_authority_id", opaque),
		privacyRule("/run/incident/exact_trust_store_ids/*", opaque),
		privacyRule("/run/incident/exact_trust_hosts/*", token),
		privacyRule("/run/incident/affected_identity_ids/*", opaque),
		privacyRule("/run/status", opaque), privacyRule("/run/halt_reason", clear),
		privacyRule("/run/rollback_wave_id", token), privacyRule("/run/rollback_stage", opaque),
		privacyRule("/run/rollback_attempt", opaque), privacyRule("/run/pause_reason", clear),
		privacyRule("/run/approval/request_id", opaque),
		privacyRule("/run/approval/intent_digest", opaque),
		privacyRule("/run/approval/requester", exact),
		privacyRule("/run/approval/resource_kind", opaque),
		privacyRule("/run/approval/resource_id", opaque),
		privacyRule("/run/approval/action", opaque),
		privacyRule("/run/approval/from_state", opaque),
		privacyRule("/run/approval/to_state", opaque),
		privacyRule("/run/approval/target_version", opaque),
		privacyRule("/run/approval/required_approvals", opaque),
		privacyRule("/run/approval/reason", clear),
		privacyRule("/run/approval/evidence_refs", clear),
		privacyRule("/run/approval/issuance", opaque),
		privacyRule("/run/waves/*/id", token), privacyRule("/run/waves/*/ordinal", opaque),
		privacyRule("/run/waves/*/phase", opaque), privacyRule("/run/waves/*/started", opaque),
		privacyRule("/run/waves/*/halt_reason", clear),
		privacyRule("/run/waves/*/members/*/identity_id", opaque),
		privacyRule("/run/waves/*/members/*/trust_verdict", opaque),
		privacyRule("/run/waves/*/members/*/successor_verdict", opaque),
		privacyRule("/run/waves/*/members/*/revocation_verdict", opaque),
		privacyRule("/run/waves/*/members/*/rollback_successor_verdict", opaque),
		privacyRule("/run/waves/*/members/*/rollback_trust_verdict", opaque),
		privacyRule("/run/waves/*/members/*/binding/issuing_authority_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/target_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/target_revision", opaque),
		privacyRule("/run/waves/*/members/*/binding/connector", opaque),
		privacyRule("/run/waves/*/members/*/binding/target", token),
		privacyRule("/run/waves/*/members/*/binding/target_config", jsonID),
		privacyRule("/run/waves/*/members/*/binding/required_agent_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_path", token),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_pem", opaque),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_fingerprint", opaque),
		privacyRule("/run/waves/*/members/*/binding/verify_address", opaque),
		privacyRule("/run/waves/*/members/*/binding/verify_server_name", token),
		privacyRule("/run/waves/*/members/*/binding/subject_common_name", token),
		privacyRule("/run/waves/*/members/*/binding/subject_dns_names/*", token),
		privacyRule("/run/waves/*/members/*/binding/subject_ip_addresses/*", token),
		privacyRule("/run/waves/*/members/*/binding/subject_email_addresses/*", token),
		privacyRule("/run/waves/*/members/*/binding/subject_uris/*", token),
		privacyRule("/run/waves/*/members/*/binding/predecessor_certificate_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/predecessor_fingerprint", opaque),
		privacyRule("/run/waves/*/members/*/binding/predecessor_ca_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/environment", opaque),
		privacyRule("/run/waves/*/members/*/binding/successor_fingerprint", opaque),
		privacyRule("/actions/*/kind", opaque), privacyRule("/actions/*/wave_id", token),
		privacyRule("/actions/*/identity_id", opaque),
	)
}
