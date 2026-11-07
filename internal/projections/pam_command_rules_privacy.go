// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

func pamCommandTemplatePrivacy(base events.PrivacyEventPolicy) events.PrivacyEventPolicy {
	base.Rules = append([]events.PrivacyFieldRule(nil), base.Rules...)
	base.Rules = append(base.Rules,
		// A269: the template's remote desktop clipboard policy.
		privacyRule("/desktop_clipboard", events.PrivacyFieldOpaqueExact),
		// A273: how the gateway signs in to a web console (field and header
		// names, never a credential).
		privacyRule("/web_sign_in/mode", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/login_path", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/username_field", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/password_field", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/header", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/header_prefix", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/browser_cookies/*", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/id", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/name", events.PrivacyFieldFreeTextClear),
		privacyRule("/command_rules/*/enabled", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/protocol", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/operations/*", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/effect", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/required_approvals", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_rules/*/review_ttl_seconds", events.PrivacyFieldOpaqueExact),
	)
	return base
}

func pamCommandSessionPrivacy(base events.PrivacyEventPolicy) events.PrivacyEventPolicy {
	base.Rules = append([]events.PrivacyFieldRule(nil), base.Rules...)
	base.Rules = append(base.Rules,
		privacyRule("/command_policy/version", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/template_id", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/template_revision", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/id", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/protocol", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/operations/*", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/effect", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/required_approvals", events.PrivacyFieldOpaqueExact),
		privacyRule("/command_policy/rules/*/review_ttl_seconds", events.PrivacyFieldOpaqueExact),
		// A273: the web console sign-in the session's reviewers approved.
		privacyRule("/web_sign_in/mode", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/login_path", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/username_field", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/password_field", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/header", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/header_prefix", events.PrivacyFieldOpaqueExact),
		privacyRule("/web_sign_in/browser_cookies/*", events.PrivacyFieldOpaqueExact),
	)
	return base
}

func pamCommandDecisionPrivacy() events.PrivacyEventPolicy {
	return privacyRules(
		privacyRule("/id", events.PrivacyFieldOpaqueExact), privacyRule("/session_id", events.PrivacyFieldOpaqueExact),
		privacyRule("/job_id", events.PrivacyFieldOpaqueExact), privacyRule("/attempt", events.PrivacyFieldOpaqueExact),
		privacyRule("/protocol", events.PrivacyFieldOpaqueExact), privacyRule("/connection_id", events.PrivacyFieldOpaqueExact),
		privacyRule("/ordinal", events.PrivacyFieldOpaqueExact), privacyRule("/phase", events.PrivacyFieldOpaqueExact),
		privacyRule("/rule_ids/*", events.PrivacyFieldOpaqueExact), privacyRule("/operations/*", events.PrivacyFieldOpaqueExact), privacyRule("/message_digest", events.PrivacyFieldOpaqueExact),
		privacyRule("/policy_digest", events.PrivacyFieldOpaqueExact), privacyRule("/status", events.PrivacyFieldOpaqueExact),
		privacyRule("/reason", events.PrivacyFieldOpaqueExact), privacyRule("/decided_at", events.PrivacyFieldOpaqueExact),
		privacyRule("/observed_at", events.PrivacyFieldOpaqueExact), privacyRule("/review_expires_at", events.PrivacyFieldOpaqueExact),
	)
}

func pamCommandReviewPrivacy() events.PrivacyEventPolicy {
	base := pamCommandDecisionPrivacy()
	opaque, exact, clear := events.PrivacyFieldOpaqueExact, events.PrivacyFieldIdentityExact, events.PrivacyFieldFreeTextClear
	base.Rules = append(base.Rules,
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque), privacyRule("/approval/requester", exact),
		privacyRule("/approval/resource_kind", opaque), privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque), privacyRule("/approval/target_version", opaque),
		privacyRule("/approval/required_approvals", opaque), privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs", opaque), privacyRule("/approval/issuance", opaque))
	return base
}

func pamCommandApprovalPrivacy(base events.PrivacyEventPolicy) events.PrivacyEventPolicy {
	base.Rules = append([]events.PrivacyFieldRule(nil), base.Rules...)
	for i := range base.Rules {
		if base.Rules[i].Path == "/evidence_refs/*" {
			base.Rules[i].Mode = events.PrivacyFieldOpaqueExact
		}
	}
	return base
}
