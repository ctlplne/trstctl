// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// The exact payload-field policies for the discovery finding projections:
// a finding recorded, its triage, and an action taken at its provider. They
// live beside one another so the central schema registry stays within its
// served-source size guard; new finding fields are classified here.

func discoveryFindingPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		jsonID = events.PrivacyFieldJSONIdentityValues
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/id", opaque), privacyRule("/run_id", opaque),
		privacyRule("/source_id", opaque), privacyRule("/kind", opaque),
		privacyRule("/ref", opaque), privacyRule("/provenance", opaque),
		privacyRule("/fingerprint", opaque), privacyRule("/risk_score", opaque),
		privacyRule("/metadata", jsonID),
	)
}

func discoveryTriagePrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		clear  = events.PrivacyFieldFreeTextClear
		jsonID = events.PrivacyFieldJSONIdentityValues
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/id", opaque), privacyRule("/status", opaque),
		privacyRule("/managed_identity_id", opaque), privacyRule("/actor", exact),
		privacyRule("/reason", clear), privacyRule("/metadata_patch", jsonID),
		privacyRule("/assignee", exact), privacyRule("/due_at", opaque),
		privacyRule("/evidence_ref", clear), privacyRule("/risk_accepted_until", opaque),
	)
}

// discoveryProviderActionPrivacyPolicy classifies an action at the provider
// on a finding (A170, A171): the operator's reason and the provider's detail
// are free text, the actor is an identity.
func discoveryProviderActionPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		clear  = events.PrivacyFieldFreeTextClear
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/finding_id", opaque), privacyRule("/action", opaque), privacyRule("/status", opaque),
		privacyRule("/provider", opaque), privacyRule("/detail", clear), privacyRule("/request_id", opaque),
		privacyRule("/reason", clear), privacyRule("/actor", exact), privacyRule("/provider_ref", opaque),
	)
}

// discoverySecretMovedPrivacyPolicy classifies a leaked secret moved into the
// native store (P6): the mover is an identity; the secret's name and version
// and the residue's repository locations are opaque. No value is carried.
func discoverySecretMovedPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/finding_id", opaque), privacyRule("/secret_name", opaque),
		privacyRule("/secret_version", opaque), privacyRule("/moved_by", exact),
		privacyRule("/residue/*/rule_id", opaque), privacyRule("/residue/*/file", opaque),
		privacyRule("/residue/*/line", opaque), privacyRule("/residue/*/commit", opaque),
	)
}

// discoverySecretResidueCheckedPrivacyPolicy classifies a later scan's
// re-check of a moved secret's history residue (P6-L5): locations only.
func discoverySecretResidueCheckedPrivacyPolicy() events.PrivacyEventPolicy {
	const opaque = events.PrivacyFieldOpaqueExact
	return privacyRules(
		privacyRule("/finding_id", opaque), privacyRule("/secret_name", opaque),
		privacyRule("/secret_version", opaque), privacyRule("/run_id", opaque), privacyRule("/checked_at", opaque),
		privacyRule("/residue/*/rule_id", opaque), privacyRule("/residue/*/file", opaque),
		privacyRule("/residue/*/line", opaque), privacyRule("/residue/*/commit", opaque),
	)
}

// discoverySecretConsumerReadPrivacyPolicy classifies the first read of a
// moved secret's rotated version (P6): the reader is an identity.
func discoverySecretConsumerReadPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/finding_id", opaque), privacyRule("/secret_name", opaque),
		privacyRule("/version", opaque), privacyRule("/reader", exact), privacyRule("/read_at", opaque),
	)
}
