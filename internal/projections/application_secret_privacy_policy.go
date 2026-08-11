// SPDX-License-Identifier: MPL-2.0

package projections

import "trstctl.com/trstctl/internal/events"

type applicationSecretLegacyAudit struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// applicationSecretLegacyRecoveryFence is the pre-v2 command shape retained by
// an application-secret mutation fence after an append/SQL crash gap. It shares
// the event's schema coordinate, but /action (rather than /version) keeps the two
// historical shapes closed and unambiguous.
type applicationSecretLegacyRecoveryFence struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type secretstoreLegacyDeleteAudit struct {
	Path string `json:"path"`
}

func init() {
	legacyRules := []events.PrivacyFieldRule{
		{Path: "/name", Mode: events.PrivacyFieldSubjectToken},
		{Path: "/version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/action", Mode: events.PrivacyFieldOpaqueExact},
	}
	legacy := events.PrivacyEventPolicy{
		Rules: legacyRules, PayloadShape: events.PrivacyPayloadShapeOneOf(
			events.PrivacyPayloadShapeOf[applicationSecretLegacyAudit](),
			events.PrivacyPayloadShapeOf[applicationSecretLegacyRecoveryFence](),
		),
	}
	deletedLegacy := events.PrivacyEventPolicy{
		Rules: append(append([]events.PrivacyFieldRule(nil), legacyRules...),
			events.PrivacyFieldRule{Path: "/path", Mode: events.PrivacyFieldSubjectToken}),
		PayloadShape: events.PrivacyPayloadShapeOneOf(
			events.PrivacyPayloadShapeOf[applicationSecretLegacyAudit](),
			events.PrivacyPayloadShapeOf[applicationSecretLegacyRecoveryFence](),
			events.PrivacyPayloadShapeOf[secretstoreLegacyDeleteAudit](),
		),
	}
	mutation := events.PrivacyEventPolicy{Rules: []events.PrivacyFieldRule{
		{Path: "/tenant_epoch", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/action", Mode: events.PrivacyFieldOpaqueExact},
		// Name and sync coordinates are intentionally absent. They bind sealed
		// AAD or external-effect authority, so a subject occurrence must enter
		// the privacy-only v3 disposition transform rather than be renamed.
		{Path: "/expected_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/result_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/sealed", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/source_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/source_written_at", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/idempotency_key_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/request_binding_hmac_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/command_evidence", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/surface", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/request_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/intent_digest", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/requester", Mode: events.PrivacyFieldIdentityExact},
		{Path: "/approval/resource_kind", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/resource_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/action", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/from_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/to_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/target_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/required_approvals", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/reason", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/evidence_refs", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/issuance", Mode: events.PrivacyFieldOpaqueExact},
	}, PayloadShape: events.PrivacyPayloadShapeOf[ApplicationSecretMutation]()}
	privacyDisposition := events.PrivacyEventPolicy{Rules: []events.PrivacyFieldRule{
		{Path: "/tenant_epoch", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/action", Mode: events.PrivacyFieldOpaqueExact},
		// The envelope-aware application-secret transformer handles Name before
		// this field policy runs. At v3 the surviving local ciphertext is valid
		// only because Name stayed byte-exact; a later subject match promotes the
		// whole command to the closed name tombstone instead of renaming it.
		{Path: "/name", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/expected_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/result_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/sealed", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/source_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/source_written_at", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/idempotency_key_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/request_binding_hmac_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/command_evidence", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/surface", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/request_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/intent_digest", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/requester", Mode: events.PrivacyFieldIdentityExact},
		{Path: "/approval/resource_kind", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/resource_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/action", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/from_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/to_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/target_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/required_approvals", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/reason", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/evidence_refs", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/issuance", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/privacy_disposition", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/privacy_subject_ref", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/privacy_source_schema_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/privacy_authority_tombstone", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/privacy_sync_authority_erased", Mode: events.PrivacyFieldOpaqueExact},
	}, PayloadShape: events.PrivacyPayloadShapeOneOf(
		events.PrivacyPayloadShapeOf[ApplicationSecretPrivacyNameTombstone](),
		events.PrivacyPayloadShapeOf[ApplicationSecretPrivacySyncErased](),
	)}
	for _, eventType := range []string{
		EventApplicationSecretCreated,
		EventApplicationSecretRotated,
		EventApplicationSecretRecovered,
		EventApplicationSecretDeleted,
	} {
		legacyPolicy := legacy
		if eventType == EventApplicationSecretDeleted {
			legacyPolicy = deletedLegacy
		}
		if err := events.RegisterPrivacyEventPolicy(eventType, 1, legacyPolicy); err != nil {
			panic(err)
		}
		if err := events.RegisterPrivacyEventPolicy(
			eventType, ApplicationSecretMutationSchemaVersion, mutation,
		); err != nil {
			panic(err)
		}
		if err := events.RegisterPrivacyEventPolicy(
			eventType, ApplicationSecretPrivacyDispositionSchemaVersion, privacyDisposition,
		); err != nil {
			panic(err)
		}
	}
}
